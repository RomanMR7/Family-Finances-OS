"""
Family Finances OS - Offline-First Local P2P Synchronization Engine (Stage 4)
Zero-Cloud, Peer-to-Peer LAN Synchronization using:
1. Hybrid Logical Clocks (HLC) for deterministic distributed ordering without clock sync
2. Append-Only Change Data Capture (CDC) Event Log with full transaction payload snapshots
3. UDP Broadcast Discovery Beacon on LAN (255.255.255.255:41234)
4. Authenticated P2P HTTP Endpoint (HMAC-SHA256 mutual pairing)
5. Commutative Double-Entry Merge & Deterministic Last-Write-Wins (LWW)
"""
import hashlib
import hmac
import json
import logging
import socket
import threading
import time
import uuid
from typing import Dict, List, Optional, Tuple, Any

from family_finances_os.models import current_iso_time

logger = logging.getLogger("ffos_sync")

# Default UDP port for local peer discovery
DISCOVERY_BROADCAST_PORT = 41234
BEACON_MAGIC = "FFOS_BEACON_V1"
_EVENT_LOCK = threading.RLock()


def current_epoch_ms() -> int:
    """Return current UTC epoch in milliseconds."""
    return int(time.time() * 1000)


class HybridLogicalClock:
    """
    Hybrid Logical Clock (HLC) combining physical wall-clock time with a logical counter.
    Provides strict monotonic ordering across distributed offline nodes even under clock drift.
    Timestamp format: "<epoch_ms:014d>:<counter:05d>:<device_id>"
    Lexicographically sortable!
    """
    def __init__(self, device_id: str):
        self.device_id = device_id
        self.physical_ms = 0
        self.logical_counter = 0
        self._lock = threading.Lock()

    def now(self) -> str:
        """Generate a new monotonic HLC timestamp."""
        with self._lock:
            cur_ms = current_epoch_ms()
            if cur_ms > self.physical_ms:
                self.physical_ms = cur_ms
                self.logical_counter = 0
            else:
                self.logical_counter += 1
            return f"{self.physical_ms:014d}:{self.logical_counter:05d}:{self.device_id}"

    def update(self, remote_hlc_str: str) -> str:
        """
        Update local clock upon receiving a remote HLC timestamp.
        Ensures local clock never lags behind remote peer.
        """
        with self._lock:
            cur_ms = current_epoch_ms()
            parts = remote_hlc_str.split(":")
            if len(parts) >= 2:
                try:
                    remote_ms = int(parts[0])
                    remote_counter = int(parts[1])
                except ValueError:
                    remote_ms = 0
                    remote_counter = 0
            else:
                remote_ms = 0
                remote_counter = 0

            max_ms = max(self.physical_ms, remote_ms, cur_ms)
            if max_ms == self.physical_ms == remote_ms:
                self.logical_counter = max(self.logical_counter, remote_counter) + 1
            elif max_ms == self.physical_ms:
                self.logical_counter += 1
            elif max_ms == remote_ms:
                self.physical_ms = remote_ms
                self.logical_counter = remote_counter + 1
            else:
                self.physical_ms = cur_ms
                self.logical_counter = 0

            return f"{self.physical_ms:014d}:{self.logical_counter:05d}:{self.device_id}"


def sign_sync_payload(body_bytes: bytes, secret: str, nonce: str, hlc: str) -> str:
    """
    Calculate HMAC-SHA256 signature for sync exchange payload.
    """
    message = nonce.encode("utf-8") + b":" + hlc.encode("utf-8") + b":" + body_bytes
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def verify_sync_payload(body_bytes: bytes, secret: str, nonce: str, hlc: str, signature: str) -> bool:
    """
    Verify HMAC-SHA256 signature in constant time.
    """
    expected = sign_sync_payload(body_bytes, secret, nonce, hlc)
    return hmac.compare_digest(expected, signature)


class P2PSyncEngine:
    """
    Core peer-to-peer reconciliation engine.
    Applies remote mutations deterministically with CRDT convergence principles.
    """
    def __init__(self, conn_or_path: Any = None, device_id: Optional[str] = None, sync_passphrase: str = "FFOS_FAMILY_PAIRING_SECRET_2026"):
        self.conn_or_path = conn_or_path
        self.sync_passphrase = sync_passphrase
        self._init_node_meta(device_id)

    def _get_conn(self):
        from family_finances_os.db import get_db_connection
        return get_db_connection(self.conn_or_path)

    def _close_if_local(self, conn):
        if hasattr(self.conn_or_path, "execute"):
            return
        from family_finances_os.db import GLOBAL_STORAGE
        if GLOBAL_STORAGE.is_unlocked() and conn is GLOBAL_STORAGE.get_connection():
            return
        if self.conn_or_path:
            conn.close()
            return
        from family_finances_os.config import DB_PATH
        if DB_PATH.exists() and not GLOBAL_STORAGE.is_unlocked():
            conn.close()

    def _save_if_encrypted(self):
        from family_finances_os.db import GLOBAL_STORAGE
        if GLOBAL_STORAGE.is_unlocked():
            GLOBAL_STORAGE.save()

    def _init_node_meta(self, override_device_id: Optional[str] = None):
        """Ensure device_id and HLC are initialized."""
        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT value FROM system_meta WHERE key = 'device_id';")
            row = cursor.fetchone()
            if row and row["value"]:
                self.device_id = override_device_id or row["value"]
            else:
                self.device_id = override_device_id or str(uuid.uuid4())
                try:
                    cursor.execute("INSERT OR REPLACE INTO system_meta (key, value) VALUES ('device_id', ?);", (self.device_id,))
                    conn.commit()
                except Exception:
                    pass

            cursor.execute("SELECT value FROM system_meta WHERE key = 'device_name';")
            name_row = cursor.fetchone()
            self.device_name = name_row["value"] if name_row else socket.gethostname()

            self.hlc = HybridLogicalClock(self.device_id)
            last = cursor.execute('SELECT MAX(hlc_timestamp) AS h FROM change_log').fetchone()['h']
            if last:
                self.hlc.update(last)
        finally:
            self._close_if_local(conn)

    def record_change_event(self, *args, **kwargs):
        with _EVENT_LOCK:
            return self._record_change_event_locked(*args, **kwargs)

    def _record_change_event_locked(
        self,
        entity_name: str,
        entity_id: str,
        change_type: str,
        payload: Dict[str, Any],
        hlc_timestamp: Optional[str] = None,
        source_device_id: Optional[str] = None,
        cursor: Any = None
    ) -> str:
        """
        Record a mutation event into the append-only change_log.
        """
        dev_id = source_device_id or self.device_id

        should_close = False
        if cursor is None:
            conn = self._get_conn()
            cursor = conn.cursor()
            should_close = True
        else:
            conn = None

        try:
            if not hlc_timestamp:
                latest = cursor.execute('SELECT MAX(hlc_timestamp) AS h FROM change_log').fetchone()['h']
                if latest:
                    self.hlc.update(latest)
            hlc_ts = hlc_timestamp or self.hlc.now()
            if entity_name in ('GOAL', 'ENVELOPE', 'ENVELOPE_OPERATION'):
                from .reservation_events import annotate_snapshot
                payload = annotate_snapshot(cursor, entity_name, entity_id, payload)
            if entity_name == 'OBLIGATION_PAYMENT':
                from .obligation_merge import merge_components
                payload = dict(payload)
                key = f"obligation_payment_components:{payload['obligation_id']}:{payload['month_year']}"
                prior = cursor.execute('SELECT value FROM system_meta WHERE key=?', (key,)).fetchone()
                incoming = payload.get('components', {})
                reset = change_type == 'DELETE' or not incoming.get('transactions')
                components = merge_components(json.loads(prior['value']) if prior else {}, incoming, hlc_ts, reset=reset)
                payload['components'] = components
                cursor.execute('INSERT INTO system_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                               (key, json.dumps(components, ensure_ascii=False)))
            payload_json = json.dumps(payload, ensure_ascii=False)
            cursor.execute("""
            INSERT INTO change_log (entity_name, entity_id, change_type, payload_json, device_id, hlc_timestamp)
            VALUES (?, ?, ?, ?, ?, ?);
            """, (entity_name, entity_id, change_type, payload_json, dev_id, hlc_ts))
            if conn:
                conn.commit()
                self._save_if_encrypted()
            return hlc_ts
        finally:
            if should_close and conn:
                self._close_if_local(conn)

    def export_changes(self, since_hlc: Optional[str] = None, limit: int = 1000) -> Dict[str, Any]:
        """
        Export local change_log entries strictly greater than since_hlc.
        """
        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            if since_hlc:
                cursor.execute("""
                SELECT local_seq, entity_name, entity_id, change_type, payload_json, device_id, hlc_timestamp, updated_at_utc
                FROM change_log
                WHERE hlc_timestamp > ?
                ORDER BY hlc_timestamp ASC
                LIMIT ?;
                """, (since_hlc, limit))
            else:
                cursor.execute("""
                SELECT local_seq, entity_name, entity_id, change_type, payload_json, device_id, hlc_timestamp, updated_at_utc
                FROM change_log
                ORDER BY hlc_timestamp ASC
                LIMIT ?;
                """, (limit,))

            rows = cursor.fetchall()
            changes = []
            for r in rows:
                changes.append({
                    "seq": r["local_seq"],
                    "entity_name": r["entity_name"],
                    "entity_id": r["entity_id"],
                    "change_type": r["change_type"],
                    "payload": json.loads(r["payload_json"]),
                    "device_id": r["device_id"],
                    "hlc_timestamp": r["hlc_timestamp"] or ""
                })

            return {
                "sender_device_id": self.device_id,
                "sender_device_name": self.device_name,
                "current_hlc": self.hlc.now(),
                "next_cursor": changes[-1]["hlc_timestamp"] if changes else since_hlc,
                "has_more": bool(changes and cursor.execute("SELECT 1 FROM change_log WHERE hlc_timestamp > ? LIMIT 1", (changes[-1]["hlc_timestamp"],)).fetchone()),
                "changes_count": len(changes),
                "changes": changes
            }
        finally:
            self._close_if_local(conn)

    def apply_remote_changes(self, sync_data: Dict[str, Any]) -> Dict[str, Any]:
        from family_finances_os.sync_merge import apply_batch
        return apply_batch(self, sync_data)


class PeerDiscoveryBeacon:
    """
    Background daemon for LAN peer discovery via UDP broadcast.
    Allows zero-configuration peer discovery without router access or central server.
    """
    def __init__(self, device_id: str, device_name: str, http_port: int = 8000, broadcast_port: int = DISCOVERY_BROADCAST_PORT):
        self.device_id = device_id
        self.device_name = device_name
        self.http_port = http_port
        self.broadcast_port = broadcast_port
        self.active_peers: Dict[str, Dict[str, Any]] = {}
        self._running = False
        self._lock = threading.Lock()
        self._send_thread: Optional[threading.Thread] = None
        self._recv_thread: Optional[threading.Thread] = None

    def start(self):
        """Start UDP broadcast transmitter and listener threads."""
        if self._running:
            return
        self._running = True

        self._recv_thread = threading.Thread(target=self._listen_loop, daemon=True, name="FFOS-Discovery-Listener")
        self._recv_thread.start()

        self._send_thread = threading.Thread(target=self._broadcast_loop, daemon=True, name="FFOS-Discovery-Broadcaster")
        self._send_thread.start()
        logger.info(f"P2P Discovery Beacon started on UDP port {self.broadcast_port}")

    def stop(self):
        """Stop UDP discovery."""
        self._running = False

    def get_active_peers(self, timeout_sec: int = 15) -> List[Dict[str, Any]]:
        """Return list of peers active within the timeout window."""
        now = time.time()
        with self._lock:
            # Purge expired peers
            self.active_peers = {
                pid: p for pid, p in self.active_peers.items()
                if now - p["last_seen_epoch"] <= timeout_sec
            }
            return list(self.active_peers.values())

    def _broadcast_loop(self):
        """Send periodic UDP broadcast beacon packets every 4 seconds."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(1.0)

        while self._running:
            try:
                beacon_data = json.dumps({
                    "magic": BEACON_MAGIC,
                    "device_id": self.device_id,
                    "device_name": self.device_name,
                    "http_port": self.http_port,
                    "timestamp": current_epoch_ms()
                }).encode("utf-8")

                sock.sendto(beacon_data, ("255.255.255.255", self.broadcast_port))
            except Exception as e:
                pass  # Network might be disconnected or sandboxed
            time.sleep(4.0)

        sock.close()

    def _listen_loop(self):
        """Listen for UDP broadcast beacon packets from local peers."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", self.broadcast_port))
        except Exception:
            try:
                sock.bind(("0.0.0.0", self.broadcast_port))
            except Exception:
                sock.close()
                return

        sock.settimeout(2.0)

        while self._running:
            try:
                data, addr = sock.recvfrom(4096)
                beacon = json.loads(data.decode("utf-8"))
                if beacon.get("magic") == BEACON_MAGIC:
                    peer_id = beacon.get("device_id")
                    if peer_id and peer_id != self.device_id:
                        with self._lock:
                            self.active_peers[peer_id] = {
                                "device_id": peer_id,
                                "device_name": beacon.get("device_name", "РЎРµРјРµР№РЅРѕРµ СѓСЃС‚СЂРѕР№СЃС‚РІРѕ"),
                                "ip": addr[0],
                                "http_port": beacon.get("http_port", 8000),
                                "last_seen_epoch": time.time(),
                                "last_seen_iso": current_iso_time()
                            }
            except socket.timeout:
                continue
            except Exception:
                continue

        sock.close()
