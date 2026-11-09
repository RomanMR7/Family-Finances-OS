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
        finally:
            self._close_if_local(conn)

    def record_change_event(
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
        hlc_ts = hlc_timestamp or self.hlc.now()
        dev_id = source_device_id or self.device_id
        payload_json = json.dumps(payload, ensure_ascii=False)

        should_close = False
        if cursor is None:
            conn = self._get_conn()
            cursor = conn.cursor()
            should_close = True
        else:
            conn = None

        try:
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
                "changes_count": len(changes),
                "changes": changes
            }
        finally:
            self._close_if_local(conn)

    def apply_remote_changes(self, sync_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply a batch of foreign changes inside an atomic SQLite transaction.
        Uses commutative double-entry merging and Last-Write-Wins (LWW) for entities.
        """
        remote_device_id = sync_data.get("sender_device_id")
        remote_hlc = sync_data.get("current_hlc", "")
        changes = sync_data.get("changes", [])

        if remote_hlc:
            self.hlc.update(remote_hlc)

        conn = self._get_conn()
        cursor = conn.cursor()
        applied_count = 0
        skipped_count = 0

        try:
            for item in changes:
                entity_name = item["entity_name"]
                entity_id = item["entity_id"]
                change_type = item["change_type"]
                payload = item["payload"]
                item_dev_id = item["device_id"]
                item_hlc = item["hlc_timestamp"]

                # 1. TRANSACTION MERGING
                if entity_name == "TRANSACTION":
                    if change_type == "INSERT":
                        # Check if transaction already exists by id or idempotency_key
                        idem_key = payload.get("idempotency_key")
                        cursor.execute("SELECT id FROM transactions WHERE id = ?;", (entity_id,))
                        if cursor.fetchone():
                            skipped_count += 1
                            continue
                        if idem_key:
                            cursor.execute("SELECT id FROM transactions WHERE idempotency_key = ?;", (idem_key,))
                            if cursor.fetchone():
                                skipped_count += 1
                                continue

                        # Check created_by_member_id foreign key
                        member_id = payload.get("created_by_member_id")
                        if member_id:
                            cursor.execute("SELECT id FROM members WHERE id = ?;", (member_id,))
                            if not cursor.fetchone():
                                member_id = None

                        # Insert Transaction Header
                        cursor.execute("""
                        INSERT OR IGNORE INTO transactions
                        (id, tx_date, tx_type, description, created_by_member_id, idempotency_key, payload_hash, is_voided, voided_reason, reversal_of_id, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """, (
                            entity_id,
                            payload.get("tx_date", current_iso_time()[:10]),
                            payload.get("tx_type", "EXPENSE"),
                            payload.get("description", "Операция"),
                            member_id,
                            idem_key,
                            payload.get("payload_hash"),
                            payload.get("is_voided", 0),
                            payload.get("voided_reason"),
                            payload.get("reversal_of_id"),
                            payload.get("created_at", current_iso_time())
                        ))

                        # Insert Postings with resilient foreign key resolution
                        for p in payload.get("postings", []):
                            acc_id = p["account_id"]
                            cursor.execute("SELECT id FROM accounts WHERE id = ?;", (acc_id,))
                            if not cursor.fetchone():
                                if p.get("account_code"):
                                    cursor.execute("SELECT id FROM accounts WHERE code = ?;", (p["account_code"],))
                                    acc_row = cursor.fetchone()
                                    if acc_row:
                                        acc_id = acc_row["id"]

                            cat_id = p.get("category_id")
                            if cat_id:
                                cursor.execute("SELECT id FROM categories WHERE id = ?;", (cat_id,))
                                if not cursor.fetchone():
                                    cat_id = None

                            cursor.execute("""
                            INSERT OR IGNORE INTO postings
                            (id, transaction_id, account_id, amount_cents, posting_type, ownership_scope, purpose_allocation, note, category_id, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                            """, (
                                p["id"],
                                entity_id,
                                acc_id,
                                p["amount_cents"],
                                p["posting_type"],
                                p.get("ownership_scope", "COMMON"),
                                p.get("purpose_allocation", "SAFE_TO_SPEND"),
                                p.get("note"),
                                cat_id,
                                p.get("created_at", current_iso_time())
                            ))

                        # Record into local change_log to allow gossip to other peers
                        cursor.execute("""
                        INSERT INTO change_log (entity_name, entity_id, change_type, payload_json, device_id, hlc_timestamp)
                        VALUES (?, ?, ?, ?, ?, ?);
                        """, (entity_name, entity_id, change_type, json.dumps(payload, ensure_ascii=False), item_dev_id, item_hlc))
                        applied_count += 1

                    elif change_type == "VOID":
                        cursor.execute("""
                        UPDATE transactions SET is_voided = 1, voided_reason = ? WHERE id = ?;
                        """, (payload.get("voided_reason", "Аннулировано через P2P"), entity_id))
                        cursor.execute("""
                        INSERT INTO change_log (entity_name, entity_id, change_type, payload_json, device_id, hlc_timestamp)
                        VALUES (?, ?, ?, ?, ?, ?);
                        """, (entity_name, entity_id, change_type, json.dumps(payload, ensure_ascii=False), item_dev_id, item_hlc))
                        applied_count += 1

                # 2. ACCOUNT MERGING (LWW)
                elif entity_name == "ACCOUNT":
                    cursor.execute("SELECT id FROM accounts WHERE id = ?;", (entity_id,))
                    existing = cursor.fetchone()
                    if not existing:
                        cursor.execute("""
                        INSERT INTO accounts (id, code, name, account_type, subtype, currency, ownership_scope, owner_member_id, description, credit_limit_cents, initial_balance_cents, is_active)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """, (
                            entity_id,
                            payload.get("code"),
                            payload.get("name"),
                            payload.get("account_type"),
                            payload.get("subtype"),
                            payload.get("currency", "RUB"),
                            payload.get("ownership_scope", "COMMON"),
                            payload.get("owner_member_id"),
                            payload.get("description"),
                            payload.get("credit_limit_cents", 0),
                            payload.get("initial_balance_cents", 0),
                            payload.get("is_active", 1)
                        ))
                    else:
                        cursor.execute("""
                        UPDATE accounts SET
                            name = COALESCE(?, name),
                            description = COALESCE(?, description),
                            credit_limit_cents = COALESCE(?, credit_limit_cents),
                            ownership_scope = COALESCE(?, ownership_scope),
                            is_active = COALESCE(?, is_active)
                        WHERE id = ?;
                        """, (
                            payload.get("name"),
                            payload.get("description"),
                            payload.get("credit_limit_cents"),
                            payload.get("ownership_scope"),
                            payload.get("is_active"),
                            entity_id
                        ))

                    cursor.execute("""
                    INSERT INTO change_log (entity_name, entity_id, change_type, payload_json, device_id, hlc_timestamp)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """, (entity_name, entity_id, change_type, json.dumps(payload, ensure_ascii=False), item_dev_id, item_hlc))
                    applied_count += 1

                # 3. CATEGORY MERGING (LWW)
                elif entity_name == "CATEGORY":
                    parent_id = payload.get("parent_id")
                    if parent_id:
                        cursor.execute("SELECT id FROM categories WHERE id = ?;", (parent_id,))
                        if not cursor.fetchone():
                            parent_id = None

                    cursor.execute("""
                    INSERT OR REPLACE INTO categories (id, name, category_type, parent_id, icon, sort_order, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?);
                    """, (
                        entity_id,
                        payload.get("name"),
                        payload.get("category_type"),
                        parent_id,
                        payload.get("icon", "tag"),
                        payload.get("sort_order", 0),
                        payload.get("is_active", 1)
                    ))
                    cursor.execute("""
                    INSERT INTO change_log (entity_name, entity_id, change_type, payload_json, device_id, hlc_timestamp)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """, (entity_name, entity_id, change_type, json.dumps(payload, ensure_ascii=False), item_dev_id, item_hlc))
                    applied_count += 1

                # 4. OBLIGATION MERGING (LWW)
                elif entity_name == "OBLIGATION":
                    cat_id = payload.get("category_id")
                    if cat_id:
                        cursor.execute("SELECT id FROM categories WHERE id = ?;", (cat_id,))
                        if not cursor.fetchone():
                            cat_id = None

                    pay_acc_id = payload.get("payment_account_id")
                    if pay_acc_id:
                        cursor.execute("SELECT id FROM accounts WHERE id = ?;", (pay_acc_id,))
                        if not cursor.fetchone():
                            pay_acc_id = None

                    cursor.execute("""
                    INSERT OR REPLACE INTO obligations (id, name, amount_cents, due_day, category_id, payment_account_id, note, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """, (
                        entity_id,
                        payload.get("name"),
                        payload.get("amount_cents"),
                        payload.get("due_day"),
                        cat_id,
                        pay_acc_id,
                        payload.get("note"),
                        payload.get("is_active", 1)
                    ))
                    cursor.execute("""
                    INSERT INTO change_log (entity_name, entity_id, change_type, payload_json, device_id, hlc_timestamp)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """, (entity_name, entity_id, change_type, json.dumps(payload, ensure_ascii=False), item_dev_id, item_hlc))
                    applied_count += 1

                # 5. OBLIGATION PAYMENT MERGING
                elif entity_name == "OBLIGATION_PAYMENT":
                    if change_type == "INSERT":
                        cursor.execute("""
                        INSERT OR REPLACE INTO obligation_payments (id, obligation_id, month_year, transaction_id, paid_amount_cents, paid_at)
                        VALUES (?, ?, ?, ?, ?, ?);
                        """, (
                            entity_id,
                            payload.get("obligation_id"),
                            payload.get("month_year"),
                            payload.get("transaction_id"),
                            payload.get("paid_amount_cents"),
                            payload.get("paid_at", current_iso_time())
                        ))
                    elif change_type == "DELETE":
                        cursor.execute("""
                        DELETE FROM obligation_payments WHERE obligation_id = ? AND month_year = ?;
                        """, (payload.get("obligation_id"), payload.get("month_year")))

                    cursor.execute("""
                    INSERT INTO change_log (entity_name, entity_id, change_type, payload_json, device_id, hlc_timestamp)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """, (entity_name, entity_id, change_type, json.dumps(payload, ensure_ascii=False), item_dev_id, item_hlc))
                    applied_count += 1

                # 6. GOAL MERGING (LWW)
                elif entity_name == "GOAL":
                    acc_id = payload.get("account_id")
                    if acc_id:
                        cursor.execute("SELECT id FROM accounts WHERE id = ?;", (acc_id,))
                        if not cursor.fetchone():
                            acc_id = None
                    cat_id = payload.get("category_id")
                    if cat_id:
                        cursor.execute("SELECT id FROM categories WHERE id = ?;", (cat_id,))
                        if not cursor.fetchone():
                            cat_id = None

                    cursor.execute("""
                    INSERT OR REPLACE INTO goals (id, name, target_amount_cents, current_amount_cents, target_date, account_id, category_id, icon, note, is_completed, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """, (
                        entity_id,
                        payload.get("name"),
                        payload.get("target_amount_cents"),
                        payload.get("current_amount_cents", 0),
                        payload.get("target_date"),
                        acc_id,
                        cat_id,
                        payload.get("icon", "🎯"),
                        payload.get("note"),
                        payload.get("is_completed", 0),
                        payload.get("is_active", 1),
                        payload.get("created_at", current_iso_time())
                    ))
                    cursor.execute("""
                    INSERT INTO change_log (entity_name, entity_id, change_type, payload_json, device_id, hlc_timestamp)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """, (entity_name, entity_id, change_type, json.dumps(payload, ensure_ascii=False), item_dev_id, item_hlc))
                    applied_count += 1

                # 7. GOAL CONTRIBUTION MERGING
                elif entity_name == "GOAL_CONTRIBUTION":
                    cursor.execute("""
                    INSERT OR REPLACE INTO goal_contributions (id, goal_id, amount_cents, transaction_id, source_account_id, note, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?);
                    """, (
                        entity_id,
                        payload.get("goal_id"),
                        payload.get("amount_cents"),
                        payload.get("transaction_id"),
                        payload.get("source_account_id"),
                        payload.get("note"),
                        payload.get("created_at", current_iso_time())
                    ))
                    cursor.execute("""
                    INSERT INTO change_log (entity_name, entity_id, change_type, payload_json, device_id, hlc_timestamp)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """, (entity_name, entity_id, change_type, json.dumps(payload, ensure_ascii=False), item_dev_id, item_hlc))
                    applied_count += 1

                # 8. ENVELOPE MERGING (LWW)
                elif entity_name == "ENVELOPE":
                    acc_id = payload.get("linked_account_id")
                    if acc_id:
                        cursor.execute("SELECT id FROM accounts WHERE id = ?;", (acc_id,))
                        if not cursor.fetchone():
                            acc_id = None
                    cat_id = payload.get("category_id")
                    if cat_id:
                        cursor.execute("SELECT id FROM categories WHERE id = ?;", (cat_id,))
                        if not cursor.fetchone():
                            cat_id = None

                    cursor.execute("""
                    INSERT OR REPLACE INTO envelopes (id, name, target_amount_cents, current_amount_cents, icon, color, linked_account_id, category_id, note, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """, (
                        entity_id,
                        payload.get("name"),
                        payload.get("target_amount_cents", 0),
                        payload.get("current_amount_cents", 0),
                        payload.get("icon", "✉️"),
                        payload.get("color", "#3b82f6"),
                        acc_id,
                        cat_id,
                        payload.get("note"),
                        payload.get("is_active", 1),
                        payload.get("created_at", current_iso_time())
                    ))
                    cursor.execute("""
                    INSERT INTO change_log (entity_name, entity_id, change_type, payload_json, device_id, hlc_timestamp)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """, (entity_name, entity_id, change_type, json.dumps(payload, ensure_ascii=False), item_dev_id, item_hlc))
                    applied_count += 1

                # 9. ENVELOPE OPERATION MERGING
                elif entity_name == "ENVELOPE_OPERATION":
                    cursor.execute("""
                    INSERT OR REPLACE INTO envelope_operations (id, envelope_id, operation_type, amount_cents, source_account_id, destination_account_id, target_envelope_id, note, member_id, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """, (
                        entity_id,
                        payload.get("envelope_id"),
                        payload.get("operation_type"),
                        payload.get("amount_cents"),
                        payload.get("source_account_id"),
                        payload.get("destination_account_id"),
                        payload.get("target_envelope_id"),
                        payload.get("note"),
                        payload.get("member_id"),
                        payload.get("created_at", current_iso_time())
                    ))
                    cursor.execute("""
                    INSERT INTO change_log (entity_name, entity_id, change_type, payload_json, device_id, hlc_timestamp)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """, (entity_name, entity_id, change_type, json.dumps(payload, ensure_ascii=False), item_dev_id, item_hlc))
                    applied_count += 1

            # Update last synced HLC for this remote device
            if remote_device_id and remote_hlc:
                cursor.execute("""
                INSERT OR REPLACE INTO system_meta (key, value) VALUES (?, ?);
                """, (f"sync_last_hlc_{remote_device_id}", remote_hlc))

            conn.commit()
            self._save_if_encrypted()
            return {
                "status": "success",
                "applied_count": applied_count,
                "skipped_count": skipped_count,
                "current_hlc": self.hlc.now()
            }
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self._close_if_local(conn)


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
                                "device_name": beacon.get("device_name", "Семейное устройство"),
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
