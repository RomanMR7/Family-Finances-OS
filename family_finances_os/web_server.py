"""

Family Finances OS - Stage 3 Mobile-First, Categories, Obligations & Envelope Encrypted Web Server

Runs locally on http://127.0.0.1:8000.

Features:

- Envelope Encryption (AES-256-GCM + PBKDF2 600k)

- DNS-Rebinding Protection & OWASP Security Headers

- Hierarchical Category Tree (Income/Expense)

- Fixed Monthly Obligations & Accurate Safe-to-Spend

- Mobile-Responsive Adaptive UI with Bottom Navigation & Fast Category Chips

- Auto-lock on Idle (15 min inactivity timer)

"""

import http.server

import json

import os

import socket

import socketserver

import urllib.parse

import urllib.request

import uuid

from pathlib import Path

from typing import Dict, Any, Optional, List

from family_finances_os.config import APP_NAME, APP_VERSION, DB_PATH, ENC_DB_PATH, STRICT_ENCRYPTION

import base64
import hashlib
import sqlite3
import tempfile
from family_finances_os.db import init_database, check_db_health, GLOBAL_STORAGE, create_schema, get_connection

from family_finances_os.auth import AuthService, GLOBAL_SESSION_MANAGER

from family_finances_os.ledger import LedgerEngine

from family_finances_os.qr import QRCode, generate_qr_svg

from family_finances_os.models import (

    Transaction,

    Posting,

    rubles_to_cents,

    cents_to_rubles,

    generate_uuid,

    current_iso_time

)

PORT = 8000

ENABLE_P2P_SYNC: bool = os.environ.get("FFOS_ENABLE_P2P_SYNC", "0").lower() in ("1", "true", "yes")

def get_lan_ip_candidates() -> List[str]:

    """Discover candidate LAN IPv4 addresses of the host machine."""

    candidates = []

    try:

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        s.settimeout(0.2)

        s.connect(("10.255.255.255", 1))

        ip = s.getsockname()[0]

        s.close()

        if ip and not ip.startswith("127.") and not ip.startswith("172."):

            candidates.append(ip)

    except Exception:

        pass

    try:

        host_name = socket.gethostname()

        for ip in socket.gethostbyname_ex(host_name)[2]:

            if not ip.startswith("127.") and not ip.startswith("172.") and ip not in candidates:

                candidates.append(ip)

    except Exception:

        pass

    return candidates

def resolve_external_host(headers: dict, fallback_host: str = "127.0.0.1") -> str:

    """

    Cascade resolution for mobile pairing:

    1. FFOS_EXTERNAL_HOST environment variable

    2. Incoming Host/X-Forwarded-Host header (if not localhost/127.0.0.1 and not docker 172.)

    3. LAN IPv4 candidate probe

    4. Fallback host

    """

    env_host = os.environ.get("FFOS_EXTERNAL_HOST", "").strip()

    if env_host:

        return env_host

    raw_host = headers.get("X-Forwarded-Host") or headers.get("Host", "")

    host_name = raw_host.split(":")[0].strip()

    if host_name and host_name.lower() not in ("localhost", "127.0.0.1", "0.0.0.0", "web"):

        if not host_name.startswith("172."):

            return host_name

    candidates = get_lan_ip_candidates()

    if candidates:

        return candidates[0]

    return fallback_host

def safe_float(val: Any, default: float = 0.0) -> float:
    """Safely parse float from string, handling spaces, commas, and currency symbols."""
    if val is None:
        return default
    if isinstance(val, (int, float)):
        return float(val)
    s = str(val).strip().replace(" ", "").replace("\xa0", "").replace("₽", "").replace(",", ".")
    if not s:
        return default
    try:
        return float(s)
    except (ValueError, TypeError):
        return default


class FamilyFinancesHandler(http.server.BaseHTTPRequestHandler):

    storage = GLOBAL_STORAGE

    def _validate_host(self) -> bool:

        """

        DNS Rebinding Protection:

        Verify Host header points to localhost or private IPv4 address.

        """

        raw_host = self.headers.get("Host", "").split(":")[0].strip().lower()

        if not raw_host:

            return True

        if os.environ.get("VERCEL") or raw_host.endswith(".vercel.app"):

            return True

        allowed_hosts = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

        if raw_host in allowed_hosts or raw_host.startswith("192.168.") or raw_host.startswith("10."):

            return True

        if raw_host.startswith("172."):

            parts = raw_host.split(".")

            if len(parts) >= 2 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:

                return True

        return False

    def _send_json(self, data: dict, status: int = 200):

        body = json.dumps(data, ensure_ascii=False).encode("utf-8")

        self.send_response(status)

        self.send_header("Content-Type", "application/json; charset=utf-8")

        self.send_header("Content-Length", str(len(body)))

        # Security hardening headers

        self.send_header("X-Content-Type-Options", "nosniff")

        self.send_header("X-Frame-Options", "DENY")

        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline' data:;")

        self.send_header("Referrer-Policy", "no-referrer")

        self.end_headers()

        self.wfile.write(body)

    def _send_html(self, html: str, status: int = 200):

        body = html.encode("utf-8")

        self.send_response(status)

        self.send_header("Content-Type", "text/html; charset=utf-8")

        self.send_header("Content-Length", str(len(body)))

        # Disable caching for HTML so UI changes are instantly visible

        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0")

        self.send_header("Pragma", "no-cache")

        self.send_header("Expires", "0")

        # Security hardening headers

        self.send_header("X-Content-Type-Options", "nosniff")

        self.send_header("X-Frame-Options", "DENY")

        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline' data:; worker-src 'self'; manifest-src 'self';")

        self.send_header("Referrer-Policy", "no-referrer")

        self.end_headers()

        self.wfile.write(body)

    def _send_manifest(self):

        manifest_data = {

            "name": "Family Finances OS",

            "short_name": "Финансы OS",

            "description": "Автономная защищенная семейная финансовая операционная система",

            "start_url": "/",

            "scope": "/",

            "display": "standalone",

            "background_color": "#0b1120",

            "theme_color": "#0b1120",

            "orientation": "portrait-primary",

            "icons": [

                {

                    "src": "/icon.svg",

                    "sizes": "any",

                    "type": "image/svg+xml",

                    "purpose": "any maskable"

                },

                {

                    "src": "/icon.svg",

                    "sizes": "192x192 512x512",

                    "type": "image/svg+xml",

                    "purpose": "any"

                }

            ]

        }

        body = json.dumps(manifest_data, ensure_ascii=False).encode("utf-8")

        self.send_response(200)

        self.send_header("Content-Type", "application/manifest+json; charset=utf-8")

        self.send_header("Content-Length", str(len(body)))

        self.send_header("Cache-Control", "no-cache")

        self.end_headers()

        self.wfile.write(body)

    def _send_sw(self):

        sw_code = """// Family Finances OS - PWA Service Worker

const CACHE_NAME = 'ffos-shell-v22';

const STATIC_SHELL = [

  '/manifest.json',

  '/icon.svg'

];

self.addEventListener('install', (event) => {

  event.waitUntil(

    caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_SHELL))

  );

  self.skipWaiting();

});

self.addEventListener('activate', (event) => {

  event.waitUntil(

    caches.keys().then((keys) => {

      return Promise.all(

        keys.map((key) => {

          if (key !== CACHE_NAME) {

            return caches.delete(key);

          }

        })

      );

    })

  );

  self.clients.claim();

});

self.addEventListener('fetch', (event) => {

  const url = new URL(event.request.url);

  // CRITICAL: API requests must NEVER use Cache-First. Always use Network-First.

  if (url.pathname.startsWith('/api/')) {

    event.respondWith(

      fetch(event.request).catch(() => {

        return new Response(

          JSON.stringify({

            status: 'error',

            error: 'offline',

            message: 'Офлайн-режим: сервер Family Finances OS недоступен'

          }),

          {

            status: 503,

            headers: { 'Content-Type': 'application/json; charset=utf-8' }

          }

        );

      })

    );

    return;

  }

  // Network-First for HTML navigation so changes are instantly visible; fallback to cache only when offline

  event.respondWith(

    fetch(event.request).then((networkResponse) => {

      if (networkResponse && networkResponse.status === 200) {

        const copy = networkResponse.clone();

        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));

      }

      return networkResponse;

    }).catch(() => {

      return caches.match(event.request);

    })

  );

});

"""

        body = sw_code.encode("utf-8")

        self.send_response(200)

        self.send_header("Content-Type", "application/javascript; charset=utf-8")

        self.send_header("Content-Length", str(len(body)))

        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")

        self.end_headers()

        self.wfile.write(body)

    def _send_icon_svg(self):

        svg_code = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">

  <defs>

    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">

      <stop offset="0%" stop-color="#0f172a"/>

      <stop offset="100%" stop-color="#020617"/>

    </linearGradient>

    <linearGradient id="goldGrad" x1="0%" y1="0%" x2="100%" y2="100%">

      <stop offset="0%" stop-color="#fbbf24"/>

      <stop offset="100%" stop-color="#d97706"/>

    </linearGradient>

    <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">

      <stop offset="0%" stop-color="#10b981"/>

      <stop offset="100%" stop-color="#047857"/>

    </linearGradient>

  </defs>

  <rect width="512" height="512" rx="128" fill="url(#bgGrad)"/>

  <path d="M256 80 L380 140 C380 280 256 380 256 420 C256 380 132 280 132 140 Z" fill="url(#shieldGrad)" opacity="0.18"/>

  <path d="M256 100 L360 152 C360 270 256 360 256 395 C256 360 152 270 152 152 Z" fill="none" stroke="#10b981" stroke-width="12" stroke-linecap="round" stroke-linejoin="round"/>

  <circle cx="256" cy="245" r="72" fill="url(#goldGrad)"/>

  <circle cx="256" cy="245" r="56" fill="none" stroke="#fef3c7" stroke-width="4" stroke-dasharray="10 6"/>

  <text x="256" y="278" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="82" font-weight="900" fill="#78350f" text-anchor="middle">₽</text>

  <circle cx="256" cy="385" r="10" fill="#10b981"/>

  <circle cx="160" cy="158" r="8" fill="#10b981"/>

  <circle cx="352" cy="158" r="8" fill="#10b981"/>

</svg>"""

        body = svg_code.encode("utf-8")

        self.send_response(200)

        self.send_header("Content-Type", "image/svg+xml; charset=utf-8")

        self.send_header("Content-Length", str(len(body)))

        self.send_header("Cache-Control", "public, max-age=86400")

        self.end_headers()

        self.wfile.write(body)

    def _read_json_body(self) -> dict:
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            content_length = 0

        if content_length <= 0:
            self._raw_body_bytes = b""
            return {}

        try:
            self._raw_body_bytes = self.rfile.read(content_length)
            decoded = self._raw_body_bytes.decode("utf-8", errors="replace").strip()
            if not decoded:
                return {}
            parsed = json.loads(decoded)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    def _get_bearer_token(self) -> Optional[str]:

        auth_header = self.headers.get("Authorization", "")

        if auth_header.startswith("Bearer "):

            return auth_header[7:].strip()

        return None

    def _get_ledger(self) -> LedgerEngine:

        conn = self.storage.get_connection() if self.storage.is_unlocked() else None

        return LedgerEngine(conn_or_path=conn)

    def _require_auth(self) -> Optional[Dict[str, Any]]:

        """Validate bearer token from headers. If invalid, sends 401 and returns None."""

        token = self._get_bearer_token()

        user = GLOBAL_SESSION_MANAGER.validate_session(token)

        if not user:

            self._send_json({"status": "error", "message": "Требуется авторизация (сессия недействительна или истекла)"}, 401)

            return None

        return user

    def _is_db_locked(self) -> bool:

        """

        Check if storage is locked.

        If storage is active and unlocked in memory, returns False.

        If encrypted storage exists on disk and is not unlocked in memory, returns True.

        If strict encryption is on and storage is not unlocked, returns True.

        If plain counterpart exists and not STRICT_ENCRYPTION, returns False (fallback mode).

        """

        from family_finances_os.config import STRICT_ENCRYPTION

        if self.storage.is_unlocked():

            return False

        if not self.storage.exists():

            return False

        if STRICT_ENCRYPTION:

            return True

        plain_counterpart = self.storage.enc_path.with_name(self.storage.enc_path.stem)

        if plain_counterpart.exists():

            return False

        return True

    def _has_owner(self) -> bool:
        """Check whether an owner account currently exists in the database."""
        if self.storage.is_unlocked():
            try:
                auth = AuthService(conn_or_path=self.storage.get_connection())
                return auth.has_owner()
            except Exception:
                return False
        if self._is_db_locked() and self.storage.exists():
            return True
        target_plain = DB_PATH if DB_PATH.exists() else self.storage.enc_path.with_name(self.storage.enc_path.stem)
        if target_plain.exists():
            try:
                auth = AuthService(conn_or_path=target_plain)
                return auth.has_owner()
            except Exception:
                return False
        return False

    def _get_database_raw_bytes(self) -> Optional[bytes]:
        """Extract raw bytes of active database, flushing WAL if needed."""
        if self.storage.is_unlocked():
            try:
                return self.storage.get_connection().serialize()
            except Exception:
                pass
        target = DB_PATH if DB_PATH.exists() else self.storage.enc_path.with_name(self.storage.enc_path.stem)
        if target.exists():
            try:
                conn = get_connection(target)
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                conn.close()
            except Exception:
                pass
            try:
                return target.read_bytes()
            except Exception:
                pass
        if self.storage.exists():
            try:
                return self.storage.enc_path.read_bytes()
            except Exception:
                pass
        return None

    def do_GET(self):

        if not self._validate_host():

            self._send_json({"status": "error", "message": "Forbidden: DNS Rebinding Protection"}, 403)

            return

        url = urllib.parse.urlparse(self.path)

        path = url.path

        # PWA Web App Manifest

        if path in ("/manifest.json", "/manifest.webmanifest"):

            self._send_manifest()

            return

        # PWA Service Worker

        if path in ("/sw.js", "/service-worker.js"):

            self._send_sw()

            return

        # PWA & Web Icons

        if path in ("/icon.svg", "/icon-192.svg", "/icon-512.svg", "/icon-192.png", "/icon-512.png", "/apple-touch-icon.png", "/favicon.ico"):

            self._send_icon_svg()

            return

        # 1. Public Metadata & Status

        if path == "/api/status":

            is_locked = self._is_db_locked()

            is_encrypted = self.storage.exists()

            has_owner = False

            target_plain = self.storage.enc_path.with_name(self.storage.enc_path.stem)

            if self.storage.is_unlocked():

                try:

                    auth = AuthService(conn_or_path=self.storage.get_connection())

                    has_owner = auth.has_owner()

                except Exception:

                    has_owner = False

            elif not is_locked and target_plain.exists():

                try:

                    auth = AuthService(conn_or_path=target_plain)

                    has_owner = auth.has_owner()

                except Exception:

                    has_owner = False

            elif is_locked and self.storage.exists():

                has_owner = True

            health = check_db_health(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

            self._send_json({

                "app": APP_NAME,

                "version": APP_VERSION,

                "is_encrypted": is_encrypted,

                "is_locked": is_locked,

                "has_owner": has_owner,

                "db_health": health

            })

            return

        # Database Backup & Export Endpoints
        if path == "/api/database/export-blob":
            user = self._require_auth()
            if not user:
                return
            raw_bytes = self._get_database_raw_bytes()
            if not raw_bytes:
                self._send_json({"status": "error", "message": "База данных недоступна для экспорта"}, 500)
                return
            sha256 = hashlib.sha256(raw_bytes).hexdigest()
            b64_str = base64.b64encode(raw_bytes).decode("ascii")
            self._send_json({
                "status": "ok",
                "size_bytes": len(raw_bytes),
                "sha256": sha256,
                "blob_base64": b64_str,
                "exported_at": current_iso_time()
            })
            return

        if path in ("/api/database/export-file", "/api/database/download", "/api/database/backup"):
            user = self._require_auth()
            if not user:
                return
            raw_bytes = self._get_database_raw_bytes()
            if not raw_bytes:
                self._send_json({"status": "error", "message": "База данных недоступна"}, 500)
                return
            filename = f"family_finances_backup_{current_iso_time()[:10].replace('-', '')}.db"
            self.send_response(200)
            self.send_header("Content-Type", "application/x-sqlite3")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(raw_bytes)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(raw_bytes)
            return

        # 2. Gatekeeper: if DB is encrypted and locked, prevent data leakage

        if self._is_db_locked() and path.startswith("/api/"):

            self._send_json({

                "status": "locked",

                "message": "База данных зашифрована и заблокирована. Требуется ввести мастер-пароль."

            }, 423)

            return

        # 3. Protected Overview (Stage 2 & 3)

        if path == "/api/overview" or path == "/api/summary":

            user = self._require_auth()

            if not user:

                return

            ledger = LedgerEngine()

            ledger.seed_default_categories()

            overview = ledger.get_financial_overview()

            self._send_json(overview)

            return

        elif path == "/api/accounts":

            user = self._require_auth()

            if not user:

                return

            ledger = LedgerEngine()

            overview = ledger.get_financial_overview()

            self._send_json(overview["accounts"])

            return

        elif path == "/api/transactions":

            user = self._require_auth()

            if not user:

                return

            ledger = self._get_ledger()

            conn = ledger._get_conn()

            cursor = conn.cursor()

            query_params = urllib.parse.parse_qs(url.query)

            month = query_params.get("month", [None])[0]

            cursor.execute("""

            SELECT DISTINCT strftime('%Y-%m', tx_date) as ym 

            FROM transactions 

            WHERE is_voided = 0 AND tx_date IS NOT NULL

            ORDER BY ym DESC;

            """)

            available_months = [r["ym"] for r in cursor.fetchall() if r["ym"]]

            current_ym = current_iso_time()[:7]

            if current_ym not in available_months:

                available_months.insert(0, current_ym)

            if month:

                cursor.execute("""

                SELECT t.id, t.tx_date, t.tx_type, t.description, t.idempotency_key, t.created_at,

                       p.account_id, a.name as account_name, a.code as account_code, p.amount_cents, p.posting_type, p.ownership_scope,

                       c.id as category_id, c.name as category_name, c.icon as category_icon

                FROM transactions t

                JOIN postings p ON t.id = p.transaction_id

                JOIN accounts a ON p.account_id = a.id

                LEFT JOIN categories c ON p.category_id = c.id

                WHERE t.is_voided = 0 AND strftime('%Y-%m', t.tx_date) = ?

                ORDER BY t.tx_date DESC, t.created_at DESC;

                """, (month,))

            else:

                cursor.execute("""

                SELECT t.id, t.tx_date, t.tx_type, t.description, t.idempotency_key, t.created_at,

                       p.account_id, a.name as account_name, a.code as account_code, p.amount_cents, p.posting_type, p.ownership_scope,

                       c.id as category_id, c.name as category_name, c.icon as category_icon

                FROM transactions t

                JOIN postings p ON t.id = p.transaction_id

                JOIN accounts a ON p.account_id = a.id

                LEFT JOIN categories c ON p.category_id = c.id

                WHERE t.is_voided = 0

                ORDER BY t.tx_date DESC, t.created_at DESC

                LIMIT 100;

                """)

            rows = cursor.fetchall()

            tx_map = {}

            for r in rows:

                tx_id = r["id"]

                if tx_id not in tx_map:

                    tx_map[tx_id] = {

                        "id": tx_id,

                        "tx_date": r["tx_date"],

                        "tx_type": r["tx_type"],

                        "description": r["description"],

                        "created_at": r["created_at"],

                        "category_id": r["category_id"],

                        "category_name": r["category_name"] or "Без категории",

                        "category_icon": r["category_icon"] or "tag",

                        "account_id": r["account_id"] if r["account_code"] in ("1010", "1011", "1020", "2010") else None,

                        "account_name": r["account_name"] if r["account_code"] in ("1010", "1011", "1020", "2010") else None,

                        "amount_rub": cents_to_rubles(r["amount_cents"]),

                        "amount_cents": r["amount_cents"],

                        "postings": []

                    }

                else:

                    if r["account_code"] in ("1010", "1011", "1020", "2010") or (r["account_id"] and (r["account_id"].startswith("acc_core_10") or r["account_id"].startswith("acc_core_20"))):

                        tx_map[tx_id]["account_id"] = r["account_id"]

                        tx_map[tx_id]["account_name"] = r["account_name"]

                    if r["category_id"]:

                        tx_map[tx_id]["category_id"] = r["category_id"]

                        tx_map[tx_id]["category_name"] = r["category_name"]

                        tx_map[tx_id]["category_icon"] = r["category_icon"] or "tag"

                tx_map[tx_id]["postings"].append({

                    "account_id": r["account_id"],

                    "account_name": r["account_name"],

                    "account_code": r["account_code"],

                    "amount_rub": cents_to_rubles(r["amount_cents"]),

                    "type": r["posting_type"],

                    "scope": r["ownership_scope"]

                })

            ledger._close_if_local(conn)

            tx_list = list(tx_map.values())

            if month:

                self._send_json({

                    "status": "success",

                    "selected_month": month,

                    "available_months": available_months,

                    "transactions": tx_list

                })

            else:

                self._send_json(tx_list)

            return

        elif path == "/api/categories":

            user = self._require_auth()

            if not user:

                return

            ledger = LedgerEngine()

            ledger.seed_default_categories()

            qs = urllib.parse.parse_qs(url.query)

            cat_type = qs.get("type", [None])[0]

            tree = ledger.get_category_tree(cat_type)

            flat = ledger.get_flat_categories(cat_type)

            self._send_json({"tree": tree, "flat": flat})

            return

        # Stage 3 Obligations endpoint

        elif path == "/api/obligations":

            user = self._require_auth()

            if not user:

                return

            ledger = self._get_ledger()

            query_params = urllib.parse.parse_qs(url.query)

            month = query_params.get("month", [None])[0]

            obligations = ledger.get_obligations(month_year=month)

            unpaid_cents, total_cents, paid_cents = ledger.calculate_unpaid_obligations_cents(month_year=month)

            self._send_json({

                "selected_month": month,

                "obligations": obligations,

                "total_rub": cents_to_rubles(total_cents),

                "paid_rub": cents_to_rubles(paid_cents),

                "unpaid_rub": cents_to_rubles(unpaid_cents)

            })

            return

        elif path == "/api/sync/status":

            user = self._require_auth()

            if not user:

                return

            from family_finances_os.sync import P2PSyncEngine

            sync_engine = P2PSyncEngine()

            peers = GLOBAL_DISCOVERY_BEACON.get_active_peers() if GLOBAL_DISCOVERY_BEACON else []

            self._send_json({

                "device_id": sync_engine.device_id,

                "device_name": sync_engine.device_name,

                "current_hlc": sync_engine.hlc.now(),

                "active_peers": peers

            })

            return

        # Stage 7 Financial Analytics Endpoint

        elif path == "/api/analytics/summary":

            user = self._require_auth()

            if not user:

                return

            qs = urllib.parse.parse_qs(url.query)

            period = qs.get("period", ["current_month"])[0]

            start_date = qs.get("start_date", [None])[0]

            end_date = qs.get("end_date", [None])[0]

            ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

            analytics = ledger.get_spending_analytics(period=period, start_date=start_date, end_date=end_date)

            self._send_json(analytics)

            return

        # Stage 7 30/60/90-Day Cash Flow Forecast Endpoint

        elif path == "/api/forecast/cashflow":

            user = self._require_auth()

            if not user:

                return

            qs = urllib.parse.parse_qs(url.query)

            try:

                days = int(qs.get("days", [30])[0])

            except Exception:

                days = 30

            include_burn = qs.get("include_burn", ["1"])[0] in ("1", "true", "True")

            custom_burn = qs.get("custom_burn", [None])[0]

            custom_burn_cents = int(custom_burn) if custom_burn and custom_burn.isdigit() else None

            ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

            forecast = ledger.get_cash_flow_forecast(

                days=days,

                include_burn_rate=include_burn,

                custom_daily_burn_cents=custom_burn_cents

            )

            self._send_json(forecast)

            return

        # Stage 8 Quick QR Pairing Endpoint

        elif path == "/api/device/qr-pair":

            user = self._require_auth()

            if not user:

                return

            qs = urllib.parse.parse_qs(url.query)

            override_ip = qs.get("override_ip", [None])[0]

            server_port = self.server.server_port if hasattr(self, 'server') and hasattr(self.server, 'server_port') else PORT

            if override_ip and override_ip.strip():

                host = override_ip.strip()

            else:

                host = resolve_external_host(self.headers, fallback_host="127.0.0.1")

            token = GLOBAL_SESSION_MANAGER.create_pairing_token(user, ttl_seconds=600)

            pair_url = f"http://{host}:{server_port}/?pair_token={token}"

            qr_svg = generate_qr_svg(pair_url)

            self._send_json({

                "ok": True,

                "pair_url": pair_url,

                "lan_ip": host,

                "port": server_port,

                "token": token,

                "expires_in": 600,

                "qr_svg": qr_svg

            })

            return

        # Stage 9 Financial Goals Endpoint

        elif path == "/api/goals":

            user = self._require_auth()

            if not user:

                return

            ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

            goals = ledger.get_goals(include_completed=True)

            self._send_json({"status": "success", "goals": goals})

            return

        # Stage 9 Debts Summary Endpoint

        elif path == "/api/debts/calculate-payoff":
            user = self._require_auth()
            if not user:
                return
            try:
                ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                liability_id = qs.get("liability_account_id", [None])[0]
                custom_rub = qs.get("custom_payment_rub", [None])[0]
                custom_pct = qs.get("custom_payment_percent", [None])[0]
                apr = qs.get("interest_rate_percent", ["24.8"])[0]
                min_pct = qs.get("min_payment_percent", ["3"])[0]
                grace_days, grace_due = 120, None
                if liability_id:
                    account = ledger.get_account_by_id(liability_id)
                    if not account or account.account_type != "LIABILITY" or not account.is_active:
                        raise ValueError("Активная задолженность не найдена.")
                    if account.currency != "RUB":
                        raise ValueError("Калькулятор с рублёвым минимумом не применяется к другой валюте.")
                    debt_cents = max(0, ledger.get_account_balance_cents(liability_id))
                    if account.description and account.description.strip().startswith("{"):
                        metadata = json.loads(account.description)
                        apr = metadata.get("interest_rate_percent", 24.8)
                        min_pct = metadata.get("min_payment_percent", 3)
                        grace_days = metadata.get("grace_period_days", 120)
                        grace_due = metadata.get("grace_due_date")
                else:
                    debt_cents = rubles_to_cents(qs.get("debt_rub", ["0"])[0])
                result = ledger.calculate_credit_payoff_scenarios(
                    debt_cents=debt_cents, interest_rate_percent=apr,
                    min_payment_percent=min_pct, grace_period_days=grace_days,
                    grace_due_date=grace_due,
                    custom_payment_cents=rubles_to_cents(custom_rub) if custom_rub is not None else None,
                    custom_payment_percent=custom_pct)
                self._send_json(result)
            except Exception as exc:
                self._send_json({"status": "error", "message": str(exc)}, status=400)
            return

        elif path == "/api/debts":

            user = self._require_auth()

            if not user:

                return

            ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

            summary = ledger.get_debts_summary()

            self._send_json(summary)

            return

        # Stage 10 Envelopes / Piggy Banks Endpoint

        elif path == "/api/envelopes":

            user = self._require_auth()

            if not user:

                return

            ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

            summary = ledger.get_envelopes_summary()

            self._send_json({"status": "success", "summary": summary, "envelopes": summary.get("envelopes", [])})

            return

        # Main HTML Application

        html = self._render_app_html()

        self._send_html(html)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_POST(self):

        if not self._validate_host():

            self._send_json({"status": "error", "message": "Forbidden: DNS Rebinding Protection"}, 403)

            return

        url = urllib.parse.urlparse(self.path)

        path = url.path

        if path == "/api/database/restore-blob":
            try:
                cl = int(self.headers.get("Content-Length", 0))
            except (ValueError, TypeError):
                cl = 0
            if cl > 20 * 1024 * 1024:
                self._send_json({"status": "error", "error": "Размер полезной нагрузки превышает лимит 20 МБ"}, 413)
                return

            has_owner = self._has_owner()
            if has_owner:
                user = self._require_auth()
                if not user:
                    return

            body = self._read_json_body()
            blob_base64 = body.get("blob_base64")
            if not blob_base64 or not isinstance(blob_base64, str):
                self._send_json({"status": "error", "error": "Отсутствует или недействителен параметр blob_base64"}, 400)
                return

            try:
                raw_bytes = base64.b64decode(blob_base64, validate=True)
            except Exception:
                self._send_json({"status": "error", "error": "Некорректная кодировка base64"}, 400)
                return

            if not (raw_bytes.startswith(b"SQLite format 3\x00") or raw_bytes.startswith(b"FFOS_ENV\x01")):
                self._send_json({"status": "error", "error": "Неверный формат: файл должен быть базой данных SQLite"}, 400)
                return

            # Verify integrity if raw SQLite
            if raw_bytes.startswith(b"SQLite format 3\x00"):
                temp_fd, temp_path = tempfile.mkstemp(prefix="ffos_restore_")
                os.close(temp_fd)
                try:
                    with open(temp_path, "wb") as f:
                        f.write(raw_bytes)
                    test_conn = sqlite3.connect(temp_path, timeout=5.0)
                    cur = test_conn.cursor()
                    cur.execute("PRAGMA integrity_check;")
                    row = cur.fetchone()
                    test_conn.close()
                    if not row or row[0] != "ok":
                        self._send_json({"status": "error", "error": f"Ошибка целостности базы данных: {row[0] if row else 'неизвестная ошибка'}"}, 400)
                        return
                except Exception as e:
                    self._send_json({"status": "error", "error": f"Файл поврежден или не является базой: {e}"}, 400)
                    return
                finally:
                    try:
                        if os.path.exists(temp_path):
                            os.unlink(temp_path)
                    except Exception:
                        pass

            # Restore database atomically to DB_PATH
            target_path = DB_PATH
            target_path.parent.mkdir(parents=True, exist_ok=True)
            wal_path = target_path.with_suffix(target_path.suffix + "-wal")
            shm_path = target_path.with_suffix(target_path.suffix + "-shm")
            for companion in (wal_path, shm_path):
                try:
                    if companion.exists():
                        companion.unlink()
                except Exception:
                    pass

            temp_restore = target_path.with_suffix(".tmp_restore")
            try:
                temp_restore.write_bytes(raw_bytes)
                temp_restore.replace(target_path)
            except Exception:
                target_path.write_bytes(raw_bytes)

            # If encrypted storage was active, reload connection in memory
            if self.storage.is_unlocked():
                try:
                    self.storage.get_connection().deserialize(raw_bytes)
                except Exception:
                    pass

            # Run schema migrations to ensure all tables exist
            try:
                conn = get_connection(target_path)
                create_schema(conn)
                conn.close()
            except Exception:
                pass

            # Create session token for owner
            token = None
            user_dict = None
            try:
                conn = get_connection(target_path)
                cur = conn.cursor()
                cur.execute("SELECT id, username, display_name, role FROM users WHERE role = 'OWNER' AND is_active = 1 LIMIT 1;")
                owner_row = cur.fetchone()
                conn.close()
                if owner_row:
                    user_dict = {
                        "user_id": owner_row[0],
                        "username": owner_row[1],
                        "display_name": owner_row[2],
                        "role": owner_row[3]
                    }
                    token = GLOBAL_SESSION_MANAGER.create_session(user_dict)
            except Exception:
                pass

            self._send_json({
                "status": "ok",
                "restored": True,
                "size_bytes": len(raw_bytes),
                "token": token,
                "user": user_dict,
                "restored_at": current_iso_time()
            })
            return

        body = self._read_json_body()

        # -------------------------------------------------------------

        # Encryption Lifecycle Endpoints (Accessible when locked)

        # -------------------------------------------------------------

        if path == "/api/unlock":

            password = body.get("password") or body.get("master_password", "")

            if not password:

                self._send_json({"status": "error", "message": "Мастер-пароль не может быть пустым"}, 400)

                return

            try:

                self.storage.open(password)

                auth = AuthService(conn_or_path=self.storage.get_connection())

                has_owner = auth.has_owner()

                self._send_json({

                    "status": "success",

                    "message": "База данных успешно разблокирована в оперативной памяти!",

                    "has_owner": has_owner

                })

            except PermissionError:

                self._send_json({"status": "error", "message": "Неверный мастер-пароль или файл поврежден"}, 401)

            except Exception as e:

                self._send_json({"status": "error", "message": f"Ошибка разблокировки: {str(e)}"}, 500)

            return

        elif path == "/api/lock":

            self.storage.lock()

            GLOBAL_SESSION_MANAGER.clear_all_sessions()

            self._send_json({

                "status": "success",

                "message": "База данных заблокирована, ключи стёрты из памяти, сессии завершены"

            })

            return

        elif path == "/api/setup-master":

            master_password = body.get("master_password", "")

            username = body.get("username", "admin").strip()

            display_name = body.get("display_name", "Глава семьи").strip()

            if len(master_password) < 6:

                self._send_json({"status": "error", "message": "Мастер-пароль должен быть не менее 6 символов"}, 400)

                return

            if self.storage.exists():

                self._send_json({"status": "error", "message": "База данных уже инициализирована. Первичная настройка невозможна."}, 400)

                return

            target_plain = self.storage.enc_path.with_name(self.storage.enc_path.stem)

            if target_plain.exists():

                try:

                    auth = AuthService(conn_or_path=target_plain)

                    if auth.has_owner():

                        self._send_json({"status": "error", "message": "Владелец семьи уже существует."}, 400)

                        return

                except Exception:

                    pass

            try:

                self.storage.initialize_new(master_password)

                conn = self.storage.get_connection()

                auth = AuthService(conn_or_path=conn)

                owner_info = auth.create_owner(username, display_name, master_password)

                ledger = LedgerEngine(conn_or_path=conn)

                ledger.seed_default_chart_of_accounts()

                ledger.seed_default_categories()

                token = GLOBAL_SESSION_MANAGER.create_session(owner_info)

                owner_info["session_token"] = token

                self._send_json({"status": "success", "owner": owner_info})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        # -------------------------------------------------------------

        # Gatekeeper: if DB is locked, block any further POST calls

        # -------------------------------------------------------------

        if self._is_db_locked():

            self._send_json({

                "status": "locked",

                "message": "База данных зашифрована и заблокирована. Требуется ввести мастер-пароль."

            }, 423)

            return

        if path == "/api/setup-owner":

            auth = AuthService()

            try:

                username = body.get("username", "").strip()

                display_name = body.get("display_name", "").strip()

                password = body.get("password", "")

                owner_info = auth.create_owner(username, display_name, password)

                # Seed default accounts and categories

                ledger = LedgerEngine()

                ledger.seed_default_chart_of_accounts()

                ledger.seed_default_categories()

                # Create session for the new owner

                token = GLOBAL_SESSION_MANAGER.create_session(owner_info)

                owner_info["session_token"] = token

                self._send_json({"status": "success", "owner": owner_info})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/login":

            auth = AuthService()

            username = body.get("username", "").strip()

            password = body.get("password", "")

            user = auth.authenticate(username, password)

            if user:

                self._send_json({"status": "success", "user": user})

            else:

                self._send_json({"status": "error", "message": "Неверное имя пользователя или пароль"}, 401)

            return

        # Stage 8 Quick QR Pairing Login

        elif path == "/api/auth/pair-login":

            token = body.get("token", "").strip()

            if not token:

                self._send_json({"status": "error", "message": "Токен сопряжения обязателен"}, 400)

                return

            user_info = GLOBAL_SESSION_MANAGER.consume_pairing_token(token)

            if not user_info:

                self._send_json({

                    "status": "error",

                    "error": "invalid_or_expired_token",

                    "message": "Срок действия QR-кода сопряжения истек или он уже был использован."

                }, 401)

                return

            new_session_token = GLOBAL_SESSION_MANAGER.create_session(user_info)

            user_response = dict(user_info)

            user_response["session_token"] = new_session_token

            self._send_json({

                "status": "ok",

                "session_token": new_session_token,

                "user": user_response

            })

            return

        elif path == "/api/logout":

            token = self._get_bearer_token()

            GLOBAL_SESSION_MANAGER.invalidate_session(token)

            self._send_json({"status": "success", "message": "Сессия успешно завершена"})

            return

        # --- Stage 2 Account Management Endpoints ---

        elif path == "/api/accounts/create":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine()

                name = body.get("name", "").strip()

                account_type = body.get("account_type", "ASSET")

                subtype = body.get("subtype", "DEBIT_CARD")

                ownership_scope = body.get("ownership_scope", "COMMON")

                description = body.get("description", "").strip() or None

                initial_balance_rub = body.get("initial_balance_rub", "0")

                credit_limit_rub = body.get("credit_limit_rub", "0")

                init_cents = rubles_to_cents(initial_balance_rub)

                limit_cents = rubles_to_cents(credit_limit_rub)

                acc = ledger.create_account(

                    name=name,

                    account_type=account_type,

                    subtype=subtype,

                    ownership_scope=ownership_scope,

                    owner_member_id=user.get("member_id"),

                    description=description,

                    credit_limit_cents=limit_cents,

                    initial_balance_cents=init_cents

                )

                self._send_json({"status": "success", "account": {"id": acc.id, "name": acc.name, "code": acc.code}})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/accounts/update":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine()

                account_id = body.get("account_id")

                name = body.get("name")

                description = body.get("description")

                credit_limit_rub = body.get("credit_limit_rub")

                limit_cents = rubles_to_cents(credit_limit_rub) if credit_limit_rub is not None else None

                ownership_scope = body.get("ownership_scope")

                ok = ledger.update_account(account_id, name=name, description=description, credit_limit_cents=limit_cents, ownership_scope=ownership_scope)

                self._send_json({"status": "success" if ok else "error"})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/accounts/archive":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine()

                account_id = body.get("account_id")

                ok = ledger.archive_account(account_id)

                self._send_json({"status": "success" if ok else "error"})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        # --- Stage 2 & 3 Transfers & Transactions ---

        elif path == "/api/transfer/create":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine()

                from_id = body.get("from_account_id")

                to_id = body.get("to_account_id")

                amount_rub = body.get("amount_rub")

                desc = body.get("description", "Внутренний перевод")

                idempotency_key = body.get("idempotency_key")

                amount_cents = rubles_to_cents(amount_rub)

                tx_id = ledger.record_transfer(

                    from_account_id=from_id,

                    to_account_id=to_id,

                    amount_cents=amount_cents,

                    description=desc,

                    created_by_member_id=user.get("member_id"),

                    idempotency_key=idempotency_key

                )

                self._send_json({"status": "success", "transaction_id": tx_id})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/transaction/create":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = self._get_ledger()

                tx_type = body.get("tx_type", "EXPENSE")

                account_id = body.get("account_id")

                category_account_id = body.get("category_account_id")

                category_id = body.get("category_id") or None

                desc = body.get("description", "Операция")

                amount_rub = body.get("amount_rub")

                idempotency_key = body.get("idempotency_key")

                is_personal_for_common = body.get("is_personal_for_common", False)

                amount_cents = rubles_to_cents(amount_rub)

                tx_date = body.get("tx_date") or current_iso_time()[:10]

                if is_personal_for_common:

                    tx_id = ledger.record_common_expense_from_personal_card(

                        personal_account_id=account_id,

                        category_account_id=category_account_id,

                        amount_cents=amount_cents,

                        description=desc,

                        created_by_member_id=user.get("member_id"),

                        tx_date=tx_date,

                        idempotency_key=idempotency_key

                    )

                else:

                    tx_id = generate_uuid()

                    acc = ledger.get_account_by_id(account_id)

                    cat = ledger.get_account_by_id(category_account_id)

                    if not acc or not cat:

                        raise ValueError("Указанный денежный счет или статья не существуют.")

                    postings = []

                    if tx_type == "EXPENSE":

                        postings.append(Posting(

                            id=generate_uuid(), transaction_id=tx_id, account_id=cat.id,

                            amount_cents=amount_cents, posting_type="DEBIT", ownership_scope=acc.ownership_scope,

                            category_id=category_id

                        ))

                        postings.append(Posting(

                            id=generate_uuid(), transaction_id=tx_id, account_id=acc.id,

                            amount_cents=amount_cents, posting_type="CREDIT", ownership_scope=acc.ownership_scope

                        ))

                    else:

                        postings.append(Posting(

                            id=generate_uuid(), transaction_id=tx_id, account_id=acc.id,

                            amount_cents=amount_cents, posting_type="DEBIT", ownership_scope=acc.ownership_scope

                        ))

                        postings.append(Posting(

                            id=generate_uuid(), transaction_id=tx_id, account_id=cat.id,

                            amount_cents=amount_cents, posting_type="CREDIT", ownership_scope=acc.ownership_scope,

                            category_id=category_id

                        ))

                    tx = Transaction(

                        id=tx_id, tx_date=tx_date, tx_type=tx_type, description=desc,

                        created_by_member_id=user.get("member_id"),

                        idempotency_key=idempotency_key,

                        postings=postings

                    )

                    ledger.record_transaction(tx, idempotency_key=idempotency_key)

                self._send_json({"status": "success", "transaction_id": tx_id})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/categories/create":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine()

                name = body.get("name", "").strip()

                cat_type = body.get("category_type", "EXPENSE")

                parent_id = body.get("parent_id") or None

                icon = body.get("icon", "tag")

                sort_order = int(body.get("sort_order", 0))

                cat = ledger.create_category(name, cat_type, parent_id, icon, sort_order)

                self._send_json({"status": "success", "category": {"id": cat.id, "name": cat.name, "type": cat.category_type, "icon": cat.icon}})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/categories/update":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine()

                cat_id = body.get("category_id")

                name = body.get("name")

                parent_id = body.get("parent_id")

                icon = body.get("icon")

                sort_order = body.get("sort_order")

                if sort_order is not None:

                    sort_order = int(sort_order)

                ok = ledger.update_category(cat_id, name, parent_id, icon, sort_order)

                self._send_json({"status": "success" if ok else "error"})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/categories/archive":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine()

                cat_id = body.get("category_id")

                ok = ledger.archive_category(cat_id)

                self._send_json({"status": "success" if ok else "error"})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        # --- Stage 3 Obligations Endpoints ---

        elif path == "/api/obligations/create":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine()

                name = body.get("name", "").strip()

                amount_rub = body.get("amount_rub")

                due_day = int(body.get("due_day", 1))

                category_id = body.get("category_id") or None

                payment_account_id = body.get("payment_account_id") or None

                note = body.get("note", "").strip() or None

                amount_cents = rubles_to_cents(amount_rub)

                obl = ledger.create_obligation(name, amount_cents, due_day, category_id, payment_account_id, note)

                self._send_json({"status": "success", "obligation": {"id": obl.id, "name": obl.name, "amount_rub": cents_to_rubles(obl.amount_cents)}})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/obligations/update":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine()

                obl_id = body.get("obligation_id")

                name = body.get("name")

                amount_rub = body.get("amount_rub")

                amount_cents = rubles_to_cents(amount_rub) if amount_rub is not None else None

                due_day = int(body.get("due_day")) if body.get("due_day") is not None else None

                category_id = body.get("category_id")

                payment_account_id = body.get("payment_account_id")

                note = body.get("note")

                ok = ledger.update_obligation(obl_id, name, amount_cents, due_day, category_id, payment_account_id, note)

                self._send_json({"status": "success" if ok else "error"})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/obligations/archive":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine()

                obl_id = body.get("obligation_id")

                ok = ledger.archive_obligation(obl_id)

                self._send_json({"status": "success" if ok else "error"})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/obligations/pay":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine()

                obl_id = body.get("obligation_id")

                month_year = body.get("month_year")

                amount_rub = body.get("amount_rub")

                amount_cents = rubles_to_cents(amount_rub) if amount_rub is not None else None

                tx_id = body.get("transaction_id")

                ok = ledger.mark_obligation_paid(obl_id, month_year, tx_id, amount_cents)

                self._send_json({"status": "success" if ok else "error"})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/obligations/unpay":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine()

                obl_id = body.get("obligation_id")

                month_year = body.get("month_year")

                ok = ledger.unmark_obligation_paid(obl_id, month_year)

                self._send_json({"status": "success" if ok else "error"})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        # --- Stage 4 P2P Synchronization Endpoints ---

        elif path == "/api/sync/pull":

            from family_finances_os.sync import P2PSyncEngine, verify_sync_payload

            raw_body = getattr(self, "_raw_body_bytes", b"")

            sig = self.headers.get("X-FFOS-Signature")

            nonce = self.headers.get("X-FFOS-Nonce")

            hlc_header = self.headers.get("X-FFOS-HLC")

            sync_engine = P2PSyncEngine()

            if sig:

                if not nonce or not hlc_header or not verify_sync_payload(raw_body, sync_engine.sync_passphrase, nonce, hlc_header, sig):

                    self._send_json({"status": "error", "message": "Invalid P2P HMAC Signature"}, 401)

                    return

            else:

                user = self._require_auth()

                if not user:

                    return

            since_hlc = body.get("since_hlc")

            changes = sync_engine.export_changes(since_hlc=since_hlc)

            self._send_json(changes)

            return

        elif path == "/api/sync/push":

            from family_finances_os.sync import P2PSyncEngine, verify_sync_payload

            raw_body = getattr(self, "_raw_body_bytes", b"")

            sig = self.headers.get("X-FFOS-Signature")

            nonce = self.headers.get("X-FFOS-Nonce")

            hlc_header = self.headers.get("X-FFOS-HLC")

            sync_engine = P2PSyncEngine()

            if sig:

                if not nonce or not hlc_header or not verify_sync_payload(raw_body, sync_engine.sync_passphrase, nonce, hlc_header, sig):

                    self._send_json({"status": "error", "message": "Invalid P2P HMAC Signature"}, 401)

                    return

            else:

                user = self._require_auth()

                if not user:

                    return

            try:

                res = sync_engine.apply_remote_changes(body)

                self._send_json(res)

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 500)

            return

        elif path == "/api/sync/trigger":

            user = self._require_auth()

            if not user:

                return

            peer_ip = body.get("peer_ip")

            peer_port = int(body.get("peer_port", 8000))

            if not peer_ip:

                self._send_json({"status": "error", "message": "peer_ip is required"}, 400)

                return

            from family_finances_os.sync import P2PSyncEngine, sign_sync_payload

            sync_engine = P2PSyncEngine()

            try:

                def remote_call(route, payload):
                    encoded = json.dumps(payload).encode("utf-8")
                    nonce = uuid.uuid4().hex
                    stamp = sync_engine.hlc.now()
                    signature = sign_sync_payload(encoded, sync_engine.sync_passphrase, nonce, stamp)
                    req = urllib.request.Request(
                        f"http://{peer_ip}:{peer_port}{route}", data=encoded,
                        headers={"Content-Type":"application/json", "X-FFOS-Signature":signature,
                                 "X-FFOS-Nonce":nonce, "X-FFOS-HLC":stamp})
                    with urllib.request.urlopen(req, timeout=10.0) as response:
                        return json.loads(response.read().decode("utf-8"))

                pull_cursor = body.get("since_hlc")
                apply_res = {"status":"success", "applied_count":0, "skipped_count":0}
                while True:
                    remote_changes = remote_call("/api/sync/pull", {"since_hlc":pull_cursor})
                    page_result = sync_engine.apply_remote_changes(remote_changes)
                    for counter in ("applied_count", "skipped_count"):
                        apply_res[counter] += page_result.get(counter, 0)
                    if not remote_changes.get("has_more"):
                        break
                    next_cursor = remote_changes.get("next_cursor")
                    if not next_cursor or next_cursor == pull_cursor:
                        raise ValueError("Peer did not advance its delivery cursor")
                    pull_cursor = next_cursor

                push_cursor = None
                push_res = {"status":"success", "applied_count":0, "skipped_count":0}
                while True:
                    our_changes = sync_engine.export_changes(since_hlc=push_cursor)
                    page_result = remote_call("/api/sync/push", our_changes)
                    for counter in ("applied_count", "skipped_count"):
                        push_res[counter] += page_result.get(counter, 0)
                    if not our_changes.get("has_more"):
                        break
                    push_cursor = our_changes["next_cursor"]

                self._send_json({

                    "status": "success",

                    "pulled": apply_res,

                    "pushed": push_res

                })

            except Exception as e:

                self._send_json({"status": "error", "message": f"Ошибка синхронизации с {peer_ip}:{peer_port}: {str(e)}"}, 500)

            return

        # --- Stage 6 Onboarding & Universal Statement Importer Endpoints ---

        elif path == "/api/onboarding/setup":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

                balances = body.get("balances", [])

                obligations = body.get("obligations", [])

                for item in balances:
                    if "balance_rub" in item:
                        item["balance_cents"] = rubles_to_cents(item.pop("balance_rub"))
                    if "credit_limit_rub" in item:
                        item["credit_limit_cents"] = rubles_to_cents(item.pop("credit_limit_rub"))
                for item in obligations:
                    if "amount_rub" in item:
                        item["amount_cents"] = rubles_to_cents(item.pop("amount_rub"))
                res = ledger.batch_onboarding_setup(balances=balances, obligations=obligations, owner_member_id=user.get("member_id"))

                self._send_json(res)

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/accounts/set-initial-balance":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

                account_id = body.get("account_id")

                balance_rub = body.get("balance_rub", "0")

                cents = rubles_to_cents(balance_rub)

                ledger.set_initial_balance(account_id, cents)

                self._send_json({"status": "success", "account_id": account_id, "balance_cents": cents})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/import/preview":

            user = self._require_auth()

            if not user:

                return

            try:

                from family_finances_os.importer import StatementImporter

                ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

                importer = StatementImporter(ledger=ledger)

                csv_text = body.get("csv_text", "")

                delimiter = body.get("delimiter")

                items = importer.parse_csv(csv_text, delimiter=delimiter)

                self._send_json({"status": "success", "count": len(items), "items": items})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/import/confirm":

            user = self._require_auth()

            if not user:

                return

            try:

                from family_finances_os.importer import StatementImporter

                ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

                importer = StatementImporter(ledger=ledger)

                account_id = body.get("account_id")

                items = body.get("items", [])

                res = importer.commit_imported_items(items=items, account_id=account_id, owner_member_id=user.get("member_id"))

                self._send_json(res)

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        # --- Stage 9 Financial Goals Endpoints ---

        elif path == "/api/goals/create":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

                name = body.get("name", "").strip()

                target_rub = body.get("target_amount_rub")

                target_date = body.get("target_date") or None

                account_id = (body.get("account_id") or "").strip() or None

                category_id = (body.get("category_id") or "").strip() or None

                icon = body.get("icon", "🎯")

                note = body.get("note") or None

                init_rub = body.get("initial_saved_rub", "0")

                target_cents = rubles_to_cents(target_rub)

                init_cents = rubles_to_cents(init_rub) if init_rub else 0

                goal = ledger.create_goal(

                    name=name,

                    target_amount_cents=target_cents,

                    target_date=target_date,

                    account_id=account_id,

                    category_id=category_id,

                    icon=icon,

                    note=note,

                    initial_saved_cents=init_cents

                )

                self._send_json({"status": "success", "goal": {

                    "id": goal.id,

                    "name": goal.name,

                    "target_amount_rub": cents_to_rubles(goal.target_amount_cents),

                    "current_amount_rub": cents_to_rubles(goal.current_amount_cents),

                    "icon": goal.icon

                }})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/goals/update":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

                goal_id = body.get("goal_id")

                name = body.get("name")

                target_rub = body.get("target_amount_rub")

                target_cents = rubles_to_cents(target_rub) if target_rub is not None else None

                target_date = body.get("target_date")

                account_id = body.get("account_id")

                category_id = body.get("category_id")

                icon = body.get("icon")

                note = body.get("note")

                ok = ledger.update_goal(goal_id, name=name, target_amount_cents=target_cents, target_date=target_date, account_id=account_id, category_id=category_id, icon=icon, note=note)

                self._send_json({"status": "success" if ok else "error"})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/goals/archive":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

                goal_id = body.get("goal_id")

                ok = ledger.archive_goal(goal_id)

                self._send_json({"status": "success" if ok else "error"})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/goals/contribute":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

                goal_id = body.get("goal_id")

                amount_rub = body.get("amount_rub")

                source_account_id = body.get("source_account_id") or None

                note = body.get("note") or None

                idempotency_key = body.get("idempotency_key") or None

                amount_cents = rubles_to_cents(amount_rub)

                res = ledger.contribute_to_goal(

                    goal_id=goal_id,

                    amount_cents=amount_cents,

                    source_account_id=source_account_id,

                    note=note,

                    member_id=user.get("member_id"),

                    idempotency_key=idempotency_key

                )

                self._send_json(res)

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        # --- Stage 9 Debt Repayment Endpoints ---

        elif path == "/api/debts/create":
            user = self._require_auth()
            if not user:
                return
            try:
                ledger = self._get_ledger()
                name = body.get("name", "").strip()
                subtype = body.get("subtype", "CONSUMER_LOAN")
                ownership_scope = body.get("ownership_scope", "COMMON")
                credit_limit_rub = safe_float(body.get("credit_limit_rub"), 0.0)
                initial_debt_rub = safe_float(body.get("initial_debt_rub"), 0.0)
                monthly_payment_rub = safe_float(body.get("monthly_payment_rub"), 0.0)
                due_day = body.get("due_day")
                if due_day is not None and str(due_day).strip():
                    due_day = int(due_day)
                else:
                    due_day = None
                receive_money = bool(body.get("receive_money", False))
                destination_account_id = (body.get("destination_account_id") or "").strip() or None
                description = body.get("description", "").strip() or None

                interest_rate_percent = safe_float(body.get("interest_rate_percent"), 24.8)
                grace_period_days = int(safe_float(body.get("grace_period_days"), 120))
                grace_due_date = body.get("grace_due_date")
                min_payment_percent = safe_float(body.get("min_payment_percent"), 3.0)
                late_penalty_rate_percent = safe_float(body.get("late_penalty_rate_percent"), 36.0)

                res = ledger.create_debt(
                    name=name,
                    subtype=subtype,
                    ownership_scope=ownership_scope,
                    credit_limit_cents=rubles_to_cents(credit_limit_rub),
                    initial_debt_cents=rubles_to_cents(initial_debt_rub),
                    monthly_payment_cents=rubles_to_cents(monthly_payment_rub),
                    due_day=due_day,
                    receive_money=receive_money,
                    destination_account_id=destination_account_id,
                    description=description,
                    owner_member_id=user.get("member_id"),
                    interest_rate_percent=interest_rate_percent,
                    grace_period_days=grace_period_days,
                    grace_due_date=grace_due_date,
                    min_payment_percent=min_payment_percent,
                    late_penalty_rate_percent=late_penalty_rate_percent
                )
                self._send_json({
                    "status": "success",
                    "account_id": res["account_id"],
                    "account": {"id": res["account_id"], "name": res["name"], "code": res["code"]},
                    "debt": res
                })
            except Exception as e:
                self._send_json({"status": "error", "message": str(e)}, 400)
            return

        elif path == "/api/debts/update-card-settings":
            user = self._require_auth()
            if not user:
                return
            try:
                ledger = self._get_ledger()
                account_id = body.get("account_id")
                if not account_id:
                    self._send_json({"status": "error", "message": "Не указан ID задолженности"}, 400)
                    return
                interest_rate = safe_float(body.get("interest_rate_percent"), 24.8)
                grace_days = int(safe_float(body.get("grace_period_days"), 120))
                grace_due = body.get("grace_due_date")
                min_pct = safe_float(body.get("min_payment_percent"), 3.0)
                penalty_rate = safe_float(body.get("late_penalty_rate_percent"), 36.0)
                limit_cents = rubles_to_cents(safe_float(body["credit_limit_rub"])) if ("credit_limit_rub" in body and body["credit_limit_rub"] is not None) else None

                res = ledger.update_credit_card_settings(
                    account_id=account_id,
                    interest_rate_percent=interest_rate,
                    grace_period_days=grace_days,
                    grace_due_date=grace_due,
                    min_payment_percent=min_pct,
                    late_penalty_rate_percent=penalty_rate,
                    credit_limit_cents=limit_cents
                )
                self._send_json(res)
            except Exception as e:
                self._send_json({"status": "error", "message": str(e)}, 400)
            return

        elif path == "/api/debts/archive":
            user = self._require_auth()
            if not user:
                return
            try:
                account_id = body.get("account_id")
                if not account_id:
                    raise ValueError("Не указан ID задолженности.")
                ledger = self._get_ledger()
                account = ledger.get_account_by_id(account_id)
                if not account or account.account_type != "LIABILITY":
                    raise ValueError("Задолженность не найдена.")
                with ledger.atomic():
                    success = ledger.archive_account(account_id)
                    for obligation in ledger.get_obligations():
                        if obligation["payment_account_id"] == account_id:
                            ledger.archive_obligation(obligation["id"])
                self._send_json({"status": "success", "archived": success})
            except Exception as exc:
                self._send_json({"status": "error", "message": str(exc)}, 400)
            return

        elif path == "/api/debts/pay":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

                source_acc_id = body.get("source_account_id")

                liability_acc_id = body.get("liability_account_id")

                amount_rub = body.get("amount_rub")

                desc = body.get("description")

                category_id = body.get("category_id")

                obligation_id = body.get("obligation_id")

                idempotency_key = body.get("idempotency_key")

                amount_percent = body.get("amount_percent")

                from family_finances_os.debt_math import percentage, rounded
                from decimal import Decimal
                if (amount_rub is None or str(amount_rub).strip() == "") and amount_percent is not None:
                    pct = percentage(amount_percent, "Процент погашения", 100)
                    if pct <= 0:
                        raise ValueError("Процент погашения должен быть больше нуля.")
                    current_debt = ledger.get_account_balance_cents(liability_acc_id)
                    amount_cents = rounded(Decimal(max(0, current_debt)) * pct / 100)
                    if idempotency_key:
                        conn = ledger._get_conn()
                        try:
                            old = conn.execute("SELECT p.amount_cents FROM transactions t JOIN postings p ON p.transaction_id=t.id WHERE t.idempotency_key=? AND p.account_id=? AND p.posting_type='DEBIT';", (idempotency_key, liability_acc_id)).fetchone()
                            if old:
                                amount_cents = old["amount_cents"]
                        finally:
                            ledger._close_if_local(conn)
                    if not desc or desc.strip() == "Погашение задолженности":
                        desc = f"Погашение ({pct:.1f}% / {cents_to_rubles(amount_cents)} ₽)"
                    else:
                        desc = f"{desc} ({pct:.1f}% / {cents_to_rubles(amount_cents)} ₽)"
                else:
                    amount_cents = rubles_to_cents(amount_rub)
                    if amount_percent is not None:
                        pct = percentage(amount_percent, "Процент погашения", 100)
                        if desc and "%" not in desc:
                            desc = f"{desc} ({pct:.1f}%)"

                tx_id = ledger.record_debt_repayment(

                    source_account_id=source_acc_id,

                    liability_account_id=liability_acc_id,

                    amount_cents=amount_cents,

                    description=desc,

                    obligation_id=obligation_id,

                    member_id=user.get("member_id"),

                    idempotency_key=idempotency_key,

                    category_id=category_id

                )

                self._send_json({"status": "success", "transaction_id": tx_id})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        # --- Stage 9 Smart Quick Input Endpoints ---

        elif path == "/api/quick-tx/parse":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

                text = body.get("text", "")

                parsed = ledger.parse_quick_input(text)

                self._send_json({"status": "success", "parsed": parsed})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/quick-tx/create":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

                text = body.get("text", "")

                account_id = body.get("account_id") or None

                category_id = body.get("category_id") or None

                idempotency_key = body.get("idempotency_key") or None

                parsed = ledger.parse_quick_input(text)

                tx_id = ledger.record_quick_input(

                    text=text,

                    account_id=account_id,

                    category_id=category_id,

                    member_id=user.get("member_id"),

                    idempotency_key=idempotency_key

                )

                self._send_json({"status": "success", "transaction_id": tx_id, "parsed": parsed})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        # --- Stage 10 Savings Envelopes & Piggy Banks Endpoints ---

        elif path == "/api/transactions/update":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = self._get_ledger()

                tx_id = body.get("transaction_id")

                if not tx_id:

                    self._send_json({"status": "error", "message": "ID операции обязателен"}, 400)

                    return

                amount_rub = body.get("amount_rub")

                amount_cents = rubles_to_cents(amount_rub) if amount_rub is not None else None

                ok = ledger.update_transaction(

                    transaction_id=tx_id,

                    tx_date=body.get("tx_date"),

                    description=body.get("description"),

                    amount_cents=amount_cents,

                    category_id=body.get("category_id"),

                    account_id=body.get("account_id"),

                    tx_type=body.get("tx_type")

                )

                if ok:

                    self._send_json({"status": "success", "message": "Операция успешно обновлена"})

                else:

                    self._send_json({"status": "error", "message": "Операция не найдена или аннулирована"}, 404)

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path in ("/api/transactions/delete", "/api/transactions/void"):

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = self._get_ledger()

                tx_id = body.get("transaction_id")

                if not tx_id:

                    self._send_json({"status": "error", "message": "ID операции обязателен"}, 400)

                    return

                reason = body.get("reason", "Удаление через интерфейс")

                ok = ledger.void_transaction(tx_id, reason=reason)

                if ok:

                    self._send_json({"status": "success", "message": "Операция успешно аннулирована"})

                else:

                    self._send_json({"status": "error", "message": "Операция не найдена"}, 404)

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/envelopes/create":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

                name = body.get("name", "").strip()

                target_rub = body.get("target_amount_rub", "0")

                init_rub = body.get("initial_amount_rub", "0")

                icon = body.get("icon", "✉️")

                color = body.get("color", "#3b82f6")

                linked_acc_id = body.get("linked_account_id") or None

                cat_id = body.get("category_id") or None

                note = body.get("note") or None

                target_cents = rubles_to_cents(target_rub) if target_rub else 0

                init_cents = rubles_to_cents(init_rub) if init_rub else 0

                env = ledger.create_envelope(

                    name=name,

                    target_amount_cents=target_cents,

                    icon=icon,

                    color=color,

                    linked_account_id=linked_acc_id,

                    category_id=cat_id,

                    note=note,

                    initial_amount_cents=init_cents

                )

                self._send_json({"status": "success", "envelope": {

                    "id": env.id,

                    "name": env.name,

                    "target_amount_rub": cents_to_rubles(env.target_amount_cents),

                    "current_amount_rub": cents_to_rubles(env.current_amount_cents),

                    "icon": env.icon,

                    "color": env.color

                }})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/envelopes/update":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

                env_id = body.get("envelope_id")

                name = body.get("name")

                target_rub = body.get("target_amount_rub")

                target_cents = rubles_to_cents(target_rub) if target_rub is not None and str(target_rub).strip() != "" else None

                curr_rub = body.get("current_amount_rub")

                curr_cents = rubles_to_cents(curr_rub) if curr_rub is not None and str(curr_rub).strip() != "" else None

                icon = body.get("icon")

                color = body.get("color")

                linked_acc_id = body.get("linked_account_id")

                cat_id = body.get("category_id")

                note = body.get("note")

                ok = ledger.update_envelope(

                    envelope_id=env_id,

                    name=name,

                    target_amount_cents=target_cents,

                    icon=icon,

                    color=color,

                    linked_account_id=linked_acc_id,

                    category_id=cat_id,

                    note=note,

                    current_amount_cents=curr_cents

                )

                self._send_json({"status": "success" if ok else "error"})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/envelopes/archive":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

                env_id = body.get("envelope_id")

                ok = ledger.archive_envelope(env_id)

                self._send_json({"status": "success" if ok else "error"})

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/envelopes/deposit":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

                env_id = body.get("envelope_id")

                amount_rub = body.get("amount_rub")

                source_acc_id = body.get("source_account_id") or None

                note = body.get("note") or None

                amount_cents = rubles_to_cents(amount_rub)

                res = ledger.deposit_to_envelope(

                    envelope_id=env_id,

                    amount_cents=amount_cents,

                    source_account_id=source_acc_id,

                    note=note,

                    member_id=user.get("member_id"),
                    idempotency_key=body.get("idempotency_key")

                )

                self._send_json(res)

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/envelopes/withdraw":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

                env_id = body.get("envelope_id")

                amount_rub = body.get("amount_rub")

                dest_acc_id = body.get("destination_account_id") or None

                note = body.get("note") or None

                amount_cents = rubles_to_cents(amount_rub)

                res = ledger.withdraw_from_envelope(

                    envelope_id=env_id,

                    amount_cents=amount_cents,

                    destination_account_id=dest_acc_id,

                    note=note,

                    member_id=user.get("member_id"),
                    idempotency_key=body.get("idempotency_key")

                )

                self._send_json(res)

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        elif path == "/api/envelopes/transfer":

            user = self._require_auth()

            if not user:

                return

            try:

                ledger = LedgerEngine(conn_or_path=self.storage.get_connection() if self.storage.is_unlocked() else None)

                from_env_id = body.get("from_envelope_id")

                to_env_id = body.get("to_envelope_id")

                amount_rub = body.get("amount_rub")

                note = body.get("note") or None

                amount_cents = rubles_to_cents(amount_rub)

                res = ledger.transfer_between_envelopes(

                    from_envelope_id=from_env_id,

                    to_envelope_id=to_env_id,

                    amount_cents=amount_cents,

                    note=note,

                    member_id=user.get("member_id"),
                    idempotency_key=body.get("idempotency_key")

                )

                self._send_json(res)

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        self._send_json({"error": "Not Found"}, 404)

    def _render_app_html(self) -> str:

        return """<!DOCTYPE html>

<html lang="ru" translate="no" class="notranslate">

<head>

  <meta charset="UTF-8">

  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
  <meta name="google" content="notranslate">

  <meta name="theme-color" content="#0b1120">

  <meta name="mobile-web-app-capable" content="yes">

  <meta name="apple-mobile-web-app-capable" content="yes">

  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">

  <meta name="apple-mobile-web-app-title" content="Finances OS">

  <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
  <meta http-equiv="Pragma" content="no-cache">
  <meta http-equiv="Expires" content="0">
  <link rel="manifest" href="/manifest.json">

  <link rel="icon" type="image/svg+xml" href="/icon.svg">

  <link rel="apple-touch-icon" href="/icon.svg">

  <title>Family Finances OS</title>


  <style>
    /* ==========================================================================
       Option 3: Apple HIG Clean & Human Interface Design System Tokens
       DTCG / Apple Human Interface Guidelines Compliant (Zero AI-Slop)
       ========================================================================== */
    :root, [data-theme="dark"] {
      /* Radius Tokens (Apple Squircle Geometry) */
      --radius-sm: 10px;
      --radius-md: 16px;
      --radius-lg: 22px;
      --radius-xl: 26px;
      --radius-pill: 9999px;
      --card-radius: var(--radius-lg);

      /* Palette: Apple Dark Mode (OLED Pure Depth) */
      --bg: #000000;
      --bg-secondary: #1c1c1e;
      --bg-gradient: linear-gradient(180deg, #000000 0%, #121214 100%);
      --card-bg: #1c1c1e;
      --card-hover: #2c2c2e;
      --border: rgba(255, 255, 255, 0.12);
      --border-subtle: rgba(255, 255, 255, 0.08);
      --border-hover: rgba(255, 255, 255, 0.22);
      --border-focus: #0071e3;
      
      /* Typography Colors */
      --text: #f5f5f7;
      --text-muted: #8e8e93;
      --text-soft: #aeaeb2;

      /* Apple System Colors (Dark) */
      --primary: #0071e3;
      --primary-hover: #0077ed;
      --primary-accent: #0071e3;
      --primary-gradient: linear-gradient(180deg, #0077ed 0%, #0071e3 100%);
      --accent-blue: #0071e3;
      --accent-purple: #af52de;
      --success: #30d158;
      --danger: #ff453a;
      --warning: #ff9f0a;
      --purple: #af52de;

      /* Surface, Modals & Shadows */
      --input-bg: #1c1c1e;
      --modal-bg: #1c1c1e;
      --box-bg: rgba(255, 255, 255, 0.04);
      --shadow: 0 4px 20px rgba(0, 0, 0, 0.55);
      --shadow-lg: 0 16px 44px rgba(0, 0, 0, 0.75);
    }

    [data-theme="light"] {
      /* Radius Tokens (Apple Squircle Geometry) */
      --radius-sm: 10px;
      --radius-md: 16px;
      --radius-lg: 22px;
      --radius-xl: 26px;
      --radius-pill: 9999px;
      --card-radius: var(--radius-lg);

      /* Palette: Apple Light Mode (Clean Studio Aesthetic) */
      --bg: #f5f5f7;
      --bg-secondary: #ffffff;
      --bg-gradient: linear-gradient(180deg, #f5f5f7 0%, #ebebf0 100%);
      --card-bg: #ffffff;
      --card-hover: #f2f2f7;
      --border: #d1d1d6;
      --border-subtle: #e5e5ea;
      --border-hover: #babbbe;
      --border-focus: #0071e3;

      /* Typography Colors */
      --text: #1d1d1f;
      --text-muted: #86868b;
      --text-soft: #6e6e73;

      /* Apple System Colors (Light) */
      --primary: #0071e3;
      --primary-hover: #0077ed;
      --primary-accent: #0071e3;
      --primary-gradient: linear-gradient(180deg, #0077ed 0%, #0071e3 100%);
      --accent-blue: #0071e3;
      --accent-purple: #af52de;
      --success: #34c759;
      --danger: #ff3b30;
      --warning: #ff9500;
      --purple: #af52de;

      /* Surface, Modals & Shadows */
      --input-bg: #ffffff;
      --modal-bg: #ffffff;
      --box-bg: #f2f2f7;
      --shadow: 0 2px 12px rgba(0, 0, 0, 0.04), 0 1px 3px rgba(0, 0, 0, 0.02);
      --shadow-lg: 0 12px 32px rgba(0, 0, 0, 0.08);
    }

    /* Base Reset & Crisp Apple Typography */
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Inter", -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }

    body {
      background-color: var(--bg);
      color: var(--text);
      min-height: 100vh;
      padding: calc(16px + env(safe-area-inset-top)) 20px calc(92px + env(safe-area-inset-bottom)) 20px;
      transition: background-color 0.25s cubic-bezier(0.16, 1, 0.3, 1), color 0.25s cubic-bezier(0.16, 1, 0.3, 1);
    }

    .container {
      max-width: 1120px;
      margin: 0 auto;
    }

    /* FamilyOS Apple HIG Header & Navigation Bar (Clean Geometric Design) */
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border);
      padding: 14px 0 16px 0;
      margin-bottom: 24px;
      gap: 12px;
      position: sticky;
      top: 0;
      z-index: 100;
      background: var(--bg);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      transition: background-color 0.2s, border-color 0.2s;
    }

    .brand-block {
      display: flex;
      align-items: center;
      gap: 12px;
      min-width: 0;
      flex-shrink: 0;
    }

    .brand-logo {
      display: flex;
      align-items: center;
      gap: 10px;
      text-decoration: none;
      cursor: pointer;
      user-select: none;
      transition: opacity 0.15s ease;
    }

    .brand-logo:hover {
      opacity: 0.92;
    }

    .brand-icon {
      width: 36px;
      height: 36px;
      border-radius: 10px;
      background: linear-gradient(145deg, #0071e3 0%, #0056b3 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      color: #ffffff;
      box-shadow: 0 2px 8px rgba(0, 113, 227, 0.28), inset 0 1px 1px rgba(255, 255, 255, 0.2);
      flex-shrink: 0;
      filter: none !important;
      transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.2s ease;
    }

    .brand-logo:hover .brand-icon {
      transform: scale(1.04);
      box-shadow: 0 4px 12px rgba(0, 113, 227, 0.36), inset 0 1px 1px rgba(255, 255, 255, 0.3);
    }

    .brand-logo-svg {
      width: 22px;
      height: 22px;
      display: block;
      color: #ffffff;
    }

    .brand-text {
      display: flex;
      flex-direction: column;
      justify-content: center;
    }

    .brand-title {
      font-size: 18px;
      font-weight: 700;
      color: var(--text);
      letter-spacing: -0.025em;
      line-height: 1.15;
    }

    .brand-tag {
      display: block;
      font-size: 11px;
      font-weight: 500;
      color: var(--text-muted);
      letter-spacing: 0.01em;
      line-height: 1.2;
    }

    .family-scope-chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(0, 113, 227, 0.08);
      border: 1px solid rgba(0, 113, 227, 0.22);
      color: #0071e3;
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 11.5px;
      font-weight: 600;
      letter-spacing: -0.01em;
      white-space: nowrap;
    }

    [data-theme="dark"] .family-scope-chip {
      background: rgba(0, 113, 227, 0.16);
      border-color: rgba(0, 113, 227, 0.35);
      color: #38bdf8;
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: nowrap;
    }

    /* Apple HIG Action Pills & Circular Buttons */
    .btn-icon-circle {
      width: 38px !important;
      height: 38px !important;
      border-radius: 50% !important;
      display: inline-flex !important;
      align-items: center !important;
      justify-content: center !important;
      background: var(--card-bg) !important;
      border: 1px solid var(--border) !important;
      color: var(--text) !important;
      cursor: pointer !important;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
      padding: 0 !important;
      flex-shrink: 0 !important;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05) !important;
    }

    .btn-icon-circle:hover {
      background: var(--card-hover) !important;
      border-color: var(--border-hover) !important;
      transform: scale(1.04);
    }

    .btn-icon-circle:active {
      transform: scale(0.96);
    }

    .privacy-mask-pill {
      display: inline-flex !important;
      align-items: center !important;
      gap: 6px !important;
      padding: 7px 12px !important;
      border-radius: 9999px !important;
      background: var(--card-bg) !important;
      border: 1px solid var(--border) !important;
      color: var(--text) !important;
      font-size: 13px !important;
      font-weight: 500 !important;
      cursor: pointer !important;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05) !important;
    }

    .privacy-mask-pill:hover {
      background: var(--card-hover) !important;
      border-color: var(--border-hover) !important;
      transform: scale(1.02);
    }

    .status-indicator-btn {
      display: inline-flex !important;
      align-items: center !important;
      gap: 6px !important;
      padding: 6px 11px !important;
      border-radius: 9999px !important;
      background: rgba(48, 209, 88, 0.1) !important;
      border: 1px solid rgba(48, 209, 88, 0.25) !important;
      color: #30d158 !important;
      font-size: 12px !important;
      font-weight: 600 !important;
      cursor: pointer !important;
      transition: all 0.2s ease !important;
    }

    [data-theme="light"] .status-indicator-btn {
      background: rgba(52, 199, 89, 0.12) !important;
      border-color: rgba(52, 199, 89, 0.3) !important;
      color: #248a3d !important;
    }

    .status-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: #30d158;
      box-shadow: 0 0 8px rgba(48, 209, 88, 0.6);
      display: inline-block;
    }

    [data-theme="light"] .status-dot {
      background: #34c759;
    }

    /* Apple Cards (Continuous 22px Squircle Radius) */
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border-subtle);
      border-radius: var(--card-radius);
      padding: 22px;
      margin-bottom: 20px;
      box-shadow: var(--shadow);
      transition: background 0.2s cubic-bezier(0.16, 1, 0.3, 1),
                  border-color 0.2s cubic-bezier(0.16, 1, 0.3, 1),
                  box-shadow 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }

    .card:hover {
      border-color: var(--border);
    }

    /* Apple Monospace Financial Numbers */
    .stat-val, .hero-balance-val, .table-amount {
      font-family: "SF Mono", "SF Pro Display", "JetBrains Mono", Menlo, Monaco, Consolas, monospace;
      font-variant-numeric: tabular-nums lining-nums;
      font-feature-settings: "tnum" 1;
    }

    /* Apple HIG iOS Segmented Control Navigation Tabs with Drag & Chevrons */
    .nav-tabs-wrapper {
      position: relative;
      display: flex;
      align-items: center;
      gap: 8px;
      width: 100%;
      margin-bottom: 24px;
    }
    .nav-tab-scroll-btn {
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      width: 36px;
      height: 36px;
      border-radius: 12px;
      background: rgba(118, 118, 128, 0.24);
      border: 1px solid rgba(255, 255, 255, 0.08);
      color: rgba(255, 255, 255, 0.85);
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
      user-select: none;
      -webkit-user-select: none;
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
    }
    .nav-tab-scroll-btn:hover {
      background: rgba(255, 255, 255, 0.16);
      color: #ffffff;
      transform: scale(1.06);
      border-color: rgba(255, 255, 255, 0.18);
    }
    .nav-tab-scroll-btn:active {
      transform: scale(0.94);
    }
    .nav-tab-scroll-btn.disabled,
    .nav-tab-scroll-btn:disabled {
      opacity: 0.18;
      cursor: default;
      pointer-events: none;
      transform: none !important;
    }
    .nav-tabs {
      flex: 1;
      min-width: 0;
      display: flex;
      align-items: center;
      flex-wrap: nowrap;
      gap: 3px;
      margin-bottom: 0;
      background: rgba(118, 118, 128, 0.24);
      border: 1px solid rgba(255, 255, 255, 0.06);
      border-radius: 12px;
      padding: 3px;
      overflow-x: auto;
      overflow-y: hidden;
      -webkit-overflow-scrolling: touch;
      touch-action: pan-x;
      scrollbar-width: none;
      -ms-overflow-style: none;
      cursor: grab;
      user-select: none;
      -webkit-user-select: none;
      scroll-behavior: smooth;
    }
    .nav-tabs.is-dragging {
      cursor: grabbing !important;
      scroll-behavior: auto !important;
    }
    .nav-tabs.is-dragging .tab-btn {
      cursor: grabbing !important;
      pointer-events: none !important;
    }
    .nav-tabs::-webkit-scrollbar {
      display: none !important;
      width: 0 !important;
      height: 0 !important;
    }

    .tab-btn {
      flex-shrink: 0;
      white-space: nowrap;
      background: transparent;
      color: rgba(235, 235, 245, 0.65);
      border: none;
      outline: none;
      padding: 7px 16px;
      border-radius: 9px;
      cursor: pointer;
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Display", "Segoe UI", Roboto, sans-serif;
      font-weight: 500;
      font-size: 13px;
      line-height: 1.25;
      letter-spacing: -0.01em;
      user-select: none;
      -webkit-user-select: none;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }

    .tab-btn:hover {
      color: #ffffff;
      background: rgba(255, 255, 255, 0.06);
    }

    .tab-btn:active {
      transform: scale(0.97);
    }

    /* Active Tab in Dark Mode: Deep elevated dark pill */
    :root .tab-btn.active,
    [data-theme="dark"] .tab-btn.active {
      color: #ffffff !important;
      background: #3a3a3c !important;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.4), 0 0.5px 0.5px rgba(255, 255, 255, 0.12) inset !important;
      font-weight: 600 !important;
      border: none !important;
    }

    /* Active Tab in Light Mode: White with subtle crisp shadow */
    [data-theme="light"] .tab-btn.active {
      color: #000000 !important;
      background: #ffffff !important;
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.12), 0 0.5px 1.5px rgba(0, 0, 0, 0.06) !important;
      font-weight: 600 !important;
      border: none !important;
    }

    /* Apple HIG Month Selector & Period Navigator Bar */
    .month-navigator-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
      padding: 12px 20px;
      margin-bottom: 20px;
      background: rgba(30, 41, 59, 0.75);
      backdrop-filter: blur(20px) saturate(180%);
      -webkit-backdrop-filter: blur(20px) saturate(180%);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25), 0 0.5px 1px rgba(255, 255, 255, 0.08) inset;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }

    .month-navigator-label {
      font-weight: 700;
      font-size: 14px;
      color: #ffffff;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      letter-spacing: -0.01em;
    }

    [data-theme="light"] .month-navigator-label {
      color: #000000 !important;
    }

    /* Apple HIG Round Squircle Chevron Buttons */
    .month-chevron-btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 34px;
      height: 34px;
      padding: 0;
      border-radius: 10px;
      font-size: 13px;
      font-weight: 600;
      border: 1px solid rgba(255, 255, 255, 0.12);
      background: rgba(255, 255, 255, 0.08);
      color: #ffffff;
      cursor: pointer;
      transition: all 0.18s cubic-bezier(0.16, 1, 0.3, 1);
      user-select: none;
      -webkit-user-select: none;
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.2);
    }

    .month-chevron-btn:hover {
      background: rgba(255, 255, 255, 0.16);
      border-color: rgba(255, 255, 255, 0.25);
      transform: translateY(-1px) scale(1.04);
      color: #ffffff;
    }

    .month-chevron-btn:active {
      transform: scale(0.94);
      background: rgba(255, 255, 255, 0.1);
    }

    [data-theme="light"] .month-chevron-btn {
      background: #f2f2f7;
      border: 1px solid rgba(0, 0, 0, 0.08);
      color: #1c1c1e;
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
    }

    [data-theme="light"] .month-chevron-btn:hover {
      background: #e5e5ea;
      border-color: rgba(0, 0, 0, 0.16);
      color: #000000;
    }

    [data-theme="light"] .month-chevron-btn:active {
      background: #d1d1d6;
    }

    /* Apple HIG Month Selector Dropdown */
    .month-select-input {
      padding: 6px 14px;
      height: 34px;
      font-size: 13px;
      font-weight: 600;
      background: rgba(255, 255, 255, 0.08);
      color: #ffffff;
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 10px;
      cursor: pointer;
      min-width: 170px;
      outline: none;
      transition: all 0.18s ease;
      font-family: inherit;
    }

    .month-select-input:hover {
      border-color: rgba(255, 255, 255, 0.25);
      background: rgba(255, 255, 255, 0.12);
    }

    [data-theme="light"] .month-select-input {
      background: #ffffff;
      color: #1c1c1e;
      border: 1px solid rgba(0, 0, 0, 0.12);
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
    }

    [data-theme="light"] .month-select-input:hover {
      border-color: rgba(0, 0, 0, 0.22);
    }

    /* Revolut Cards & Grids */
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: var(--card-radius);
      padding: 22px;
      margin-bottom: 20px;
      box-shadow: var(--shadow);
      transition: background 0.2s, border-color 0.2s, box-shadow 0.2s, transform 0.15s;
    }

    .card:hover {
      border-color: var(--border-hover);
    }

    [data-theme="light"] .card:hover {
      border-color: #cbd5e1;
    }

    .grid-3 {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 16px;
      margin-bottom: 20px;
    }

    .stat-label {
      color: var(--text-muted);
      font-size: 11px;
      margin-bottom: 8px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      font-weight: 600;
    }

    /* Monospace amounts tracking (anti-AI-slop fintech) */
    .stat-val {
      font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
      font-size: 26px;
      font-weight: 700;
      letter-spacing: -0.015em;
      font-variant-numeric: tabular-nums lining-nums;
      font-feature-settings: "tnum" 1;
      color: var(--text);
      line-height: 1.15;
    }

    .stat-val.primary { color: #3b82f6; }
    .stat-val.success { color: #10b981; }
    .stat-val.warning { color: #f59e0b; }
    .stat-val.danger { color: #ef4444; }
    .stat-val.purple { color: #8b5cf6; }

    .title {
      font-size: 20px;
      font-weight: 700;
      color: var(--text);
      letter-spacing: -0.02em;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .badge {
      background: rgba(37, 99, 235, 0.1);
      color: #3b82f6;
      padding: 4px 12px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 600;
      border: 1px solid rgba(37, 99, 235, 0.22);
    }

    [data-theme="dark"] .badge {
      color: #3b82f6;
    }

    /* Revolut Action Buttons */
    .btn {
      background: var(--primary);
      color: #ffffff;
      border: 1px solid transparent;
      padding: 10px 18px;
      border-radius: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
      font-size: 14px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      box-shadow: none;
    }

    .btn:hover {
      background: var(--primary-hover);
      transform: translateY(-1px);
    }

    .btn:active {
      transform: translateY(0);
    }

    .btn:disabled {
      background: #334155;
      color: #94a3b8;
      cursor: not-allowed;
      opacity: 0.6;
      transform: none;
      box-shadow: none;
    }

    .btn-secondary {
      background: var(--card-hover);
      color: var(--text);
      border: 1px solid var(--border);
      box-shadow: none;
    }

    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.08);
      border-color: var(--border-hover);
      box-shadow: none;
    }

    [data-theme="light"] .btn-secondary {
      background: #f1f3f7 !important;
      color: #0f172a !important;
      border: 1px solid #e2e8f0 !important;
    }

    [data-theme="light"] .btn-secondary:hover {
      background: #e2e8f0 !important;
    }

    .btn-success { background: #10b981; }
    .btn-success:hover { background: #059669; }
    .btn-danger { background: #ef4444; }
    .btn-danger:hover { background: #dc2626; }

    /* Form Controls */
    .form-group {
      margin-bottom: 16px;
    }

    label {
      display: block;
      margin-bottom: 6px;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-muted);
    }

    input, select, textarea {
      width: 100%;
      padding: 11px 14px;
      background: var(--input-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      color: var(--text);
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
    }

    input:focus, select:focus, textarea:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.18);
    }

    [data-theme="light"] input,
    [data-theme="light"] select,
    [data-theme="light"] textarea {
      background: #f8fafc !important;
      color: #0f172a !important;
      border: 1px solid #e2e8f0 !important;
    }

    [data-theme="light"] input:focus,
    [data-theme="light"] select:focus,
    [data-theme="light"] textarea:focus {
      border-color: var(--primary) !important;
      background: #ffffff !important;
      box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15) !important;
    }

    [data-theme="light"] input::placeholder,
    [data-theme="light"] textarea::placeholder {
      color: #94a3b8 !important;
    }

    /* Revolut Table System */
    table {
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      margin-top: 10px;
    }

    th, td {
      text-align: left;
      padding: 12px 14px;
      border-bottom: 1px solid var(--border);
      font-size: 14px;
      color: var(--text);
    }

    th {
      color: var(--text-muted);
      font-weight: 600;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    [data-theme="light"] th {
      color: #64748b !important;
    }

    [data-theme="light"] td {
      color: #0f172a !important;
    }

    tr:last-child td {
      border-bottom: none;
    }

    tbody tr:hover td {
      background: rgba(255, 255, 255, 0.02);
    }

    [data-theme="light"] tbody tr:hover td {
      background: rgba(0, 0, 0, 0.015);
    }

    .progress-bar-bg {
      background: rgba(148, 163, 184, 0.15);
      border-radius: 9999px;
      overflow: hidden;
      height: 8px;
    }

    .progress-bar-fill {
      border-radius: 9999px;
      transition: width 0.3s cubic-bezier(0.16, 1, 0.3, 1);
      height: 100%;
    }

    .hidden {
      display: none !important;
    }

    /* Category Dropdown System */
    .category-dropdown-trigger {
      background: var(--input-bg);
      border: 1px solid var(--border);
      color: var(--text);
      border-radius: 12px;
      padding: 11px 14px;
      cursor: pointer;
      display: flex;
      justify-content: space-between;
      align-items: center;
      transition: all 0.2s ease;
      user-select: none;
    }

    .category-dropdown-trigger:hover {
      border-color: var(--primary);
      background: var(--card-hover);
    }

    .category-dropdown-menu {
      position: absolute;
      top: calc(100% + 6px);
      left: 0;
      right: 0;
      background: #141720;
      border: 1px solid var(--border-hover);
      box-shadow: 0 16px 40px rgba(0, 0, 0, 0.7);
      border-radius: 16px;
      z-index: 1000;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      max-height: 420px;
      min-width: 300px;
      max-width: min(440px, calc(100vw - 24px));
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      overscroll-behavior: contain;
      touch-action: pan-y;
      -webkit-overflow-scrolling: touch;
    }

    .category-dropdown-search {
      padding: 12px 14px;
      background: rgba(255, 255, 255, 0.02);
      border-bottom: 1px solid var(--border);
      flex-shrink: 0;
    }

    .category-dropdown-search input {
      width: 100%;
      padding: 9px 12px;
      border-radius: 10px;
      background: #0f1118;
      border: 1px solid var(--border);
      color: var(--text);
    }

    .category-dropdown-list {
      flex: 1 1 auto;
      overflow-y: auto !important;
      max-height: 320px;
      padding: 6px 0;
      -webkit-overflow-scrolling: touch !important;
      overscroll-behavior: contain !important;
      touch-action: pan-y !important;
      scrollbar-width: thin;
      scrollbar-color: rgba(255, 255, 255, 0.35) rgba(255, 255, 255, 0.04);
    }

    .category-dropdown-list::-webkit-scrollbar {
      width: 6px;
      display: block;
    }

    .category-dropdown-list::-webkit-scrollbar-track {
      background: rgba(255, 255, 255, 0.04);
    }

    .category-dropdown-list::-webkit-scrollbar-thumb {
      background: rgba(255, 255, 255, 0.25);
      border-radius: 9999px;
    }

    .category-dropdown-list::-webkit-scrollbar-thumb:hover {
      background: var(--primary);
    }

    [data-theme="light"] .category-dropdown-menu {
      background: #ffffff;
      box-shadow: 0 16px 36px rgba(0, 0, 0, 0.12);
      border: 1px solid #e2e8f0;
    }

    [data-theme="light"] .category-dropdown-list {
      scrollbar-color: rgba(0, 0, 0, 0.25) rgba(0, 0, 0, 0.04);
    }

    [data-theme="light"] .category-dropdown-list::-webkit-scrollbar-track {
      background: rgba(0, 0, 0, 0.04);
    }

    [data-theme="light"] .category-dropdown-list::-webkit-scrollbar-thumb {
      background: rgba(0, 0, 0, 0.2);
    }

    .cat-filter-btn {
      padding: 4px 10px;
      font-size: 11px;
      font-weight: 600;
      border-radius: 9999px;
      cursor: pointer;
      border: 1px solid var(--border);
      background: var(--card-hover);
      color: var(--text-muted);
      transition: all 0.15s;
    }

    .cat-filter-btn.active {
      background: var(--primary) !important;
      color: #fff !important;
      border-color: var(--primary) !important;
    }

    .cat-group-header {
      padding: 8px 14px 4px 14px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--text-muted);
      background: rgba(255, 255, 255, 0.02);
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      position: sticky;
      top: 0;
      z-index: 2;
    }

    .cat-dropdown-item {
      padding: 10px 14px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 13px;
      font-weight: 500;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      transition: all 0.15s cubic-bezier(0.16, 1, 0.3, 1);
    }

    .cat-dropdown-item:hover {
      background: rgba(255, 255, 255, 0.05);
      color: #ffffff;
      padding-left: 18px;
    }

    .cat-dropdown-item.active {
      background: rgba(37, 99, 235, 0.15);
      color: #3b82f6;
      font-weight: 600;
    }

    /* Debt Type Buttons */
    .debt-type-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 8px;
      margin-bottom: 14px;
    }

    .debt-type-btn {
      padding: 10px;
      border: 1px solid var(--border);
      border-radius: 12px;
      background: var(--card-hover);
      color: var(--text-muted);
      font-weight: 600;
      font-size: 12px;
      cursor: pointer;
      transition: all 0.2s;
    }

    .debt-type-btn.active {
      background: var(--primary);
      color: #fff;
      border-color: var(--primary);
      box-shadow: none;
    }

    /* Settings Sheet Modal */
    .settings-section {
      margin-bottom: 20px;
    }

    .settings-section-title {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--text-muted);
      margin-bottom: 10px;
    }

    .settings-sheet {
      border-radius: 20px !important;
      box-shadow: var(--shadow-lg) !important;
      border: 1px solid var(--border) !important;
    }

    /* Alerts */
    .alert {
      padding: 12px 16px;
      border-radius: 12px;
      margin-bottom: 14px;
      font-size: 13px;
      font-weight: 500;
      line-height: 1.4;
    }

    .alert-success {
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.25);
      color: #10b981;
    }

    [data-theme="dark"] .alert-success {
      color: #34d399;
    }

    .alert-error {
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.25);
      color: #ef4444;
    }

    [data-theme="dark"] .alert-error {
      color: #f87171;
    }

    /* Floating iOS Bottom Navigation Capsule */
    .mobile-bottom-nav {
      display: none;
    }

    @media (max-width: 768px) {
      .mobile-bottom-nav {
        display: flex !important;
        position: fixed !important;
        bottom: calc(10px + env(safe-area-inset-bottom, 0px)) !important;
        left: 12px !important;
        right: 12px !important;
        max-width: 440px !important;
        margin: 0 auto !important;
        background: rgba(20, 23, 32, 0.9) !important;
        backdrop-filter: blur(20px) !important;
        -webkit-backdrop-filter: blur(20px) !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 9999px !important;
        z-index: 1000 !important;
        justify-content: space-around !important;
        align-items: center !important;
        padding: 6px 8px !important;
        padding-bottom: calc(6px + env(safe-area-inset-bottom, 0px)) !important;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5) !important;
      }

      [data-theme="light"] .mobile-bottom-nav {
        background: rgba(255, 255, 255, 0.92) !important;
        border: 1px solid rgba(0, 0, 0, 0.08) !important;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1) !important;
      }

      .mobile-nav-item {
        display: flex !important;
        flex-direction: column !important;
        align-items: center !important;
        background: transparent !important;
        border: none !important;
        color: var(--text-muted) !important;
        font-size: 11px !important;
        font-weight: 600 !important;
        padding: 6px 12px !important;
        border-radius: 9999px !important;
        cursor: pointer !important;
        transition: all 0.2s ease !important;
      }

      .mobile-nav-item.active {
        color: #3b82f6 !important;
        background: rgba(37, 99, 235, 0.12) !important;
      }

      .mobile-nav-item .icon {
        font-size: 18px !important;
        margin-bottom: 2px !important;
      }
    }

    /* Mobile Responsive Overrides */
    @media (max-width: 680px) {
      body {
        padding: calc(10px + env(safe-area-inset-top)) 12px calc(92px + env(safe-area-inset-bottom)) 12px !important;
      }
      .container {
        width: 100% !important;
        max-width: 100% !important;
      }
      .header {
        padding: 8px 0 12px 0 !important;
        margin-bottom: 16px !important;
      }
      .desktop-only-text {
        display: none !important;
      }
      .family-scope-chip {
        display: none !important;
      }
      .category-dropdown-menu {
        max-width: calc(100vw - 24px) !important;
        min-width: 0 !important;
        width: 100% !important;
      }
      .category-dropdown-list {
        max-height: 250px !important;
        -webkit-overflow-scrolling: touch !important;
        touch-action: pan-y !important;
        overscroll-behavior: contain !important;
      }
      #settingsModal {
        align-items: flex-end !important;
        overflow-y: auto !important;
        -webkit-overflow-scrolling: touch !important;
        overscroll-behavior: contain !important;
        padding: 0 !important;
        z-index: 100000 !important;
      }
      .settings-sheet {
        position: fixed !important;
        bottom: 0 !important;
        top: auto !important;
        left: 0 !important;
        right: 0 !important;
        max-width: 100% !important;
        width: 100% !important;
        border-radius: 28px 28px 0 0 !important;
        max-height: calc(88vh - env(safe-area-inset-bottom, 0px)) !important;
        margin: 0 !important;
        box-shadow: 0 -10px 40px rgba(0, 0, 0, 0.6) !important;
        animation: slideUpSheet 0.3s cubic-bezier(0.16, 1, 0.3, 1) !important;
        overflow-y: auto !important;
        -webkit-overflow-scrolling: touch !important;
        overscroll-behavior: contain !important;
        padding-bottom: calc(28px + env(safe-area-inset-bottom, 0px)) !important;
      }
      @keyframes slideUpSheet {
        from { transform: translateY(100%); }
        to { transform: translateY(0); }
      }
      .nav-tabs {
        display: flex !important;
        align-items: center !important;
        flex-wrap: nowrap !important;
        overflow-x: auto !important;
        overflow-y: hidden !important;
        -webkit-overflow-scrolling: touch !important;
        touch-action: pan-x !important;
        scrollbar-width: none !important;
        -ms-overflow-style: none !important;
        gap: 3px !important;
        padding: 3px !important;
        border-radius: 12px !important;
        margin-bottom: 16px !important;
      }
      .nav-tabs::-webkit-scrollbar {
        display: none !important;
        width: 0 !important;
        height: 0 !important;
      }
      .tab-btn {
        flex-shrink: 0 !important;
        white-space: nowrap !important;
        padding: 6px 13px !important;
        font-size: 12px !important;
        border-radius: 9px !important;
      }
      .card {
        padding: 16px !important;
        border-radius: 18px !important;
        margin-bottom: 14px !important;
      }
      .grid-3 {
        grid-template-columns: 1fr !important;
        gap: 12px !important;
      }
      .stat-val {
        font-size: 24px !important;
      }

      /* Mobile Modal Viewport & Touch Scroll Fix */
      #modalNewDebt, #modalEditTx, #modalPayDebt, #modalCardSettings, #modalEnvelope, #modalGoal, #modalObligation, #modalQrPair, #modalNewTx, #modalContributeGoal, #modalEnvelopeDeposit, #modalEnvelopeWithdraw, #modalEnvelopeTransfer, #vaultModal, [id^="modal"] {
        align-items: flex-start !important;
        justify-content: center !important;
        overflow-y: auto !important;
        -webkit-overflow-scrolling: touch !important;
        touch-action: pan-y !important;
        overscroll-behavior: contain !important;
        padding: calc(12px + env(safe-area-inset-top, 0px)) 10px calc(110px + env(safe-area-inset-bottom, 0px)) 10px !important;
        z-index: 100000 !important;
      }
      #modalNewDebt .card, #modalEditTx .card, #modalPayDebt .card, #modalCardSettings .card, #modalEnvelope .card, #modalGoal .card, #modalObligation .card, #modalQrPair .card, #modalNewTx .card, #modalContributeGoal .card, #modalEnvelopeDeposit .card, #modalEnvelopeWithdraw .card, #modalEnvelopeTransfer .card, #vaultModal .card, [id^="modal"] .card {
        max-height: none !important;
        width: 100% !important;
        max-width: 100% !important;
        margin-top: 10px !important;
        margin-bottom: 90px !important;
        overscroll-behavior: contain !important;
        -webkit-overflow-scrolling: touch !important;
      }
    }

    @media (max-width: 430px) {
      .hero-actions-grid {
        gap: 8px !important;
      }
      .hero-action-icon {
        width: 46px !important;
        height: 46px !important;
      }
      .hero-action-btn span {
        font-size: 11px !important;
      }
    }

    /* Revolut Hero Card & Actions (Clean Matte Surface, Anti-AI-Slop) */
    .appetite-hero-card, .revolut-hero-card {
      position: relative;
      border-radius: 22px;
      padding: 26px 24px 22px 24px;
      color: #ffffff;
      overflow: hidden;
      margin-bottom: 20px;
      box-shadow: 0 8px 30px rgba(0, 0, 0, 0.45);
      border: 1px solid var(--border);
      background: var(--card-bg);
    }

    [data-theme="light"] .appetite-hero-card,
    [data-theme="light"] .revolut-hero-card {
      background: linear-gradient(135deg, #1e3a8a 0%, #2563eb 100%);
      box-shadow: 0 8px 24px rgba(37, 99, 235, 0.2);
      border: 1px solid rgba(255, 255, 255, 0.2);
    }

    .appetite-hero-stripes {
      background-image: none !important;
    }

    /* Accounts table 7-row viewport with sticky header */
    .accounts-table-scroll-wrapper {
      max-height: 392px;
      overflow-y: auto;
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
      border-radius: 8px;
    }
    .accounts-table-scroll-wrapper thead {
      position: sticky;
      top: 0;
      z-index: 2;
      background: var(--card-bg);
    }
    .accounts-table-scroll-wrapper thead th {
      border-bottom: 1px solid var(--border);
      backdrop-filter: blur(8px);
    }
    .accounts-table-scroll-wrapper::-webkit-scrollbar { width: 5px; }
    .accounts-table-scroll-wrapper::-webkit-scrollbar-track { background: transparent; }
    .accounts-table-scroll-wrapper::-webkit-scrollbar-thumb { background: rgba(128,128,128,0.25); border-radius: 3px; }
    .accounts-table-scroll-wrapper::-webkit-scrollbar-thumb:hover { background: rgba(128,128,128,0.4); }
    [data-theme="light"] .accounts-table-scroll-wrapper thead {
      background: #ffffff;
    }

    .hero-label {
      font-size: 11px;
      font-weight: 600;
      color: var(--text-muted);
      letter-spacing: 0.05em;
      text-transform: uppercase;
      margin-bottom: 6px;
    }

    .hero-balance-val {
      font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
      font-size: 42px;
      font-weight: 700;
      letter-spacing: -0.015em;
      font-variant-numeric: tabular-nums lining-nums;
      font-feature-settings: "tnum" 1;
      color: #ffffff;
      line-height: 1.1;
    }

    @media (max-width: 600px) {
      .hero-balance-val {
        font-size: 32px !important;
      }
    }

    .hero-badge-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.08);
      padding: 4px 12px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 500;
      color: var(--text-soft);
      margin-top: 10px;
    }

    /* Revolut Circular & Pill Hero Action Buttons */
    .hero-actions-grid, .revolut-actions-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-top: 22px;
      padding-top: 20px;
      border-top: 1px solid var(--border);
    }

    .hero-action-btn, .revolut-action-btn {
      display: flex;
      flex-direction: column;
      align-items: center;
      background: transparent;
      border: none;
      cursor: pointer;
      color: var(--text);
      text-decoration: none;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
      user-select: none;
      -webkit-tap-highlight-color: transparent;
    }

    .hero-action-btn:hover, .revolut-action-btn:hover {
      transform: translateY(-3px) scale(1.02);
    }

    .hero-action-btn:active, .revolut-action-btn:active {
      transform: translateY(0) scale(0.96);
    }

    .hero-action-icon {
      width: 52px;
      height: 52px;
      border-radius: 50%;
      background: rgba(255, 255, 255, 0.08);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      color: #ffffff;
      display: flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 8px;
      border: 1px solid rgba(255, 255, 255, 0.12);
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
      transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
    }

    /* Distinct active and hover states for Action Buttons (Revolut Style) */
    .revolut-icon-expense {
      color: #f87171;
    }
    .hero-action-btn.active-expense .hero-action-icon,
    .hero-action-btn#heroBtnExpense:hover .hero-action-icon,
    .revolut-action-btn:hover .revolut-icon-expense {
      background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%) !important;
      color: #ffffff !important;
      border-color: #ef4444 !important;
      box-shadow: 0 6px 20px rgba(239, 68, 68, 0.45) !important;
    }

    .revolut-icon-income {
      color: #34d399;
    }
    .hero-action-btn.active-income .hero-action-icon,
    .hero-action-btn#heroBtnIncome:hover .hero-action-icon,
    .revolut-action-btn:hover .revolut-icon-income {
      background: linear-gradient(135deg, #10b981 0%, #059669 100%) !important;
      color: #ffffff !important;
      border-color: #10b981 !important;
      box-shadow: 0 6px 20px rgba(16, 185, 129, 0.45) !important;
    }

    .revolut-icon-transfer {
      color: #60a5fa;
    }
    .revolut-action-btn:hover .revolut-icon-transfer {
      background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%) !important;
      color: #ffffff !important;
      border-color: #3b82f6 !important;
      box-shadow: 0 6px 20px rgba(59, 130, 246, 0.45) !important;
    }

    .revolut-icon-goals {
      color: #fbbf24;
    }
    .revolut-action-btn:hover .revolut-icon-goals {
      background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%) !important;
      color: #ffffff !important;
      border-color: #f59e0b !important;
      box-shadow: 0 6px 20px rgba(245, 158, 11, 0.45) !important;
    }

    [data-theme="light"] .hero-action-icon {
      background: #ffffff;
      color: #0f172a;
      border: 1px solid #e2e8f0;
      box-shadow: 0 4px 14px rgba(0, 0, 0, 0.06);
    }

    .hero-action-btn span, .revolut-action-label {
      font-size: 12px;
      font-weight: 600;
      letter-spacing: -0.01em;
      color: var(--text-soft);
      text-align: center;
      line-height: 1.25;
    }

    [data-theme="light"] .hero-action-btn span,
    [data-theme="light"] .revolut-action-label {
      color: #0f172a;
    }

    /* Segmented Toggle for Expense / Income in New Transaction Form */
    .tx-type-segment-group {
      display: flex;
      gap: 10px;
      margin-bottom: 14px;
    }
    .tx-type-segment-btn {
      flex: 1;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      padding: 12px 16px;
      border-radius: 12px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid var(--border);
      background: var(--card-hover);
      color: var(--text-muted);
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }
    .tx-type-segment-btn:hover {
      background: rgba(255, 255, 255, 0.08);
      color: var(--text);
    }
    .tx-type-segment-btn.active-expense {
      background: #ef4444 !important;
      color: #ffffff !important;
      border-color: #ef4444 !important;
    }
    .tx-type-segment-btn.active-income {
      background: #10b981 !important;
      color: #ffffff !important;
      border-color: #10b981 !important;
    }

    /* Vibrant Semantic Colors for Category Filter Buttons */
    .cat-filter-btn[data-filter="EXPENSE"].active,
    .cat-filter-btn.active-expense {
      background: #ef4444 !important;
      color: #ffffff !important;
      border-color: #ef4444 !important;
    }
    .cat-filter-btn[data-filter="INCOME"].active,
    .cat-filter-btn.active-income {
      background: #10b981 !important;
      color: #ffffff !important;
      border-color: #10b981 !important;
    }

    /* ==========================================================================
       Revolut Modal & Authentic Mobile Bottom Sheet for #modalNewTx
       ========================================================================== */
    #modalNewTx {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.65);
      backdrop-filter: blur(25px);
      -webkit-backdrop-filter: blur(25px);
      z-index: 99999;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 16px;
      transition: opacity 0.25s cubic-bezier(0.16, 1, 0.3, 1), visibility 0.25s cubic-bezier(0.16, 1, 0.3, 1);
    }

    #modalNewTx.hidden {
      display: none !important;
    }

    #modalNewTx .bottom-sheet-card {
      width: 100%;
      max-width: 520px;
      background: var(--modal-bg, #11131a);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 24px;
      box-shadow: 0 20px 48px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(255, 255, 255, 0.05);
      padding: 24px 26px 26px 26px;
      position: relative;
      max-height: 90vh;
      overflow-y: auto;
      overscroll-behavior: contain;
      -webkit-overflow-scrolling: touch;
      transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    }

    [data-theme="light"] #modalNewTx .bottom-sheet-card {
      background: #ffffff;
      border-color: rgba(0, 0, 0, 0.08);
      box-shadow: 0 20px 48px rgba(0, 0, 0, 0.15);
    }

    .bottom-sheet-handle-bar {
      display: none;
      width: 100%;
      padding-top: 4px;
      padding-bottom: 14px;
      justify-content: center;
      cursor: grab;
      touch-action: none;
    }

    .bottom-sheet-handle {
      width: 36px;
      height: 5px;
      background: rgba(255, 255, 255, 0.35);
      border-radius: 9999px;
      margin: 0 auto;
      transition: background 0.2s ease;
    }

    [data-theme="light"] .bottom-sheet-handle {
      background: rgba(0, 0, 0, 0.22);
    }

    .bottom-sheet-close-btn {
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid rgba(255, 255, 255, 0.1);
      color: var(--text-muted);
      width: 32px;
      height: 32px;
      border-radius: 50%;
      font-size: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .bottom-sheet-close-btn:hover {
      background: rgba(255, 255, 255, 0.16);
      color: var(--text);
    }
    [data-theme="light"] .bottom-sheet-close-btn {
      background: rgba(0, 0, 0, 0.05);
      border-color: rgba(0, 0, 0, 0.08);
    }

    /* Prominent Revolut Hero Amount Input */
    .revolut-amount-wrapper {
      display: flex;
      align-items: center;
      justify-content: center;
      background: rgba(255, 255, 255, 0.04);
      border: 2px solid rgba(255, 255, 255, 0.1);
      border-radius: 18px;
      padding: 10px 16px;
      margin-bottom: 12px;
      transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }
    .revolut-amount-wrapper:focus-within {
      border-color: var(--primary, #3b82f6);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.25);
    }
    [data-theme="light"] .revolut-amount-wrapper {
      background: #f8fafc;
      border-color: rgba(0, 0, 0, 0.1);
    }
    .revolut-amount-currency {
      font-size: 32px;
      font-weight: 800;
      color: #f87171;
      margin-right: 8px;
      line-height: 1;
      user-select: none;
    }
    .revolut-amount-input {
      font-size: 34px;
      font-weight: 800;
      color: var(--text, #ffffff);
      background: transparent;
      border: none;
      outline: none;
      width: 100%;
      text-align: left;
      letter-spacing: -0.02em;
    }
    [data-theme="light"] .revolut-amount-input {
      color: #0f172a;
    }

    /* Quick Amount Chips (+100, +500, +1000) */
    .revolut-chips-row {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }
    .revolut-chip {
      flex: 1;
      min-width: 65px;
      padding: 8px 12px;
      border-radius: 12px;
      border: 1px solid rgba(255, 255, 255, 0.1);
      background: rgba(255, 255, 255, 0.06);
      color: var(--text);
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      text-align: center;
      transition: all 0.15s cubic-bezier(0.16, 1, 0.3, 1);
    }
    .revolut-chip:hover {
      background: rgba(255, 255, 255, 0.14);
      transform: translateY(-1px);
    }
    .revolut-chip:active {
      transform: scale(0.96);
    }
    [data-theme="light"] .revolut-chip {
      background: #f1f5f9;
      border-color: rgba(0, 0, 0, 0.08);
      color: #1e293b;
    }

    /* Large CTA Button */
    .revolut-cta-btn {
      width: 100%;
      padding: 15px 20px;
      font-size: 16px;
      font-weight: 700;
      border-radius: 16px;
      letter-spacing: -0.01em;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
      color: #ffffff;
      border: none;
      cursor: pointer;
      box-shadow: 0 4px 18px rgba(239, 68, 68, 0.4);
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }
    .revolut-cta-btn.cta-income {
      background: linear-gradient(135deg, #10b981 0%, #059669 100%) !important;
      box-shadow: 0 4px 18px rgba(16, 185, 129, 0.4) !important;
    }
    .revolut-cta-btn:hover {
      transform: translateY(-2px);
      filter: brightness(1.05);
    }
    .revolut-cta-btn:active {
      transform: translateY(0) scale(0.98);
    }

    /* Mobile Bottom Sheet Media Query (< 768px) */
    @media (max-width: 768px) {
      #modalNewTx {
        align-items: flex-end !important;
        justify-content: center !important;
        padding: 0 !important;
        background: rgba(0, 0, 0, 0.6) !important;
        backdrop-filter: blur(25px) !important;
        -webkit-backdrop-filter: blur(25px) !important;
        touch-action: pan-y;
      }
      #modalNewTx .bottom-sheet-card {
        max-width: 100% !important;
        width: 100% !important;
        border-radius: 28px 28px 0 0 !important;
        margin: 0 !important;
        border-left: none !important;
        border-right: none !important;
        border-bottom: none !important;
        max-height: calc(88vh - env(safe-area-inset-bottom, 0px)) !important;
        padding: 12px 20px calc(24px + env(safe-area-inset-bottom, 20px)) 20px !important;
        animation: revolutSlideUp 0.32s cubic-bezier(0.16, 1, 0.3, 1);
        box-shadow: 0 -10px 40px rgba(0, 0, 0, 0.5) !important;
        overflow-y: auto !important;
        -webkit-overflow-scrolling: touch !important;
        overscroll-behavior: contain !important;
      }
      .bottom-sheet-handle-bar {
        display: flex !important;
      }
    }

    @keyframes revolutSlideUp {
      from {
        transform: translateY(100%);
      }
      to {
        transform: translateY(0);
      }
    }

    /* ==========================================================================
       Apple HIG Modals & Bottom Sheets Optimization
       ========================================================================== */
    /* 1. Backdrop Blur (25px) and Base Presentation for All Modals */
    #modalNewTx,
    #modalNewDebt,
    #modalEditTx,
    #modalPayDebt,
    #modalGoal,
    #modalEnvelope,
    #settingsModal,
    #modalCardSettings,
    #modalObligation,
    #modalQrPair,
    #modalContributeGoal,
    #modalEnvelopeDeposit,
    #modalEnvelopeWithdraw,
    #modalEnvelopeTransfer,
    #vaultModal,
    [id^="modal"] {
      backdrop-filter: blur(25px) !important;
      -webkit-backdrop-filter: blur(25px) !important;
      background: rgba(0, 0, 0, 0.65) !important;
      -webkit-overflow-scrolling: touch !important;
      overscroll-behavior: contain !important;
    }

    [data-theme="light"] #modalNewTx,
    [data-theme="light"] #modalNewDebt,
    [data-theme="light"] #modalEditTx,
    [data-theme="light"] #modalPayDebt,
    [data-theme="light"] #modalGoal,
    [data-theme="light"] #modalEnvelope,
    [data-theme="light"] #settingsModal,
    [data-theme="light"] #modalCardSettings,
    [data-theme="light"] #modalObligation,
    [data-theme="light"] #modalQrPair,
    [data-theme="light"] #modalContributeGoal,
    [data-theme="light"] #modalEnvelopeDeposit,
    [data-theme="light"] #modalEnvelopeWithdraw,
    [data-theme="light"] #modalEnvelopeTransfer,
    [data-theme="light"] #vaultModal,
    [data-theme="light"] [id^="modal"] {
      background: rgba(15, 23, 42, 0.45) !important;
    }

    /* Modal Cards: Apple HIG Glass Surfaces */
    #modalNewDebt .card,
    #modalEditTx .card,
    #modalPayDebt .card,
    #modalGoal .card,
    #modalEnvelope .card,
    #settingsModal .card,
    #modalCardSettings .card,
    #modalObligation .card,
    #modalQrPair .card,
    #modalContributeGoal .card,
    #modalEnvelopeDeposit .card,
    #modalEnvelopeWithdraw .card,
    #modalEnvelopeTransfer .card,
    #vaultModal .card {
      border-radius: 24px !important;
      border: 1px solid rgba(255, 255, 255, 0.12) !important;
      box-shadow: 0 24px 48px -12px rgba(0, 0, 0, 0.6), 0 0 0 1px rgba(255, 255, 255, 0.05) !important;
      overflow-y: auto !important;
      -webkit-overflow-scrolling: touch !important;
      overscroll-behavior: contain !important;
    }

    [data-theme="light"] #modalNewDebt .card,
    [data-theme="light"] #modalEditTx .card,
    [data-theme="light"] #modalPayDebt .card,
    [data-theme="light"] #modalGoal .card,
    [data-theme="light"] #modalEnvelope .card,
    [data-theme="light"] #settingsModal .card,
    [data-theme="light"] #modalCardSettings .card,
    [data-theme="light"] #modalObligation .card,
    [data-theme="light"] #modalQrPair .card,
    [data-theme="light"] #modalContributeGoal .card,
    [data-theme="light"] #modalEnvelopeDeposit .card,
    [data-theme="light"] #modalEnvelopeWithdraw .card,
    [data-theme="light"] #modalEnvelopeTransfer .card,
    [data-theme="light"] #vaultModal .card {
      background: #ffffff !important;
      border: 1px solid rgba(0, 0, 0, 0.08) !important;
      box-shadow: 0 20px 40px -8px rgba(0, 0, 0, 0.15) !important;
    }

    /* 2. Category Dropdown Menu (#modalTxCatMenu): Smooth Touch Scroll & 100% Readability */
    #modalTxCatMenu {
      position: absolute;
      width: 100% !important;
      max-width: 100% !important;
      background: rgba(20, 23, 32, 0.97) !important;
      backdrop-filter: blur(25px) !important;
      -webkit-backdrop-filter: blur(25px) !important;
      border: 1px solid rgba(255, 255, 255, 0.12) !important;
      border-radius: 16px !important;
      box-shadow: 0 16px 40px rgba(0, 0, 0, 0.7) !important;
      z-index: 10001 !important;
      overflow: hidden !important;
    }

    #modalTxCatMenu .category-dropdown-list,
    #modalTxCatList {
      max-height: 300px !important;
      overflow-y: auto !important;
      -webkit-overflow-scrolling: touch !important;
      overscroll-behavior: contain !important;
      touch-action: pan-y !important;
      padding: 4px 0 !important;
    }

    #modalTxCatMenu .cat-dropdown-item {
      color: #f8fafc !important;
      padding: 10px 14px !important;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05) !important;
      font-size: 14px !important;
      display: flex !important;
      align-items: center !important;
      justify-content: space-between !important;
      gap: 10px !important;
      transition: background 0.15s ease, padding 0.15s ease !important;
      -webkit-tap-highlight-color: transparent !important;
    }

    #modalTxCatMenu .cat-dropdown-item:hover,
    #modalTxCatMenu .cat-dropdown-item:active {
      background: rgba(255, 255, 255, 0.08) !important;
      color: #ffffff !important;
    }

    #modalTxCatMenu .cat-dropdown-item.active {
      background: rgba(59, 130, 246, 0.2) !important;
      color: #60a5fa !important;
      font-weight: 600 !important;
    }

    #modalTxCatMenu .cat-group-header {
      padding: 8px 14px !important;
      font-size: 11px !important;
      font-weight: 700 !important;
      text-transform: uppercase !important;
      letter-spacing: 0.05em !important;
      color: #94a3b8 !important;
      background: #181c26 !important;
      border-bottom: 1px solid rgba(255, 255, 255, 0.08) !important;
      position: sticky !important;
      top: 0 !important;
      z-index: 2 !important;
    }

    #modalTxCatMenu .category-dropdown-search {
      padding: 10px 12px !important;
      background: rgba(255, 255, 255, 0.02) !important;
      border-bottom: 1px solid rgba(255, 255, 255, 0.08) !important;
      flex-shrink: 0 !important;
    }

    #modalTxCatMenu .category-dropdown-search input {
      background: #0d0f15 !important;
      border: 1px solid rgba(255, 255, 255, 0.14) !important;
      color: #ffffff !important;
      border-radius: 10px !important;
      padding: 9px 12px !important;
      font-size: 14px !important;
    }

    #modalTxCatMenu .category-dropdown-search input::placeholder {
      color: #64748b !important;
    }

    /* Category Dropdown - Light Theme 100% Readability */
    [data-theme="light"] #modalTxCatMenu {
      background: rgba(255, 255, 255, 0.98) !important;
      border: 1px solid #cbd5e1 !important;
      box-shadow: 0 16px 36px rgba(0, 0, 0, 0.12) !important;
    }

    [data-theme="light"] #modalTxCatMenu .cat-dropdown-item {
      color: #0f172a !important;
      border-bottom: 1px solid #f1f5f9 !important;
    }

    [data-theme="light"] #modalTxCatMenu .cat-dropdown-item:hover,
    [data-theme="light"] #modalTxCatMenu .cat-dropdown-item:active {
      background: #f1f5f9 !important;
      color: #0f172a !important;
    }

    [data-theme="light"] #modalTxCatMenu .cat-dropdown-item.active {
      background: rgba(37, 99, 235, 0.1) !important;
      color: #2563eb !important;
      font-weight: 600 !important;
    }

    [data-theme="light"] #modalTxCatMenu .cat-group-header {
      color: #475569 !important;
      background: #f8fafc !important;
      border-bottom: 1px solid #e2e8f0 !important;
    }

    [data-theme="light"] #modalTxCatMenu .category-dropdown-search {
      background: #f8fafc !important;
      border-bottom: 1px solid #e2e8f0 !important;
    }

    [data-theme="light"] #modalTxCatMenu .category-dropdown-search input {
      background: #ffffff !important;
      border: 1px solid #cbd5e1 !important;
      color: #0f172a !important;
    }

    [data-theme="light"] #modalTxCatMenu .category-dropdown-search input::placeholder {
      color: #94a3b8 !important;
    }

    /* 3. Apple HIG Form Controls (Inputs, Selects, Textareas) in All Modals */
    .modal input:not([type="checkbox"]):not([type="radio"]),
    .modal select,
    .modal textarea,
    [id^="modal"] input:not([type="checkbox"]):not([type="radio"]),
    [id^="modal"] select,
    [id^="modal"] textarea,
    #settingsModal input:not([type="checkbox"]):not([type="radio"]),
    #settingsModal select,
    #settingsModal textarea {
      border-radius: 12px !important;
      border: 1px solid rgba(255, 255, 255, 0.12) !important;
      background: var(--input-bg, #11131a);
      color: var(--text, #ffffff);
      padding: 11px 14px;
      font-family: inherit;
      font-size: 15px;
      transition: border-color 0.18s ease, box-shadow 0.18s ease, background-color 0.18s ease;
      -webkit-appearance: none;
      appearance: none;
      box-sizing: border-box;
    }

    .modal select,
    [id^="modal"] select,
    #settingsModal select {
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath fill='%2394a3b8' d='M1.41 0L6 4.58 10.59 0 12 1.41l-6 6-6-6z'/%3E%3C/svg%3E");
      background-repeat: no-repeat;
      background-position: right 14px center;
      padding-right: 36px;
    }

    .modal input:focus,
    .modal select:focus,
    .modal textarea:focus,
    [id^="modal"] input:focus,
    [id^="modal"] select:focus,
    [id^="modal"] textarea:focus,
    #settingsModal input:focus,
    #settingsModal select:focus,
    #settingsModal textarea:focus {
      outline: none !important;
      border-color: #3b82f6 !important;
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.28) !important;
    }

    [data-theme="light"] .modal input:not([type="checkbox"]):not([type="radio"]),
    [data-theme="light"] .modal select,
    [data-theme="light"] .modal textarea,
    [data-theme="light"] [id^="modal"] input:not([type="checkbox"]):not([type="radio"]),
    [data-theme="light"] [id^="modal"] select,
    [data-theme="light"] [id^="modal"] textarea,
    [data-theme="light"] #settingsModal input:not([type="checkbox"]):not([type="radio"]),
    [data-theme="light"] #settingsModal select,
    [data-theme="light"] #settingsModal textarea {
      background: #f8fafc !important;
      color: #0f172a !important;
      border: 1px solid rgba(0, 0, 0, 0.12) !important;
    }

    [data-theme="light"] .modal select,
    [data-theme="light"] [id^="modal"] select,
    [data-theme="light"] #settingsModal select {
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath fill='%2364748b' d='M1.41 0L6 4.58 10.59 0 12 1.41l-6 6-6-6z'/%3E%3C/svg%3E");
    }

    /* iOS Anti-Auto-Zoom: 16px Base Font on Mobile Viewports */
    @media (max-width: 768px) {
      input:not([type="checkbox"]):not([type="radio"]),
      select,
      textarea,
      .modal input:not([type="checkbox"]):not([type="radio"]),
      .modal select,
      .modal textarea,
      [id^="modal"] input:not([type="checkbox"]):not([type="radio"]),
      [id^="modal"] select,
      [id^="modal"] textarea,
      #settingsModal input:not([type="checkbox"]):not([type="radio"]),
      #settingsModal select,
      #settingsModal textarea {
        font-size: 16px !important;
      }
      .revolut-amount-input {
        font-size: 32px !important;
      }
    }

    /* 4. Apple HIG Buttons across All Modals */
    .modal .btn,
    [id^="modal"] .btn,
    #settingsModal .btn {
      border-radius: 12px;
      font-weight: 600;
      letter-spacing: -0.01em;
      transition: all 0.18s cubic-bezier(0.16, 1, 0.3, 1);
      -webkit-tap-highlight-color: transparent;
    }

    .modal .btn:active,
    [id^="modal"] .btn:active,
    #settingsModal .btn:active {
      transform: scale(0.97);
    }

    /* Secondary Buttons in Modals */
    .modal .btn-secondary,
    [id^="modal"] .btn-secondary,
    #settingsModal .btn-secondary {
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid rgba(255, 255, 255, 0.12);
      color: var(--text, #ffffff);
    }

    .modal .btn-secondary:hover,
    [id^="modal"] .btn-secondary:hover,
    #settingsModal .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.14);
      border-color: rgba(255, 255, 255, 0.2);
    }

    [data-theme="light"] .modal .btn-secondary,
    [data-theme="light"] [id^="modal"] .btn-secondary,
    [data-theme="light"] #settingsModal .btn-secondary {
      background: rgba(0, 0, 0, 0.05) !important;
      border: 1px solid rgba(0, 0, 0, 0.08) !important;
      color: #0f172a !important;
    }

    [data-theme="light"] .modal .btn-secondary:hover,
    [data-theme="light"] [id^="modal"] .btn-secondary:hover,
    [data-theme="light"] #settingsModal .btn-secondary:hover {
      background: rgba(0, 0, 0, 0.09) !important;
    }

    /* Universal Modal Close Buttons: Apple Circular Pill */
    #modalNewTx .bottom-sheet-close-btn,
    #modalEditTx > .card > button:first-child,
    #modalNewDebt > .card > button:first-child,
    #modalPayDebt > .card > button:first-child,
    #modalGoal > .card > button:first-child,
    #modalEnvelope > .card > button:first-child,
    #modalCardSettings > .card > button:first-child,
    #modalObligation > .card > button:first-child,
    #modalQrPair > .card > button:first-child,
    #vaultModal > .card button[onclick*="close"],
    #settingsModal button[onclick*="close"] {
      width: 32px !important;
      height: 32px !important;
      border-radius: 50% !important;
      background: rgba(255, 255, 255, 0.08) !important;
      border: 1px solid rgba(255, 255, 255, 0.1) !important;
      color: var(--text-muted) !important;
      font-size: 15px !important;
      font-weight: 600 !important;
      display: inline-flex !important;
      align-items: center !important;
      justify-content: center !important;
      cursor: pointer !important;
      transition: all 0.15s ease !important;
      padding: 0 !important;
      line-height: 1 !important;
    }

    #modalNewTx .bottom-sheet-close-btn:hover,
    #modalEditTx > .card > button:first-child:hover,
    #modalNewDebt > .card > button:first-child:hover,
    #modalPayDebt > .card > button:first-child:hover,
    #modalGoal > .card > button:first-child:hover,
    #modalEnvelope > .card > button:first-child:hover,
    #modalCardSettings > .card > button:first-child:hover,
    #modalObligation > .card > button:first-child:hover,
    #modalQrPair > .card > button:first-child:hover,
    #vaultModal > .card button[onclick*="close"]:hover,
    #settingsModal button[onclick*="close"]:hover {
      background: rgba(255, 255, 255, 0.16) !important;
      color: #ffffff !important;
      transform: scale(1.05);
    }

    [data-theme="light"] #modalNewTx .bottom-sheet-close-btn,
    [data-theme="light"] #modalEditTx > .card > button:first-child,
    [data-theme="light"] #modalNewDebt > .card > button:first-child,
    [data-theme="light"] #modalPayDebt > .card > button:first-child,
    [data-theme="light"] #modalGoal > .card > button:first-child,
    [data-theme="light"] #modalEnvelope > .card > button:first-child,
    [data-theme="light"] #modalCardSettings > .card > button:first-child,
    [data-theme="light"] #modalObligation > .card > button:first-child,
    [data-theme="light"] #modalQrPair > .card > button:first-child,
    [data-theme="light"] #vaultModal > .card button[onclick*="close"],
    [data-theme="light"] #settingsModal button[onclick*="close"] {
      background: rgba(0, 0, 0, 0.05) !important;
      border-color: rgba(0, 0, 0, 0.08) !important;
      color: #64748b !important;
    }

    [data-theme="light"] #modalNewTx .bottom-sheet-close-btn:hover,
    [data-theme="light"] #modalEditTx > .card > button:first-child:hover,
    [data-theme="light"] #modalNewDebt > .card > button:first-child:hover,
    [data-theme="light"] #modalPayDebt > .card > button:first-child:hover,
    [data-theme="light"] #modalGoal > .card > button:first-child:hover,
    [data-theme="light"] #modalEnvelope > .card > button:first-child:hover,
    [data-theme="light"] #modalCardSettings > .card > button:first-child:hover,
    [data-theme="light"] #modalObligation > .card > button:first-child:hover,
    [data-theme="light"] #modalQrPair > .card > button:first-child:hover,
    [data-theme="light"] #vaultModal > .card button[onclick*="close"]:hover,
    [data-theme="light"] #settingsModal button[onclick*="close"]:hover {
      background: rgba(0, 0, 0, 0.1) !important;
      color: #0f172a !important;
    }

    /* 5. Apple HIG Segmented Controls (Type Switches) */
    .tx-type-segment-group {
      display: flex;
      gap: 6px;
      background: rgba(0, 0, 0, 0.28);
      padding: 4px;
      border-radius: 14px;
      border: 1px solid rgba(255, 255, 255, 0.08);
    }

    [data-theme="light"] .tx-type-segment-group {
      background: rgba(0, 0, 0, 0.05);
      border-color: rgba(0, 0, 0, 0.06);
    }

    .tx-type-segment-btn {
      flex: 1;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      padding: 10px 14px;
      border-radius: 10px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid transparent;
      background: transparent;
      color: var(--text-muted);
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
      -webkit-tap-highlight-color: transparent;
    }

    .tx-type-segment-btn:hover {
      color: var(--text);
      background: rgba(255, 255, 255, 0.05);
    }

    .tx-type-segment-btn.active-expense {
      background: #ef4444 !important;
      color: #ffffff !important;
      border-color: rgba(255, 255, 255, 0.15) !important;
      box-shadow: 0 3px 10px rgba(239, 68, 68, 0.35) !important;
    }

    .tx-type-segment-btn.active-income {
      background: #10b981 !important;
      color: #ffffff !important;
      border-color: rgba(255, 255, 255, 0.15) !important;
      box-shadow: 0 3px 10px rgba(16, 185, 129, 0.35) !important;
    }

    [data-theme="light"] .tx-type-segment-btn:hover {
      background: rgba(0, 0, 0, 0.03);
      color: #0f172a;
    }

    /* Debt Type Segmented Grid */
    .debt-type-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 6px;
      background: rgba(0, 0, 0, 0.22);
      padding: 6px;
      border-radius: 14px;
      border: 1px solid rgba(255, 255, 255, 0.06);
    }

    [data-theme="light"] .debt-type-grid {
      background: rgba(0, 0, 0, 0.04);
      border-color: rgba(0, 0, 0, 0.06);
    }

    .debt-type-btn {
      padding: 9px 8px;
      border: 1px solid transparent;
      border-radius: 10px;
      background: transparent;
      color: var(--text-muted);
      font-weight: 600;
      font-size: 12px;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
      text-align: center;
    }

    .debt-type-btn:hover {
      background: rgba(255, 255, 255, 0.06);
      color: var(--text);
    }

    .debt-type-btn.active {
      background: var(--primary, #3b82f6) !important;
      color: #ffffff !important;
      border-color: rgba(255, 255, 255, 0.15) !important;
      box-shadow: 0 2px 8px rgba(59, 130, 246, 0.35) !important;
    }

    [data-theme="light"] .debt-type-btn:hover {
      background: rgba(0, 0, 0, 0.04);
      color: #0f172a;
    }

    @media (max-width: 480px) {
      .debt-type-grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }

    /* Revolut Metal / Dark Debit Card Component */
    .appetite-debit-card, .revolut-debit-card {
      position: relative;
      width: 100%;
      aspect-ratio: 1.58 / 1;
      border-radius: 20px;
      background: linear-gradient(145deg, #1b202c 0%, #10131a 100%);
      padding: 22px;
      color: #ffffff;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      overflow: hidden;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.45);
      border: 1px solid rgba(255, 255, 255, 0.09);
      user-select: none;
    }

    .appetite-card-sheen {
      display: none;
    }

    /* Dedicated Monospace Amount Classes */
    .amount-mono,
    .overview-balance-val,
    #valLiquid,
    #valSafeToSpend,
    #valHeroTotalBalance,
    #dashOverviewTotalDebt,
    #dashMonthlyBurnRate,
    #dashSavingsRate,
    #analyticsSavingsRate,
    .tx-amount {
      font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace !important;
      font-variant-numeric: tabular-nums lining-nums;
      font-feature-settings: "tnum" 1;
      letter-spacing: -0.015em;
    }

    /* ==========================================================================
       CONCEPT 1 REVOLUT DESKTOP DASHBOARD & DESKTOP ERGONOMICS (>= 1024px)
       ========================================================================== */
    html {
      overflow-x: hidden;
      max-width: 100vw;
    }

    body {
      overflow-x: hidden;
      max-width: 100vw;
      box-sizing: border-box;
    }

    *, *::before, *::after {
      box-sizing: border-box;
    }

    /* Revolut Crisp Table System with Tabular Numbers & Right-aligned Amounts */
    table, .revolut-ledger-table {
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      margin-top: 6px;
    }

    th, td {
      padding: 12px 14px;
      border-bottom: 1px solid var(--border);
      font-size: 13px;
      color: var(--text);
    }

    th {
      color: var(--text-muted);
      font-weight: 600;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      border-bottom: 1px solid rgba(255, 255, 255, 0.12);
    }

    [data-theme="light"] th {
      color: #737a85 !important;
      border-bottom: 1px solid #e5e7eb;
    }

    tbody tr {
      transition: background 0.15s ease;
    }

    tbody tr:hover td {
      background: rgba(255, 255, 255, 0.035);
    }

    [data-theme="light"] tbody tr:hover td {
      background: rgba(0, 0, 0, 0.02);
    }

    .amount-cell, td.amount-val, th.amount-header {
      text-align: right !important;
      font-variant-numeric: tabular-nums;
    }

    td.amount-val {
      font-weight: 700;
      white-space: nowrap;
    }

    /* Hero balance section with Safe-to-Spend & Total Balance */
    .hero-balance-header-row {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 16px;
      flex-wrap: wrap;
    }

    .hero-primary-balance-box {
      flex: 1;
      min-width: 260px;
    }

    .hero-secondary-balance-box {
      display: inline-flex;
      flex-direction: column;
      align-items: flex-start;
      padding: 10px 18px;
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid rgba(255, 255, 255, 0.16);
      border-radius: 16px;
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
    }

    .hero-secondary-label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      opacity: 0.85;
      color: #ffffff;
      font-weight: 600;
      margin-bottom: 2px;
    }

    .hero-secondary-val {
      font-size: 26px;
      font-weight: 800;
      letter-spacing: -0.02em;
      color: #ffffff;
      font-variant-numeric: tabular-nums;
      line-height: 1.15;
    }

    .hero-secondary-pill {
      font-size: 11px;
      font-weight: 500;
      color: rgba(255, 255, 255, 0.8);
      margin-top: 4px;
    }

    [data-theme="light"] .hero-secondary-balance-box {
      background: rgba(255, 255, 255, 0.4);
      border: 1px solid rgba(255, 255, 255, 0.6);
      color: #0c0d0e;
    }

    [data-theme="light"] .hero-secondary-label,
    [data-theme="light"] .hero-secondary-val,
    [data-theme="light"] .hero-secondary-pill {
      color: #0c0d0e;
    }

    body.privacy-masked #valHeroTotalBalance,
    body.privacy-masked .hero-secondary-val {
      filter: blur(7px);
      user-select: none;
      transition: filter 0.2s ease;
    }

    /* Desktop Dashboard Grid: Main Column + Right Side Widget Column */
    .desktop-dashboard-grid {
      display: block;
      width: 100%;
    }

    .desktop-main-column {
      width: 100%;
      min-width: 0;
    }

    .desktop-widget-column {
      width: 100%;
      min-width: 0;
      margin-top: 20px;
    }

    @media (max-width: 1023px) {
      .desktop-dashboard-grid {
        display: flex;
        flex-direction: column;
        gap: 16px;
      }
      .desktop-main-column,
      .desktop-widget-column {
        display: contents;
      }
      .hero-card-container { order: 1; }
      .quick-entry-card { order: 2; }
      .onboarding-card { order: 3; }
      .core-financial-cards { order: 4; }
      #dashEnvelopesCard { order: 5; }
      #dashGoalsCard { order: 6; }
      #dashLedgerCard { order: 7; }
      .accounts-card { order: 8; }
    }

    /* Desktop Ergonomics (>= 1024px) */
    @media (min-width: 1024px) {
      .container {
        max-width: 1400px !important;
        width: 100% !important;
        padding-left: 28px !important;
        padding-right: 28px !important;
        margin: 0 auto !important;
      }

      .header {
        padding: 16px 0 18px 0 !important;
        margin-bottom: 20px !important;
      }

      .month-navigator-bar {
        display: flex !important;
        align-items: center !important;
        justify-content: space-between !important;
        flex-wrap: nowrap !important;
        padding: 12px 22px !important;
        border-radius: 16px !important;
        background: rgba(17, 24, 39, 0.75) !important;
        backdrop-filter: blur(20px) saturate(180%) !important;
        -webkit-backdrop-filter: blur(20px) saturate(180%) !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        margin-bottom: 20px !important;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25) !important;
      }

      .nav-tabs {
        display: flex !important;
        align-items: center !important;
        flex-wrap: nowrap !important;
        gap: 3px !important;
        padding: 4px !important;
        border-radius: 9999px !important;
        background: rgba(118, 118, 128, 0.24) !important;
        backdrop-filter: blur(25px) !important;
        -webkit-backdrop-filter: blur(25px) !important;
        margin-bottom: 24px !important;
        overflow-x: auto !important;
        overflow-y: hidden !important;
        -webkit-overflow-scrolling: touch !important;
        scrollbar-width: none !important;
        -ms-overflow-style: none !important;
      }

      .nav-tabs::-webkit-scrollbar {
        display: none !important;
        width: 0 !important;
        height: 0 !important;
      }

      .tab-btn {
        padding: 7px 15px !important;
        font-size: 13px !important;
        font-weight: 500 !important;
        border-radius: 9px !important;
        white-space: nowrap !important;
      }

      .hero-secondary-balance-box {
        align-items: flex-end;
        text-align: right;
      }

      .desktop-dashboard-grid {
        display: grid !important;
        grid-template-columns: minmax(0, 1fr) 390px !important;
        gap: 24px !important;
        align-items: start !important;
      }

      .desktop-main-column {
        display: flex !important;
        flex-direction: column !important;
        min-width: 0 !important;
        gap: 0 !important;
      }

      .desktop-widget-column {
        display: flex !important;
        flex-direction: column !important;
        min-width: 0 !important;
        margin-top: 0 !important;
        position: sticky !important;
        top: 90px !important;
        gap: 0 !important;
      }

      .hero-card-container,
      .quick-entry-card,
      .onboarding-card,
      .core-financial-cards,
      #dashEnvelopesCard,
      #dashGoalsCard,
      #dashLedgerCard,
      .accounts-card {
        order: initial !important;
      }
    }

  
    /* ==========================================================================
       BULLETPROOF LIGHT THEME HIGH-CONTRAST SPECIFICATION (REVOLUT / HALLMARK)
       ========================================================================== */
    [data-theme="light"] body {
      background: #f8fafc !important;
      background-image: linear-gradient(180deg, #f8fafc 0%, #f1f5f9 100%) !important;
      color: #0f172a !important;
    }

    [data-theme="light"] .header {
      background: rgba(255, 255, 255, 0.92) !important;
      backdrop-filter: blur(20px) !important;
      -webkit-backdrop-filter: blur(20px) !important;
      border-bottom: 1px solid #e2e8f0 !important;
    }

    [data-theme="light"] .brand-title {
      color: #0f172a !important;
    }

    [data-theme="light"] .brand-tag {
      color: #64748b !important;
    }

    /* Cards */
    [data-theme="light"] .card,
    [data-theme="light"] .desktop-main-column .card,
    [data-theme="light"] .desktop-widget-column .card {
      background: #ffffff !important;
      border: 1px solid #e2e8f0 !important;
      border-top: 1px solid #cbd5e1 !important;
      box-shadow: 0 4px 20px -2px rgba(15, 23, 42, 0.06) !important;
      color: #0f172a !important;
    }

    [data-theme="light"] .card:hover {
      border-color: #cbd5e1 !important;
      box-shadow: 0 8px 30px -4px rgba(15, 23, 42, 0.1) !important;
    }

    /* Card Titles & Text */
    [data-theme="light"] h1,
    [data-theme="light"] h2,
    [data-theme="light"] h3,
    [data-theme="light"] h4,
    [data-theme="light"] .card-title,
    [data-theme="light"] .text-strong {
      color: #0f172a !important;
    }

    [data-theme="light"] p,
    [data-theme="light"] .text-muted,
    [data-theme="light"] .stat-label {
      color: #64748b !important;
    }

    /* Hero Balance Card in Light Theme */
    [data-theme="light"] .revolut-hero-card,
    [data-theme="light"] .appetite-hero-card {
      background: #ffffff !important;
      background-image: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%) !important;
      border: 1px solid #e2e8f0 !important;
      border-top: none !important;
      box-shadow: 0 10px 30px -4px rgba(15, 23, 42, 0.08) !important;
      color: #0f172a !important;
    }

    [data-theme="light"] .hero-balance-val {
      color: #0f172a !important;
    }

    [data-theme="light"] .hero-balance-label {
      color: #64748b !important;
    }

    [data-theme="light"] .hero-secondary-balance-box {
      background: #f1f5f9 !important;
      border: 1px solid #e2e8f0 !important;
      color: #0f172a !important;
    }

    [data-theme="light"] .hero-secondary-val {
      color: #0f172a !important;
    }

    [data-theme="light"] .hero-secondary-label {
      color: #64748b !important;
    }

    /* 4 Revolut Action Buttons in Light Theme */
    [data-theme="light"] .revolut-action-label,
    [data-theme="light"] .hero-action-btn span {
      color: #0f172a !important;
      font-weight: 600 !important;
    }

    [data-theme="light"] .hero-action-icon,
    [data-theme="light"] .revolut-action-icon {
      background: #f8fafc !important;
      border: 1px solid #e2e8f0 !important;
      color: #0f172a !important;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04) !important;
    }

    [data-theme="light"] .revolut-icon-expense {
      background: #fef2f2 !important;
      border-color: #fecaca !important;
      color: #dc2626 !important;
    }

    [data-theme="light"] .revolut-icon-income {
      background: #f0fdf4 !important;
      border-color: #bbf7d0 !important;
      color: #16a34a !important;
    }

    [data-theme="light"] .revolut-icon-transfer {
      background: #eff6ff !important;
      border-color: #bfdbfe !important;
      color: #2563eb !important;
    }

    [data-theme="light"] .revolut-icon-goals {
      background: #fffbeb !important;
      border-color: #fde68a !important;
      color: #d97706 !important;
    }

    /* Navigation Tabs in Light Theme (Apple HIG iOS Segmented Control) */
    [data-theme="light"] .nav-tabs {
      background: rgba(118, 118, 128, 0.12) !important;
      border: 1px solid rgba(0, 0, 0, 0.06) !important;
      box-shadow: inset 0 0.5px 1px rgba(0, 0, 0, 0.06) !important;
    }

    [data-theme="light"] .tab-btn {
      color: #636366 !important;
      background: transparent !important;
    }

    [data-theme="light"] .tab-btn:hover {
      color: #1c1c1e !important;
      background: rgba(0, 0, 0, 0.04) !important;
    }

    [data-theme="light"] .tab-btn.active {
      color: #2563eb !important;
      background: #ffffff !important;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08) !important;
      font-weight: 700 !important;
    }

    /* Inputs & Selects in Light Theme */
    [data-theme="light"] input,
    [data-theme="light"] select,
    [data-theme="light"] textarea {
      background: #ffffff !important;
      color: #0f172a !important;
      border: 1px solid #cbd5e1 !important;
    }

    [data-theme="light"] input::placeholder,
    [data-theme="light"] textarea::placeholder {
      color: #94a3b8 !important;
    }

    [data-theme="light"] input:focus,
    [data-theme="light"] select:focus,
    [data-theme="light"] textarea:focus {
      background: #ffffff !important;
      color: #0f172a !important;
      border-color: #2563eb !important;
      box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15) !important;
    }

    [data-theme="light"] label {
      color: #334155 !important;
      font-weight: 600 !important;
    }

    /* Buttons in Light Theme */
    [data-theme="light"] .btn-secondary {
      background: #f1f5f9 !important;
      color: #0f172a !important;
      border: 1px solid #cbd5e1 !important;
    }

    [data-theme="light"] .btn-secondary:hover {
      background: #e2e8f0 !important;
      color: #0f172a !important;
    }

    /* Stat Amounts in Light Theme */
    [data-theme="light"] .stat-val {
      color: #0f172a !important;
    }

    [data-theme="light"] .stat-val.primary { color: #2563eb !important; }
    [data-theme="light"] .stat-val.success { color: #16a34a !important; }
    [data-theme="light"] .stat-val.danger { color: #dc2626 !important; }
    [data-theme="light"] .stat-val.warning { color: #d97706 !important; }
    [data-theme="light"] .stat-val.purple { color: #7c3aed !important; }

    /* Tables & Rows in Light Theme */
    [data-theme="light"] table {
      color: #0f172a !important;
    }

    [data-theme="light"] th {
      background: #f8fafc !important;
      color: #64748b !important;
      border-bottom: 1px solid #e2e8f0 !important;
      font-weight: 600 !important;
    }

    [data-theme="light"] td {
      color: #0f172a !important;
      border-bottom: 1px solid #f1f5f9 !important;
    }

    [data-theme="light"] tbody tr:hover td {
      background: #f8fafc !important;
    }

    /* Modals & Bottom Sheets in Light Theme */
    [data-theme="light"] .modal-overlay,
    [data-theme="light"] [id^="modal"] {
      background: rgba(15, 23, 42, 0.5) !important;
    }

    [data-theme="light"] .modal-overlay .card,
    [data-theme="light"] [id^="modal"] .card,
    [data-theme="light"] .bottom-sheet-card {
      background: #ffffff !important;
      color: #0f172a !important;
      border: 1px solid #e2e8f0 !important;
      box-shadow: 0 20px 48px -6px rgba(15, 23, 42, 0.2) !important;
    }

    /* Category Dropdown in Light Theme */
    [data-theme="light"] .category-dropdown-menu {
      background: #ffffff !important;
      border: 1px solid #cbd5e1 !important;
      box-shadow: 0 12px 36px -4px rgba(15, 23, 42, 0.15) !important;
    }

    [data-theme="light"] .cat-dropdown-item {
      color: #0f172a !important;
    }

    [data-theme="light"] .cat-dropdown-item:hover {
      background: #f1f5f9 !important;
      color: #0f172a !important;
    }

    [data-theme="light"] .cat-group-header {
      color: #64748b !important;
      background: #f8fafc !important;
    }

    /* Mobile Bottom Nav in Light Theme */
    [data-theme="light"] .mobile-bottom-nav {
      background: rgba(255, 255, 255, 0.95) !important;
      border: 1px solid #e2e8f0 !important;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08) !important;
    }

    [data-theme="light"] .mobile-nav-item {
      color: #64748b !important;
    }

    [data-theme="light"] .mobile-nav-item.active {
      color: #2563eb !important;
    }

    [data-theme="light"] .mobile-nav-item.active .icon {
      color: #2563eb !important;
    }

    /* Month Selector in Light Theme */
    [data-theme="light"] #globalMonthSelect,
    [data-theme="light"] .month-nav-select {
      background: #ffffff !important;
      color: #0f172a !important;
      border: 1px solid #cbd5e1 !important;
    }

    [data-theme="light"] #prevMonthBtn,
    [data-theme="light"] #nextMonthBtn {
      background: #ffffff !important;
      color: #0f172a !important;
      border: 1px solid #cbd5e1 !important;
    }

    [data-theme="light"] #prevMonthBtn:hover,
    [data-theme="light"] #nextMonthBtn:hover {
      background: #f1f5f9 !important;
    }

    /* Badges & Chips in Light Theme */
    [data-theme="light"] .badge {
      background: #f1f5f9 !important;
      color: #475569 !important;
      border: 1px solid #e2e8f0 !important;
    }

    [data-theme="light"] .revolut-chip {
      background: #f1f5f9 !important;
      border: 1px solid #e2e8f0 !important;
      color: #0f172a !important;
    }

    [data-theme="light"] .revolut-chip:hover {
      background: #e2e8f0 !important;
    }

    /* ==============================================================
       SYSTEM-WIDE HARMONIZATION & POLISH (Dark & Light)
       ============================================================== */

    /* Action Buttons in Hero Card - High Touch Target & Perfect Alignment */
    .hero-actions-grid, .revolut-actions-grid {
      display: grid !important;
      grid-template-columns: repeat(4, 1fr) !important;
      gap: 12px !important;
      margin-top: 22px !important;
      padding-top: 18px !important;
      border-top: 1px solid var(--border) !important;
      align-items: start !important;
    }

    .hero-action-btn, .revolut-action-btn {
      display: flex !important;
      flex-direction: column !important;
      align-items: center !important;
      justify-content: flex-start !important;
      background: transparent !important;
      border: none !important;
      cursor: pointer !important;
      color: var(--text) !important;
      text-decoration: none !important;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
      user-select: none !important;
      -webkit-tap-highlight-color: transparent !important;
      width: 100% !important;
      min-height: 84px !important;
      padding: 4px 2px !important;
    }

    .hero-action-icon, .revolut-action-icon {
      width: 52px !important;
      height: 52px !important;
      border-radius: 16px !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      margin-bottom: 8px !important;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
      flex-shrink: 0 !important;
    }

    .hero-action-btn span, .revolut-action-label {
      font-size: 13px !important;
      font-weight: 700 !important;
      letter-spacing: -0.01em !important;
      color: var(--text) !important;
      text-align: center !important;
      line-height: 1.25 !important;
      word-break: break-word !important;
      display: block !important;
    }

    /* Dark mode action button icons */
    [data-theme="dark"] .revolut-icon-expense {
      background: rgba(239, 68, 68, 0.16) !important;
      border: 1px solid rgba(239, 68, 68, 0.35) !important;
      color: #f87171 !important;
    }
    [data-theme="dark"] .revolut-icon-income {
      background: rgba(16, 185, 129, 0.16) !important;
      border: 1px solid rgba(16, 185, 129, 0.35) !important;
      color: #34d399 !important;
    }
    [data-theme="dark"] .revolut-icon-transfer {
      background: rgba(59, 130, 246, 0.16) !important;
      border: 1px solid rgba(59, 130, 246, 0.35) !important;
      color: #60a5fa !important;
    }
    [data-theme="dark"] .revolut-icon-goals {
      background: rgba(245, 158, 11, 0.16) !important;
      border: 1px solid rgba(245, 158, 11, 0.35) !important;
      color: #fbbf24 !important;
    }

    /* Hover interactions on buttons */
    .hero-action-btn:hover, .revolut-action-btn:hover {
      transform: translateY(-2px) !important;
    }
    .hero-action-btn:active, .revolut-action-btn:active {
      transform: translateY(0) scale(0.97) !important;
    }

    /* Month navigator light mode (Apple HIG) */
    [data-theme="light"] .month-navigator-bar {
      background: rgba(255, 255, 255, 0.88) !important;
      backdrop-filter: blur(20px) saturate(180%) !important;
      -webkit-backdrop-filter: blur(20px) saturate(180%) !important;
      border: 1px solid rgba(0, 0, 0, 0.08) !important;
      box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.06), 0 1px 2px rgba(0, 0, 0, 0.03) !important;
      color: #1c1c1e !important;
    }
    [data-theme="light"] .month-navigator-bar span {
      color: #1c1c1e !important;
    }

    /* Segmented transaction switcher in light theme */
    [data-theme="light"] .tx-type-segment-btn {
      background: #f1f5f9 !important;
      border: 1px solid #cbd5e1 !important;
      color: #475569 !important;
    }
    [data-theme="light"] .tx-type-segment-btn:hover {
      background: #e2e8f0 !important;
      color: #0f172a !important;
    }
    .tx-type-segment-btn.active-expense {
      background: #dc2626 !important;
      color: #ffffff !important;
      border-color: #dc2626 !important;
      box-shadow: 0 2px 8px rgba(220, 38, 38, 0.35) !important;
    }
    .tx-type-segment-btn.active-income {
      background: #16a34a !important;
      color: #ffffff !important;
      border-color: #16a34a !important;
      box-shadow: 0 2px 8px rgba(22, 163, 74, 0.35) !important;
    }

    /* Status indicator in light theme */
    [data-theme="light"] .status-indicator-btn {
      background: #ecfdf5 !important;
      border: 1px solid #a7f3d0 !important;
      color: #059669 !important;
    }
    [data-theme="light"] .status-indicator-btn:hover {
      background: #d1fae5 !important;
    }

    /* Family scope chip in light theme */
    [data-theme="light"] .family-scope-chip {
      background: #eff6ff !important;
      border: 1px solid #bfdbfe !important;
      color: #2563eb !important;
    }

    /* Quick input widget in light theme */
    [data-theme="light"] #dashQuickInput {
      background: #ffffff !important;
      border: 1px solid #cbd5e1 !important;
      color: #0f172a !important;
    }
    [data-theme="light"] #dashQuickInput:focus {
      border-color: #2563eb !important;
      box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15) !important;
    }
    [data-theme="light"] #dashQuickPreview {
      background: #f8fafc !important;
      border: 1px solid #e2e8f0 !important;
      color: #0f172a !important;
    }

    /* Hero secondary box and labels */
    [data-theme="light"] .hero-label {
      color: #64748b !important;
    }
    [data-theme="light"] .hero-badge-pill {
      background: #f1f5f9 !important;
      border: 1px solid #e2e8f0 !important;
      color: #475569 !important;
    }

    /* Mobile media query overrides for buttons */
    @media (max-width: 480px) {
      .hero-actions-grid, .revolut-actions-grid {
        gap: 8px !important;
        padding-top: 14px !important;
      }
      .hero-action-icon, .revolut-action-icon {
        width: 46px !important;
        height: 46px !important;
        border-radius: 14px !important;
        margin-bottom: 6px !important;
      }
      .hero-action-btn span, .revolut-action-label {
        font-size: 11px !important;
      }
      .hero-balance-val {
        font-size: 30px !important;
      }
      .hero-secondary-val {
        font-size: 22px !important;
      }
      .hero-secondary-balance-box {
        padding: 8px 12px !important;
      }
    }

    /* Light Theme Debit Card Surface */
    [data-theme="light"] .revolut-debit-card {
      background: linear-gradient(145deg, #1e293b 0%, #0f172a 100%) !important;
      border: 1px solid #cbd5e1 !important;
      color: #ffffff !important;
      box-shadow: 0 10px 25px -5px rgba(15, 23, 42, 0.25) !important;
    }

    /* Strict Light Theme Contrast Overrides for Header and Badges */
    [data-theme="light"] .status-indicator-btn {
      background: #ecfdf5 !important;
      border: 1px solid #6ee7b7 !important;
      color: #047857 !important;
      font-weight: 600 !important;
    }
    [data-theme="light"] .family-scope-chip {
      background: #eff6ff !important;
      border: 1px solid #93c5fd !important;
      color: #1d4ed8 !important;
      font-weight: 600 !important;
    }
    [data-theme="light"] .btn-icon-round {
      background: #f1f5f9 !important;
      border: 1px solid #cbd5e1 !important;
      color: #0f172a !important;
    }

    /* ==============================================================
       APPLE HIG MODERN DESIGN SYSTEM (Cards, Ledger Tables, Badges)
       ============================================================== */

    /* 1. CARDS: 22px Squircle, Apple Dark #1c1c1e / Light Pure White #ffffff */
    .card,
    .desktop-main-column .card,
    .desktop-widget-column .card,
    .accounts-card,
    .desktop-ledger-card,
    .analytics-card,
    .debt-card,
    .obligation-card,
    .goal-card,
    .envelope-card,
    .modal-overlay .card,
    [id^="modal"] .card,
    .bottom-sheet-card {
      border-radius: 22px !important;
      transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1),
                  box-shadow 0.2s cubic-bezier(0.16, 1, 0.3, 1),
                  border-color 0.2s ease,
                  background 0.2s ease;
    }

    /* Dark Mode Cards: #1c1c1e surface, 1px rgba(255,255,255,0.08) border */
    :root, [data-theme="dark"] {
      --card-bg: #1c1c1e !important;
      --card-radius: 22px !important;
      --border: rgba(255, 255, 255, 0.08) !important;
      --border-hover: rgba(255, 255, 255, 0.16) !important;
    }

    .card,
    .desktop-main-column .card,
    .desktop-widget-column .card,
    .accounts-card,
    .desktop-ledger-card,
    .analytics-card {
      background: #1c1c1e !important;
      border: 1px solid rgba(255, 255, 255, 0.08) !important;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35) !important;
      color: #ffffff;
    }

    .card:hover,
    .desktop-main-column .card:hover,
    .desktop-widget-column .card:hover {
      border-color: rgba(255, 255, 255, 0.16) !important;
      box-shadow: 0 8px 30px rgba(0, 0, 0, 0.5) !important;
    }

    /* Light Mode Cards: Pure White #ffffff surface with 1px border #e5e5ea, no muddy gray haze */
    [data-theme="light"] {
      --card-bg: #ffffff !important;
      --card-radius: 22px !important;
      --border: #e5e5ea !important;
      --border-hover: #d1d1d6 !important;
    }

    [data-theme="light"] .card,
    [data-theme="light"] .desktop-main-column .card,
    [data-theme="light"] .desktop-widget-column .card,
    [data-theme="light"] .accounts-card,
    [data-theme="light"] .desktop-ledger-card,
    [data-theme="light"] .analytics-card,
    [data-theme="light"] .modal-overlay .card,
    [data-theme="light"] [id^="modal"] .card,
    [data-theme="light"] .bottom-sheet-card {
      background: #ffffff !important;
      border: 1px solid #e5e5ea !important;
      border-top: 1px solid #e5e5ea !important;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.04) !important;
      color: #1c1c1e !important;
    }

    [data-theme="light"] .card:hover,
    [data-theme="light"] .desktop-main-column .card:hover,
    [data-theme="light"] .desktop-widget-column .card:hover {
      border-color: #d1d1d6 !important;
      box-shadow: 0 8px 28px rgba(0, 0, 0, 0.08) !important;
    }

    /* 2. TABLES: Apple Inset Grouped / List Table Style */
    table,
    .revolut-ledger-table,
    #txTable,
    #dashTxTable,
    .apple-table {
      width: 100%;
      border-collapse: separate !important;
      border-spacing: 0 !important;
      margin-top: 8px;
    }

    /* Apple List Header: 12px uppercase, text-muted, letter-spacing: 0.05em */
    th,
    table thead th,
    .revolut-ledger-table thead th {
      font-size: 12px !important;
      text-transform: uppercase !important;
      letter-spacing: 0.05em !important;
      font-weight: 600 !important;
      padding: 10px 16px !important;
      text-align: left;
      height: 38px;
      line-height: 1.2;
    }

    th,
    table thead th,
    .revolut-ledger-table thead th {
      color: #8e8e93 !important;
      border-bottom: 1px solid rgba(255, 255, 255, 0.08) !important;
      background: transparent !important;
    }

    [data-theme="light"] th,
    [data-theme="light"] table thead th,
    [data-theme="light"] .revolut-ledger-table thead th {
      color: #8e8e93 !important;
      border-bottom: 1px solid #e5e5ea !important;
      background: transparent !important;
    }

    /* Apple List Rows: 52px comfortable height, subtle bottom divider */
    table tbody tr,
    .revolut-ledger-table tbody tr {
      height: 52px !important;
      min-height: 52px !important;
      transition: background 0.15s ease;
    }

    table tbody td,
    .revolut-ledger-table tbody td,
    td {
      height: 52px !important;
      padding: 12px 16px !important;
      font-size: 14px;
      vertical-align: middle;
      border-top: none;
    }

    /* Dark Mode Table Rows & Dividers */
    table tbody td,
    .revolut-ledger-table tbody td {
      color: #ffffff;
      border-bottom: 1px solid rgba(255, 255, 255, 0.08) !important;
    }

    table tbody tr:hover td,
    .revolut-ledger-table tbody tr:hover td {
      background: rgba(255, 255, 255, 0.035) !important;
    }

    /* Light Mode Table Rows & Dividers */
    [data-theme="light"] table tbody td,
    [data-theme="light"] .revolut-ledger-table tbody td {
      color: #1c1c1e !important;
      border-bottom: 1px solid #e5e5ea !important;
    }

    [data-theme="light"] table tbody tr:hover td,
    [data-theme="light"] .revolut-ledger-table tbody tr:hover td {
      background: rgba(0, 0, 0, 0.02) !important;
    }

    /* Remove bottom divider from last row */
    table tbody tr:last-child td,
    .revolut-ledger-table tbody tr:last-child td {
      border-bottom: none !important;
    }

    /* Monospace Amounts: SF Mono / monospace tabular-nums, right-aligned */
    .amount-cell,
    td.amount-val,
    th.amount-header,
    .tx-amount,
    .table-amount {
      font-family: -apple-system-monospaced, "SF Mono", "SFProMono-Regular", "JetBrains Mono", Menlo, Consolas, monospace !important;
      font-variant-numeric: tabular-nums lining-nums !important;
      font-feature-settings: "tnum" 1 !important;
      text-align: right !important;
      white-space: nowrap !important;
      font-weight: 600 !important;
      font-size: 14px;
    }

    /* Amounts: Green (+) for Income, Dark/White (-) for Expense */
    /* Dark Mode Amounts */
    .amount-income,
    .is-income,
    .tx-income,
    td[style*="34d399"] {
      color: #30d158 !important; /* Apple Green Dark */
    }

    .amount-expense,
    .is-expense,
    .tx-expense,
    td[style*="f87171"] {
      color: #ffffff !important; /* Apple Dark Mode Expense: White */
    }

    /* Light Mode Amounts */
    [data-theme="light"] .amount-income,
    [data-theme="light"] .is-income,
    [data-theme="light"] .tx-income,
    [data-theme="light"] td[style*="34d399"] {
      color: #34c759 !important; /* Apple Green Light */
    }

    [data-theme="light"] .amount-expense,
    [data-theme="light"] .is-expense,
    [data-theme="light"] .tx-expense,
    [data-theme="light"] td[style*="f87171"] {
      color: #1c1c1e !important; /* Apple Light Mode Expense: Dark */
    }

    /* 3. CATEGORY CHIPS & BADGES: Rounded 9999px Pills */
    .badge,
    .chip,
    .revolut-chip,
    .family-scope-chip,
    .hero-badge-pill,
    .category-pill,
    .cat-badge {
      display: inline-flex !important;
      align-items: center !important;
      justify-content: center !important;
      gap: 6px !important;
      border-radius: 9999px !important;
      padding: 4px 12px !important;
      font-size: 12px !important;
      font-weight: 500 !important;
      line-height: 1.3 !important;
      white-space: nowrap !important;
      box-sizing: border-box !important;
      transition: all 0.15s ease !important;
    }

    /* Dark Mode: Deep Luminous Tints */
    .badge,
    .chip,
    .revolut-chip {
      background: #2c2c2e;
      color: #ffffff;
      border: 1px solid rgba(255, 255, 255, 0.10);
    }

    .revolut-chip:hover {
      background: #3a3a3c !important;
      border-color: rgba(255, 255, 255, 0.20) !important;
    }

    .badge-blue, .badge-info, .family-scope-chip {
      background: rgba(10, 132, 255, 0.18) !important;
      border: 1px solid rgba(10, 132, 255, 0.32) !important;
      color: #0a84ff !important;
    }

    .badge-green, .badge-success, .badge-income {
      background: rgba(48, 209, 88, 0.18) !important;
      border: 1px solid rgba(48, 209, 88, 0.32) !important;
      color: #30d158 !important;
    }

    .badge-red, .badge-danger, .badge-expense {
      background: rgba(255, 69, 58, 0.18) !important;
      border: 1px solid rgba(255, 69, 58, 0.32) !important;
      color: #ff453a !important;
    }

    .badge-warning, .badge-amber {
      background: rgba(255, 159, 10, 0.18) !important;
      border: 1px solid rgba(255, 159, 10, 0.32) !important;
      color: #ff9f0a !important;
    }

    .badge-purple {
      background: rgba(191, 90, 242, 0.18) !important;
      border: 1px solid rgba(191, 90, 242, 0.32) !important;
      color: #bf5af2 !important;
    }

    /* Light Mode: Soft Pastel Tints */
    [data-theme="light"] .badge,
    [data-theme="light"] .chip,
    [data-theme="light"] .revolut-chip {
      background: #f2f2f7 !important;
      border: 1px solid #e5e5ea !important;
      color: #1c1c1e !important;
    }

    [data-theme="light"] .revolut-chip:hover {
      background: #e5e5ea !important;
      border-color: #d1d1d6 !important;
    }

    [data-theme="light"] .badge-blue,
    [data-theme="light"] .badge-info,
    [data-theme="light"] .family-scope-chip {
      background: rgba(0, 122, 255, 0.10) !important;
      border: 1px solid rgba(0, 122, 255, 0.22) !important;
      color: #007aff !important;
    }

    [data-theme="light"] .badge-green,
    [data-theme="light"] .badge-success,
    [data-theme="light"] .badge-income {
      background: rgba(52, 199, 89, 0.12) !important;
      border: 1px solid rgba(52, 199, 89, 0.24) !important;
      color: #28cd41 !important;
    }

    [data-theme="light"] .badge-red,
    [data-theme="light"] .badge-danger,
    [data-theme="light"] .badge-expense {
      background: rgba(255, 59, 48, 0.10) !important;
      border: 1px solid rgba(255, 59, 48, 0.20) !important;
      color: #ff3b30 !important;
    }

    [data-theme="light"] .badge-warning,
    [data-theme="light"] .badge-amber {
      background: rgba(255, 149, 0, 0.12) !important;
      border: 1px solid rgba(255, 149, 0, 0.24) !important;
      color: #ff9500 !important;
    }

    [data-theme="light"] .badge-purple {
      background: rgba(175, 82, 222, 0.12) !important;
      border: 1px solid rgba(175, 82, 222, 0.24) !important;
      color: #af52de !important;
    }

    /* 4. WIDGET STAT AMOUNTS & INNER PANELS */
    .stat-val {
      font-family: -apple-system-monospaced, "SF Mono", "SFProMono-Regular", "JetBrains Mono", Menlo, Consolas, monospace !important;
      font-variant-numeric: tabular-nums lining-nums !important;
      font-feature-settings: "tnum" 1 !important;
      letter-spacing: -0.02em !important;
    }

    .stat-label {
      font-size: 11px !important;
      text-transform: uppercase !important;
      letter-spacing: 0.05em !important;
      font-weight: 600 !important;
      color: #8e8e93 !important;
    }

    [data-theme="light"] .stat-label {
      color: #8e8e93 !important;
    }

    .inner-panel-box,
    .debt-banking-block {
      border-radius: 14px !important;
    }

    /* ==============================================================
       MODAL NEW TRANSACTION SCREENSHOT DEFECT FIXES (Apple HIG)
       ============================================================== */

    /* Universal anti-artifact rules for modal text elements */
    #modalTxHeaderTitle,
    #modalTxCatSelectedName,
    #modalTxCatSelectedParent,
    #modalBtnSubmitLabel,
    #modalTxMsg,
    .category-dropdown-trigger span,
    .category-dropdown-trigger div {
      background: transparent !important;
      background-color: transparent !important;
      box-shadow: none !important;
    }

    /* 1. Hide ugly HTML5 number spinners */
    input[type="number"]::-webkit-outer-spin-button,
    input[type="number"]::-webkit-inner-spin-button {
      -webkit-appearance: none !important;
      margin: 0 !important;
    }
    input[type="number"] {
      -moz-appearance: textfield !important;
    }

    /* 2. Amount Input & Currency Sign (Perfect Apple HIG Layout) */
    .revolut-amount-wrapper {
      display: flex !important;
      align-items: center !important;
      justify-content: flex-start !important;
      border-radius: 16px !important;
      padding: 12px 18px !important;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
      min-height: 64px !important;
    }
    .revolut-amount-wrapper:focus-within {
      outline: none !important;
      border-color: #0071e3 !important;
      box-shadow: 0 0 0 3px rgba(0, 113, 227, 0.25) !important;
    }
    [data-theme="light"] .revolut-amount-wrapper {
      background: #ffffff !important;
      border: 1.5px solid #d1d1d6 !important;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04) !important;
    }
    [data-theme="dark"] .revolut-amount-wrapper {
      background: #2c2c2e !important;
      border: 1.5px solid rgba(255, 255, 255, 0.16) !important;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4) !important;
    }
    .revolut-amount-currency {
      font-size: 32px !important;
      font-weight: 700 !important;
      color: #ff3b30 !important;
      margin-right: 12px !important;
      line-height: 1 !important;
      user-select: none !important;
      flex-shrink: 0 !important;
    }
    .revolut-amount-currency.currency-income {
      color: #34c759 !important;
    }
    .revolut-amount-input {
      font-size: 36px !important;
      font-weight: 700 !important;
      background: transparent !important;
      border: none !important;
      outline: none !important;
      width: 100% !important;
      padding: 0 !important;
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", system-ui, sans-serif !important;
      font-variant-numeric: tabular-nums lining-nums !important;
      font-feature-settings: "tnum" 1 !important;
      line-height: 1 !important;
    }
    [data-theme="light"] .revolut-amount-input {
      color: #1d1d1f !important;
    }
    [data-theme="dark"] .revolut-amount-input {
      color: #f5f5f7 !important;
    }
    .revolut-amount-input::placeholder {
      color: #8e8e93 !important;
      opacity: 0.6 !important;
    }

    /* 3. Category Selector Box (#modalTxCatTrigger) - 100% Readable */
    .category-dropdown-trigger {
      display: flex !important;
      align-items: center !important;
      justify-content: space-between !important;
      border-radius: 14px !important;
      padding: 12px 16px !important;
      cursor: pointer !important;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
      user-select: none !important;
      min-height: 54px !important;
    }
    [data-theme="light"] .category-dropdown-trigger,
    [data-theme="light"] #modalTxCatTrigger {
      background: #ffffff !important;
      border: 1.5px solid #d1d1d6 !important;
      color: #1d1d1f !important;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04) !important;
    }
    [data-theme="light"] .category-dropdown-trigger:hover,
    [data-theme="light"] #modalTxCatTrigger:hover {
      background: #f2f2f7 !important;
      border-color: #0071e3 !important;
    }
    [data-theme="dark"] .category-dropdown-trigger,
    [data-theme="dark"] #modalTxCatTrigger {
      background: #2c2c2e !important;
      border: 1px solid rgba(255, 255, 255, 0.14) !important;
      color: #f5f5f7 !important;
    }
    [data-theme="dark"] .category-dropdown-trigger:hover,
    [data-theme="dark"] #modalTxCatTrigger:hover {
      background: #3a3a3c !important;
      border-color: #0071e3 !important;
    }
    #modalTxCatSelectedName {
      font-size: 15px !important;
      font-weight: 600 !important;
      line-height: 1.25 !important;
    }
    [data-theme="light"] #modalTxCatSelectedName {
      color: #1d1d1f !important;
    }
    [data-theme="dark"] #modalTxCatSelectedName {
      color: #f5f5f7 !important;
    }
    #modalTxCatSelectedParent {
      font-size: 12px !important;
      font-weight: 500 !important;
      line-height: 1.2 !important;
      margin-top: 2px !important;
    }
    [data-theme="light"] #modalTxCatSelectedParent {
      color: #86868b !important;
    }
    [data-theme="dark"] #modalTxCatSelectedParent {
      color: #8e8e93 !important;
    }

    /* 4. Large CTA Submit Button (Clean Apple HIG Action) */
    .revolut-cta-btn,
    #modalBtnSubmitTx {
      width: 100% !important;
      padding: 15px 20px !important;
      font-size: 16px !important;
      font-weight: 600 !important;
      border-radius: 14px !important;
      letter-spacing: -0.01em !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      gap: 8px !important;
      background: #ff3b30 !important;
      color: #ffffff !important;
      border: none !important;
      cursor: pointer !important;
      box-shadow: 0 4px 16px rgba(255, 59, 48, 0.3) !important;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
      -webkit-tap-highlight-color: transparent !important;
      min-height: 52px !important;
    }
    .revolut-cta-btn.cta-income,
    #modalBtnSubmitTx.cta-income {
      background: #34c759 !important;
      box-shadow: 0 4px 16px rgba(52, 199, 89, 0.3) !important;
    }
    .revolut-cta-btn:hover,
    #modalBtnSubmitTx:hover {
      transform: translateY(-1px) !important;
      filter: brightness(1.06) !important;
    }
    .revolut-cta-btn:active,
    #modalBtnSubmitTx:active {
      transform: scale(0.98) !important;
      filter: brightness(0.96) !important;
    }
    #modalBtnSubmitLabel {
      color: #ffffff !important;
      font-weight: 600 !important;
      font-size: 16px !important;
      background: transparent !important;
    }

    /* 1. Hide ugly HTML5 number spinners */
    input[type="number"]::-webkit-outer-spin-button,
    input[type="number"]::-webkit-inner-spin-button {
      -webkit-appearance: none !important;
      margin: 0 !important;
    }
    input[type="number"] {
      -moz-appearance: textfield !important;
    }

    /* 2. Amount Input & Currency Sign (Perfect Apple HIG Layout) */
    .revolut-amount-wrapper {
      display: flex !important;
      align-items: center !important;
      justify-content: flex-start !important;
      border-radius: 16px !important;
      padding: 12px 18px !important;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
      min-height: 64px !important;
    }
    .revolut-amount-wrapper:focus-within {
      outline: none !important;
      border-color: #0071e3 !important;
      box-shadow: 0 0 0 3px rgba(0, 113, 227, 0.25) !important;
    }
    [data-theme="light"] .revolut-amount-wrapper {
      background: #ffffff !important;
      border: 1.5px solid #d1d1d6 !important;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04) !important;
    }
    [data-theme="dark"] .revolut-amount-wrapper {
      background: #2c2c2e !important;
      border: 1.5px solid rgba(255, 255, 255, 0.16) !important;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4) !important;
    }
    .revolut-amount-currency {
      font-size: 32px !important;
      font-weight: 700 !important;
      color: #ff3b30 !important;
      margin-right: 12px !important;
      line-height: 1 !important;
      user-select: none !important;
      flex-shrink: 0 !important;
    }
    .revolut-amount-currency.currency-income {
      color: #34c759 !important;
    }
    .revolut-amount-input {
      font-size: 36px !important;
      font-weight: 700 !important;
      background: transparent !important;
      border: none !important;
      outline: none !important;
      width: 100% !important;
      padding: 0 !important;
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", system-ui, sans-serif !important;
      font-variant-numeric: tabular-nums lining-nums !important;
      font-feature-settings: "tnum" 1 !important;
      line-height: 1 !important;
    }
    [data-theme="light"] .revolut-amount-input {
      color: #1d1d1f !important;
    }
    [data-theme="dark"] .revolut-amount-input {
      color: #f5f5f7 !important;
    }
    .revolut-amount-input::placeholder {
      color: #8e8e93 !important;
      opacity: 0.6 !important;
    }

    /* 3. Category Selector Box (#modalTxCatTrigger) - 100% Readable */
    .category-dropdown-trigger {
      display: flex !important;
      align-items: center !important;
      justify-content: space-between !important;
      border-radius: 14px !important;
      padding: 12px 16px !important;
      cursor: pointer !important;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
      user-select: none !important;
      min-height: 54px !important;
    }
    [data-theme="light"] .category-dropdown-trigger {
      background: #f5f5f7 !important;
      border: 1px solid #d1d1d6 !important;
      color: #1d1d1f !important;
    }
    [data-theme="light"] .category-dropdown-trigger:hover {
      background: #e5e5ea !important;
      border-color: #0071e3 !important;
    }
    [data-theme="dark"] .category-dropdown-trigger {
      background: #2c2c2e !important;
      border: 1px solid rgba(255, 255, 255, 0.14) !important;
      color: #f5f5f7 !important;
    }
    [data-theme="dark"] .category-dropdown-trigger:hover {
      background: #3a3a3c !important;
      border-color: #0071e3 !important;
    }
    #modalTxCatSelectedName {
      font-size: 15px !important;
      font-weight: 600 !important;
      line-height: 1.25 !important;
    }
    [data-theme="light"] #modalTxCatSelectedName {
      color: #1d1d1f !important;
    }
    [data-theme="dark"] #modalTxCatSelectedName {
      color: #f5f5f7 !important;
    }
    #modalTxCatSelectedParent {
      font-size: 12px !important;
      font-weight: 500 !important;
      line-height: 1.2 !important;
      margin-top: 2px !important;
    }
    [data-theme="light"] #modalTxCatSelectedParent {
      color: #6e6e73 !important;
    }
    [data-theme="dark"] #modalTxCatSelectedParent {
      color: #8e8e93 !important;
    }

    /* 4. Large CTA Submit Button (Clean Apple HIG Action) */
    .revolut-cta-btn,
    #modalBtnSubmitTx {
      width: 100% !important;
      padding: 15px 20px !important;
      font-size: 16px !important;
      font-weight: 600 !important;
      border-radius: 14px !important;
      letter-spacing: -0.01em !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      gap: 8px !important;
      background: #ff3b30 !important;
      color: #ffffff !important;
      border: none !important;
      cursor: pointer !important;
      box-shadow: 0 4px 16px rgba(255, 59, 48, 0.3) !important;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
      -webkit-tap-highlight-color: transparent !important;
      min-height: 52px !important;
    }
    .revolut-cta-btn.cta-income,
    #modalBtnSubmitTx.cta-income {
      background: #34c759 !important;
      box-shadow: 0 4px 16px rgba(52, 199, 89, 0.3) !important;
    }
    .revolut-cta-btn:hover,
    #modalBtnSubmitTx:hover {
      transform: translateY(-1px) !important;
      filter: brightness(1.06) !important;
    }
    .revolut-cta-btn:active,
    #modalBtnSubmitTx:active {
      transform: scale(0.98) !important;
      filter: brightness(0.96) !important;
    }
    #modalBtnSubmitLabel {
      color: #ffffff !important;
      font-weight: 600 !important;
      font-size: 16px !important;
    }

    /* 5. Date Picker Indicator Styling */
    input[type="date"]::-webkit-calendar-picker-indicator {
      cursor: pointer !important;
      opacity: 0.7 !important;
      transition: opacity 0.15s ease !important;
    }
    input[type="date"]::-webkit-calendar-picker-indicator:hover {
      opacity: 1 !important;
    }

    /* 6. Quick Amount Chips (+100, +500, +1000) */
    .revolut-chips-row {
      display: flex !important;
      gap: 8px !important;
      flex-wrap: wrap !important;
      margin-bottom: 14px !important;
    }
    .revolut-chip {
      flex: 1 !important;
      min-width: 65px !important;
      padding: 9px 12px !important;
      border-radius: 12px !important;
      font-size: 13px !important;
      font-weight: 600 !important;
      cursor: pointer !important;
      text-align: center !important;
      transition: all 0.15s cubic-bezier(0.16, 1, 0.3, 1) !important;
    }
    [data-theme="light"] .revolut-chip {
      background: #ffffff !important;
      border: 1px solid #d1d1d6 !important;
      color: #1d1d1f !important;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04) !important;
    }
    [data-theme="light"] .revolut-chip:hover {
      background: #f2f2f7 !important;
      border-color: #0071e3 !important;
    }
    [data-theme="dark"] .revolut-chip {
      background: #2c2c2e !important;
      border: 1px solid rgba(255, 255, 255, 0.12) !important;
      color: #f5f5f7 !important;
    }
    [data-theme="dark"] .revolut-chip:hover {
      background: #3a3a3c !important;
      border-color: rgba(255, 255, 255, 0.25) !important;
    }
    .revolut-chip:active {
      transform: scale(0.96) !important;
    }

    /* FamilyOS workspace: common surfaces, readable hierarchy, local system fonts. */
    :root, :root[data-theme="dark"], [data-theme="dark"] {
      --bg: #151b1c !important;
      --bg-gradient: none !important;
      --bg-secondary: #1c2425 !important;
      --card-bg: #1e2728 !important;
      --card-hover: #283334 !important;
      --input-bg: #192122 !important;
      --modal-bg: #1e2728 !important;
      --box-bg: #253132 !important;
      --border: #354344 !important;
      --border-subtle: #354344 !important;
      --border-hover: #4e6766 !important;
      --text: #edf3f0 !important;
      --text-muted: #a9bab5 !important;
      --text-soft: #c5d2cd !important;
      --primary: #73c5b1 !important;
      --primary-hover: #8bd4c2 !important;
      --primary-accent: #73c5b1 !important;
      --primary-gradient: linear-gradient(#73c5b1,#73c5b1) !important;
      --border-focus: #73c5b1 !important;
      --success: #7bd1a5 !important;
      --danger: #ffa19b !important;
      --warning: #e8c080 !important;
      --workspace-accent-ink: #102f29;
      --workspace-tint: #263d38;
      --workspace-shadow: 0 2px 8px rgba(0,0,0,.10);
    }
    :root[data-theme="light"], [data-theme="light"] {
      --bg: #f4f3ee !important;
      --bg-secondary: #fafaf7 !important;
      --card-bg: #fffefa !important;
      --card-hover: #eeefea !important;
      --input-bg: #fffefa !important;
      --modal-bg: #fffefa !important;
      --box-bg: #eeefea !important;
      --border: #d7ddd5 !important;
      --border-subtle: #d7ddd5 !important;
      --border-hover: #a6b9ae !important;
      --text: #203731 !important;
      --text-muted: #607269 !important;
      --text-soft: #425b50 !important;
      --primary: #286654 !important;
      --primary-hover: #1d5142 !important;
      --primary-accent: #286654 !important;
      --primary-gradient: linear-gradient(#286654,#286654) !important;
      --border-focus: #286654 !important;
      --success: #246c46 !important;
      --danger: #a23d38 !important;
      --warning: #8c601e !important;
      --workspace-accent-ink: #ffffff;
      --workspace-tint: #e7f0e9;
      --workspace-shadow: 0 2px 8px rgba(32,55,49,.035);
    }
    html { min-height: 100%; scroll-padding-bottom: 100px; }
    html body {
      height: auto !important; min-height: 100vh !important;
      overflow-y: auto !important; background: var(--bg) !important;
      background-image: none !important; color: var(--text) !important;
      font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, sans-serif !important;
      line-height: 1.5;
    }
    :root[data-theme] body { background: var(--bg) !important; background-image: none !important; color: var(--text) !important; }
    body .container { max-width: 1480px !important; padding: 24px 32px 96px !important; }
    body .header { padding: 0 0 20px !important; margin-bottom: 16px !important; border-bottom: 1px solid var(--border); }
    body .brand-title { color: var(--text) !important; font-size: 22px !important; font-weight: 700 !important; }
    body .brand-tag { color: var(--text-muted) !important; letter-spacing: .025em; }
    body .brand-icon, body .family-scope-chip {
      background: var(--workspace-tint) !important; color: var(--primary) !important;
      border: 1px solid var(--border) !important; box-shadow: none !important;
    }
    :root[data-theme] body .header { background: var(--bg) !important; backdrop-filter: none !important; }
    :root[data-theme] body .brand-title { color: var(--text) !important; }
    :root[data-theme] body .brand-tag { color: var(--text-muted) !important; }
    :root[data-theme] body .brand-icon, :root[data-theme] body .family-scope-chip { background: var(--workspace-tint) !important; color: var(--primary) !important; border: 1px solid var(--border) !important; box-shadow: none !important; }
    :root[data-theme] body .brand-logo-svg { color: var(--primary) !important; stroke: currentColor !important; }
    body .btn-icon-circle, body .privacy-mask-pill, body .status-indicator-btn {
      background: var(--card-bg) !important; border: 1px solid var(--border) !important;
      color: var(--text) !important; box-shadow: none !important; min-height: 40px;
    }
    body #mainDashboard { min-width: 0; height: auto !important; overflow: visible !important; }
    body #mainDashboard > [id^="tab-"] { min-width: 0; padding-top: 4px; }
    body #mainDashboard .card, body .modal-overlay .card, body [id^="modal"] .card, body .bottom-sheet-card {
      background: var(--card-bg) !important; color: var(--text) !important;
      border: 1px solid var(--border) !important; border-radius: 18px !important;
      box-shadow: var(--workspace-shadow) !important;
    }
    body #mainDashboard .card { padding: 22px !important; }
    body #mainDashboard .card:hover { border-color: var(--border) !important; box-shadow: var(--workspace-shadow) !important; transform: none !important; }
    body #mainDashboard :is(h1,h2,h3,h4), body .modal-overlay :is(h2,h3,h4) { color: var(--text) !important; letter-spacing: -.018em; }
    body #mainDashboard > [id^="tab-"] > .card > h3,
    body #mainDashboard > [id^="tab-"] > .card > div:first-child h3,
    body #mainDashboard #tab-debts > div:first-child h3 { font-size: 21px !important; line-height: 1.3; }
    body #mainDashboard p, body #mainDashboard .stat-label { color: var(--text-muted) !important; }
    body #mainDashboard .stat-label { font-size: 12px !important; font-weight: 600; letter-spacing: .025em; text-transform: none !important; }
    body #mainDashboard .stat-val { font-size: clamp(19px,2vw,27px) !important; line-height: 1.3; margin-top: 8px; color: var(--text) !important; overflow-wrap: anywhere; }
    body #mainDashboard .stat-val.success { color: var(--success) !important; }
    body #mainDashboard .stat-val.danger { color: var(--danger) !important; }
    body #mainDashboard .stat-val.warning { color: var(--warning) !important; }
    body #mainDashboard .stat-val.purple, body #mainDashboard .stat-val.primary { color: var(--primary) !important; }
    body #mainDashboard .grid-3 { gap: 16px !important; }
    body #mainDashboard .grid-3 > .card { background: var(--bg-secondary) !important; box-shadow: none !important; }
    body #mainDashboard .btn, body .modal-overlay .btn, body [id^="modal"] .btn {
      min-height: 40px; border-radius: 10px !important; font-weight: 600 !important;
      background: var(--primary) !important; color: var(--workspace-accent-ink) !important;
      border: 1px solid transparent !important; box-shadow: none !important;
      transition: background .15s ease, border-color .15s ease !important;
    }
    body #mainDashboard .btn-secondary, body .modal-overlay .btn-secondary, body [id^="modal"] .btn-secondary {
      background: var(--card-hover) !important; color: var(--text) !important;
      border: 1px solid var(--border) !important;
    }
    body #mainDashboard .btn-danger { background: var(--danger) !important; color: var(--bg) !important; }
    body #mainDashboard .btn:hover { filter: brightness(1.06); transform: none !important; }
    body #mainDashboard .btn-secondary:hover { border-color: var(--border-hover) !important; background: var(--workspace-tint) !important; }
    body #mainDashboard :is(button,a,input,select,textarea,[tabindex]):focus-visible,
    body .modal-overlay :is(button,input,select,textarea):focus-visible {
      outline: 3px solid var(--primary) !important; outline-offset: 3px !important;
    }
    body #mainDashboard button:disabled { opacity: .5; cursor: not-allowed !important; }
    body #mainDashboard input, body #mainDashboard select, body #mainDashboard textarea,
    body .modal-overlay input, body .modal-overlay select, body .modal-overlay textarea {
      min-width: 0; max-width: 100%; background: var(--input-bg) !important; color: var(--text) !important;
      border: 1px solid var(--border) !important; border-radius: 10px !important; box-shadow: none !important;
    }
    body #mainDashboard input:not([type="checkbox"]):not([type="radio"]), body #mainDashboard select { min-height: 44px; }
    body #mainDashboard input::placeholder, body #mainDashboard textarea::placeholder { color: var(--text-muted) !important; opacity: 1; }
    body #mainDashboard label { color: var(--text-soft) !important; }
    body #mainDashboard .form-group { min-width: 0; margin-bottom: 18px; }
    body #mainDashboard .month-navigator-bar {
      padding: 12px 18px !important; border-radius: 12px !important; background: var(--card-bg) !important;
      border: 1px solid var(--border) !important; box-shadow: none !important; backdrop-filter: none !important;
      margin-bottom: 14px !important; flex-wrap: wrap !important;
    }
    body #mainDashboard .month-navigator-bar span { color: var(--text) !important; }
    body #mainDashboard .month-navigator-label { font-weight: 500 !important; font-size: 13px !important; }
    body #mainDashboard .month-chevron-btn { min-height: 40px; min-width: 40px; background: var(--card-hover) !important; color: var(--text) !important; border: 1px solid var(--border) !important; border-radius: 9px !important; }
    body #mainDashboard .nav-tabs-wrapper { gap: 8px; margin-bottom: 22px !important; }
    body #mainDashboard .nav-tabs {
      border: 1px solid var(--border) !important; border-radius: 12px !important;
      background: var(--bg-secondary) !important; padding: 5px !important; gap: 4px !important;
      margin-bottom: 0 !important; box-shadow: none !important; backdrop-filter: none !important;
      touch-action: pan-x pan-y; scroll-padding: 8px;
    }
    body #mainDashboard .nav-tabs .tab-btn { min-height: 42px; padding: 9px 14px !important; color: var(--text-muted) !important; background: transparent !important; border: 1px solid transparent !important; font-size: 13px !important; border-radius: 8px !important; }
    body #mainDashboard .nav-tabs .tab-btn:hover { background: var(--card-hover) !important; color: var(--text) !important; }
    body #mainDashboard .nav-tabs .tab-btn.active { color: var(--primary) !important; background: var(--workspace-tint) !important; box-shadow: none !important; border: 1px solid var(--border) !important; font-weight: 700 !important; }
    body #mainDashboard .nav-tab-scroll-btn { width: 40px; height: 44px; color: var(--text) !important; background: var(--card-bg) !important; border: 1px solid var(--border) !important; box-shadow: none !important; border-radius: 10px; }
    body #mainDashboard .desktop-dashboard-grid { display: block !important; }
    body #mainDashboard .desktop-widget-column { position: static !important; top: auto !important; margin-top: 20px !important; }
    body #mainDashboard .desktop-main-column, body #mainDashboard .desktop-widget-column { min-width: 0 !important; }
    body #mainDashboard .appetite-hero-card.revolut-hero-card {
      background: var(--card-bg) !important; background-image: none !important;
      border: 1px solid var(--border) !important; border-top: 1px solid var(--border) !important;
      border-radius: 20px !important; padding: 28px !important; color: var(--text) !important;
      box-shadow: var(--workspace-shadow) !important; overflow: visible !important;
    }
    body #mainDashboard .appetite-hero-card::before, body #mainDashboard .appetite-hero-card::after { display: none !important; }
    body #mainDashboard .hero-balance-header-row { align-items: start !important; gap: 24px !important; }
    body #mainDashboard .hero-primary-balance-box { flex: 1; min-width: 0; }
    body #mainDashboard .hero-label { color: var(--text-muted) !important; font-size: 13px !important; font-weight: 600 !important; text-transform: none !important; letter-spacing: .01em !important; }
    body #mainDashboard .hero-balance-val { color: var(--text) !important; font-family: "Segoe UI",sans-serif !important; font-size: clamp(32px,3.5vw,49px) !important; font-weight: 650 !important; letter-spacing: -.045em !important; line-height: 1.15 !important; margin: 12px 0 !important; overflow-wrap: anywhere; }
    body #mainDashboard .hero-balance-val .badge { font-family: "Segoe UI",sans-serif !important; font-size: 11px !important; letter-spacing: 0 !important; line-height: 1.4 !important; vertical-align: middle; white-space: normal !important; }
    body #mainDashboard #valSafeToSpend .badge { background: var(--danger) !important; color: var(--bg) !important; border-color: transparent !important; }
    body #mainDashboard .hero-badge-pill { background: transparent !important; color: var(--text-muted) !important; border: none !important; padding: 0 !important; white-space: normal !important; font-size: 12px !important; justify-content: start !important; }
    body #mainDashboard .hero-secondary-balance-box { flex: 0 1 220px; padding: 16px !important; border-radius: 12px !important; border: 1px solid var(--border) !important; background: var(--bg-secondary) !important; text-align: left !important; align-items: start !important; min-width: 0; box-shadow: none !important; }
    body #mainDashboard .hero-secondary-label, body #mainDashboard .hero-secondary-pill { color: var(--text-muted) !important; font-size: 11px !important; }
    body #mainDashboard .hero-secondary-val { color: var(--text) !important; font-size: 24px !important; font-weight: 650 !important; margin: 6px 0; overflow-wrap: anywhere; }
    body #mainDashboard .hero-actions-grid { grid-template-columns: repeat(4,minmax(0,1fr)) !important; gap: 8px !important; padding-top: 20px !important; margin-top: 24px !important; align-items: stretch !important; }
    body #mainDashboard .hero-action-btn.revolut-action-btn { padding: 12px 8px !important; min-height: 76px !important; gap: 8px; border: 1px solid var(--border) !important; border-radius: 12px !important; background: var(--bg-secondary) !important; justify-content: center !important; }
    body #mainDashboard .hero-action-btn.revolut-action-btn:hover { transform: none !important; background: var(--workspace-tint) !important; border-color: var(--border-hover) !important; }
    body #mainDashboard .hero-action-icon { width: 24px !important; height: 24px !important; margin: 0 !important; padding: 0 !important; border: none !important; background: transparent !important; box-shadow: none !important; border-radius: 0 !important; color: var(--text) !important; }
    body #mainDashboard .hero-action-icon svg { width: 21px; height: 21px; }
    body #mainDashboard .hero-action-btn .revolut-icon-expense { color: var(--danger) !important; }
    body #mainDashboard .hero-action-btn .revolut-icon-income { color: var(--success) !important; }
    body #mainDashboard .hero-action-btn .revolut-icon-transfer, body #mainDashboard .hero-action-btn .revolut-icon-goals { color: var(--primary) !important; }
    body #mainDashboard .hero-action-btn span { color: var(--text) !important; font-size: 12px !important; font-weight: 600 !important; }
    body #mainDashboard .quick-entry-card { background: var(--bg-secondary) !important; }
    body #mainDashboard .core-financial-cards { grid-template-columns: minmax(0,1fr) minmax(0,1.15fr) !important; gap: 16px !important; }
    body #mainDashboard .appetite-debit-card { background: #25483f !important; background-image: none !important; color: #f0f6ef !important; border: 1px solid #436458 !important; border-radius: 16px !important; box-shadow: none !important; padding: 22px !important; min-width: 0; }
    body #mainDashboard .appetite-card-sheen { display: none; }
    body #mainDashboard #valLiquid { overflow-wrap: anywhere; }
    body #mainDashboard .period-pills { display: flex; flex-wrap: wrap; gap: 8px; margin: 0 0 20px; padding: 0; }
    body #mainDashboard .pill-btn {
      min-height: 44px; padding: 10px 16px; border-radius: 10px; border: 1px solid var(--border);
      background: var(--card-bg); color: var(--text-soft); font: 600 13px/1.3 "Segoe UI",sans-serif;
      cursor: pointer; transition: background .15s ease,border-color .15s ease;
    }
    body #mainDashboard .pill-btn:hover { border-color: var(--border-hover); background: var(--card-hover); color: var(--text); }
    body #mainDashboard .pill-btn.active, body #mainDashboard .pill-btn[aria-pressed="true"] { background: var(--primary); border-color: var(--primary); color: var(--workspace-accent-ink); }
    body #mainDashboard .pill-btn:disabled { opacity: .45; cursor: not-allowed; }
    body #mainDashboard .badge { background: var(--workspace-tint) !important; color: var(--text-soft) !important; border: 1px solid var(--border) !important; }
    body #mainDashboard .progress-bar-bg { background: var(--card-hover) !important; overflow: hidden; border-radius: 10px !important; }
    body #mainDashboard #goalsListContainer { grid-template-columns: repeat(auto-fit,minmax(min(100%,340px),1fr)) !important; gap: 18px !important; }
    body #mainDashboard #goalsListContainer > .card { padding: 24px !important; border-radius: 14px !important; }
    body #mainDashboard #goalsListContainer .progress-bar-bg { height: 10px !important; margin: 12px 0; }
    body #mainDashboard #envelopesListContainer { grid-template-columns: repeat(auto-fit,minmax(min(100%,290px),1fr)) !important; gap: 16px !important; }
    body #mainDashboard #envelopesListContainer > .card { background: var(--bg-secondary) !important; border-radius: 12px !important; padding: 20px !important; border-top: 1px solid var(--border) !important; box-shadow: none !important; }
    body #mainDashboard #debtsListContainer > .card { border-radius: 12px !important; padding: 24px !important; }
    body #mainDashboard #debtsListContainer > .card > div:first-child { border-bottom: 1px solid var(--border); padding-bottom: 14px; margin-bottom: 16px !important; }
    body #mainDashboard #dashEnvelopesContainer { grid-template-columns: minmax(0,1fr) !important; }
    body #mainDashboard #dashGoalsContainer > div, body #mainDashboard #dashEnvelopesContainer > div { min-width: 0; border-radius: 10px !important; }
    body #mainDashboard #dashGoalsContainer, body #mainDashboard #dashEnvelopesContainer { gap: 14px !important; }
    body #mainDashboard #tab-tx > .card { max-width: 900px; margin-inline: auto; }
    body #mainDashboard #tab-tx #txAmount { color: var(--text) !important; font-size: 28px !important; min-height: 60px; }
    body #mainDashboard .category-dropdown-trigger, body #mainDashboard .category-dropdown-menu { background: var(--card-bg) !important; border-color: var(--border) !important; color: var(--text) !important; }
    body #mainDashboard .tx-type-segment-group { gap: 8px; background: var(--bg-secondary) !important; padding: 5px; border-radius: 12px; }
    body #mainDashboard .tx-type-segment-btn { min-height: 44px; background: transparent !important; color: var(--text-muted) !important; border: 1px solid transparent !important; }
    body #mainDashboard .tx-type-segment-btn.active-expense { border-color: var(--danger) !important; color: var(--danger) !important; background: var(--card-bg) !important; }
    body #mainDashboard .tx-type-segment-btn.active-income { border-color: var(--success) !important; color: var(--success) !important; background: var(--card-bg) !important; }
    body #mainDashboard #divNewObligation { background: var(--bg-secondary) !important; border-style: dashed !important; }
    body #mainDashboard #obligationsListContainer > div { border-radius: 10px !important; }
    body #mainDashboard #tab-analytics > .card:last-child { border-color: var(--border-hover) !important; }
    body #mainDashboard #tab-analytics > div[style*="grid-template-columns"] { grid-template-columns: repeat(auto-fit,minmax(min(100%,310px),1fr)) !important; }
    body #mainDashboard #tab-analytics > .grid-3 { grid-template-columns: repeat(auto-fit,minmax(min(100%,210px),1fr)) !important; }
    body #mainDashboard #tab-analytics .card h3 { flex-wrap: wrap; gap: 8px; }
    body #mainDashboard #tab-analytics div:has(> #btnForecast30) { flex-wrap: wrap; }
    body #mainDashboard .chart-box { background: var(--bg-secondary) !important; border: 1px solid var(--border) !important; border-radius: 12px !important; }
    body #mainDashboard #donutChartContainer svg text { fill: var(--text-muted) !important; }
    body #mainDashboard #donutChartContainer svg text:last-child { fill: var(--text) !important; }
    body #mainDashboard #donutChartContainer svg circle[stroke="#1e293b"], body #mainDashboard #donutChartContainer svg circle[stroke="#334155"] { stroke: var(--card-hover) !important; }
    body #mainDashboard #cashFlowChartSvg svg text { fill: var(--text-muted) !important; }
    body #mainDashboard #cashFlowChartSvg svg text[fill="#f87171"] { fill: var(--danger) !important; }
    body #mainDashboard table { color: var(--text) !important; }
    body #mainDashboard table th { color: var(--text-muted) !important; background: var(--bg-secondary) !important; font-size: 11px !important; letter-spacing: .03em !important; border-color: var(--border) !important; }
    body #mainDashboard table td { color: var(--text) !important; border-color: var(--border) !important; font-size: 13px; }
    body #mainDashboard table tbody tr:hover td { background: var(--card-hover) !important; }
    body .mobile-bottom-nav { background: var(--card-bg) !important; border-color: var(--border) !important; box-shadow: none !important; }
    body .mobile-nav-item { color: var(--text-muted) !important; }
    body .mobile-nav-item.active { color: var(--primary) !important; }
    @media(min-width:1180px) {
      body #mainDashboard .desktop-dashboard-grid { display: grid !important; grid-template-columns: minmax(0,1fr) 330px !important; gap: 22px !important; align-items: start !important; }
      body #mainDashboard .desktop-main-column { display: flex !important; flex-direction: column !important; }
      body #mainDashboard .desktop-widget-column { display: flex !important; flex-direction: column !important; margin-top: 0 !important; }
    }
    @media(max-width:1179px) {
      body #mainDashboard .desktop-main-column, body #mainDashboard .desktop-widget-column { display: block !important; }
      body #mainDashboard .hero-secondary-balance-box { flex-basis: 230px; }
    }
    @media(max-width:767px) {
      body .container { padding: 16px 16px 100px !important; }
      body .header { flex-wrap: wrap !important; gap: 14px; }
      body #mainDashboard .appetite-hero-card.revolut-hero-card { padding: 22px !important; }
      body #mainDashboard .hero-balance-header-row { flex-direction: column !important; gap: 18px !important; }
      body #mainDashboard .hero-secondary-balance-box { flex-basis: auto; width: 100%; display: block !important; }
      body #mainDashboard .hero-secondary-val { font-size: 22px !important; }
      body #mainDashboard .core-financial-cards { grid-template-columns: minmax(0,1fr) !important; }
      body #mainDashboard .month-navigator-bar { padding: 12px !important; }
      body #mainDashboard .nav-tabs-wrapper { gap: 5px !important; }
      body #mainDashboard .nav-tab-scroll-btn { width: 32px; min-width: 32px; }
      body #mainDashboard .nav-tabs .tab-btn { padding-inline: 10px !important; }
      body #mainDashboard .grid-3 { grid-template-columns: repeat(2,minmax(0,1fr)) !important; }
    }
    @media(max-width:600px) {
      body #mainDashboard .card { padding: 18px !important; }
      body #mainDashboard #tab-overview .hero-actions-grid { grid-template-columns: repeat(2,minmax(0,1fr)) !important; }
      body #mainDashboard #tab-overview .hero-action-btn { min-height: 64px !important; flex-direction: row !important; }
      body #mainDashboard #goalsListContainer, body #mainDashboard #envelopesListContainer { grid-template-columns: minmax(0,1fr) !important; }
      body #mainDashboard #tab-accounts div[style*="grid-template-columns"],
      body #mainDashboard #tab-obligations div[style*="grid-template-columns"],
      body #mainDashboard #tab-debts div[style*="grid-template-columns"],
      body #mainDashboard #tab-tx div[style*="grid-template-columns"],
      body #mainDashboard #onboardingBanner div[style*="grid-template-columns"] { grid-template-columns: minmax(0,1fr) !important; }
      body #mainDashboard .quick-entry-card > div[style*="display: flex"], body #mainDashboard .quick-input-bar { flex-wrap: wrap !important; }
      body #mainDashboard #dashQuickInput { flex: 1 1 100% !important; width: 100%; }
      body #mainDashboard .quick-input-bar > input { order: 3; }
      body #mainDashboard #dashCatMenu { min-width: min(290px,calc(100vw - 70px)) !important; max-width: calc(100vw - 70px); }
      body #mainDashboard .period-pills { gap: 6px; }
      body #mainDashboard .period-pills .pill-btn { flex: 1 1 130px; padding-inline: 10px; }
      body #mainDashboard #tab-analytics .grid-3 { grid-template-columns: minmax(0,1fr) !important; }
      body #mainDashboard #tab-tx .form-group > div { flex-wrap: wrap; gap: 8px; }
      body #mainDashboard #tab-tx .form-group > div > div { flex-wrap: wrap; }
      body #mainDashboard .category-dropdown-trigger { gap: 8px; flex-wrap: wrap; }
      body #mainDashboard #debtsListContainer > .card, body #mainDashboard #goalsListContainer > .card { padding: 18px !important; }
      body #mainDashboard #goalsListContainer > .card > div:first-child > div:first-child { flex-wrap: wrap; gap: 10px; }
      body #mainDashboard #envelopesListContainer > .card > div:first-child { flex-wrap: wrap; gap: 8px; }
      body #mainDashboard #tab-analytics table { table-layout: fixed; }
      body #mainDashboard #tab-analytics table th, body #mainDashboard #tab-analytics table td { padding: 9px 6px !important; font-size: 11px !important; white-space: normal; overflow-wrap: anywhere; }
    }
    @media(prefers-reduced-motion:reduce) {
      body #mainDashboard *, body .modal-overlay * { scroll-behavior: auto !important; transition: none !important; animation: none !important; }
    }

    /* Complete account list: seven fixed-height rows, all accounts retained. */
    .accounts-list-viewport {
      --account-row-height: 84px;
      box-sizing: border-box;
      max-height: calc(7 * var(--account-row-height) + 2px);
      overflow-y: auto;
      overflow-x: hidden;
      -webkit-overflow-scrolling: touch;
      scrollbar-gutter: stable;
      border-block: 1px solid var(--border);
      border-radius: 8px;
    }
    .accounts-list-viewport:focus-visible,
    .account-list-name:focus-visible {
      outline: 2px solid var(--primary);
      outline-offset: -2px;
    }
    .account-list-hint {
      margin: -4px 0 14px;
      color: var(--text-muted);
      font-size: 12px;
      line-height: 1.5;
    }
    .accounts-list { min-width: 0; }
    .account-list-row {
      box-sizing: border-box;
      height: var(--account-row-height);
      min-width: 0;
      padding: 12px 8px;
      display: flex;
      flex-direction: column;
      justify-content: center;
      gap: 6px;
      border-bottom: 1px solid var(--border);
    }
    .account-list-row:last-child { border-bottom: 0; }
    .account-list-row:hover { background: var(--box-bg); }
    .account-list-identity { min-width: 0; }
    .account-list-name, .account-list-meta {
      display: block;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      line-height: 1.35;
    }
    .account-list-name { color: var(--text); font-size: 14px; font-weight: 600; }
    .account-list-meta { color: var(--text-muted); font-size: 11px; margin-top: 2px; }
    .account-list-amount {
      align-self: flex-end;
      color: var(--text);
      font-size: 14px;
      font-weight: 600;
      line-height: 1.3;
      font-variant-numeric: tabular-nums;
      white-space: nowrap;
    }
    .account-list-empty { padding: 18px 8px; color: var(--text-muted); }
    .manage-accounts-table td { overflow-wrap: anywhere; }
    @media (min-width: 1280px) {
      .account-list-row { flex-direction: row; align-items: center; justify-content: space-between; gap: 16px; }
      .account-list-identity { flex: 1; }
      .account-list-amount { align-self: center; flex-shrink: 0; }
    }
    @media (max-width: 600px) {
      .account-list-amount { font-size: 12px; letter-spacing: -0.02em; }
      .manage-accounts-table, .manage-accounts-table tbody { display: block; width: 100%; }
      .manage-accounts-table thead { display: none; }
      .manage-accounts-table tbody tr {
        display: block;
        height: auto !important;
        padding: 12px 0;
        border-bottom: 1px solid var(--border);
      }
      .manage-accounts-table tbody td {
        display: grid;
        grid-template-columns: minmax(0, 0.75fr) minmax(0, 1.25fr);
        gap: 10px;
        height: auto !important;
        min-height: 32px;
        padding: 6px 0 !important;
        border-bottom: 0 !important;
        text-align: right;
        font-size: 12px;
      }
      .manage-accounts-table td::before {
        content: attr(data-label);
        color: var(--text-muted);
        text-align: left;
      }
      .manage-accounts-table td button { min-height: 40px; }
    }

    /* Confirmed responsive QA fixes: payments, alerts, and wide numeric metrics. */
    body #mainDashboard .core-financial-cards > div:last-child { min-width: 0; }
    body #mainDashboard .stat-label { overflow-wrap: anywhere; }
    :root[data-theme="light"] body #mainDashboard [style*="color: #34d399"],
    :root[data-theme="light"] body #mainDashboard [style*="color:#34d399"],
    :root[data-theme="light"] body #mainDashboard [style*="color: #10b981"],
    :root[data-theme="light"] body #mainDashboard [style*="color:#10b981"] { color: var(--success) !important; }
    :root[data-theme="light"] body #mainDashboard [style*="color: #38bdf8"],
    :root[data-theme="light"] body #mainDashboard [style*="color:#38bdf8"],
    :root[data-theme="light"] body #mainDashboard [style*="color: #60a5fa"],
    :root[data-theme="light"] body #mainDashboard [style*="color:#60a5fa"],
    :root[data-theme="light"] body #mainDashboard [style*="color: #c084fc"] { color: var(--primary) !important; }
    :root[data-theme="light"] body #mainDashboard [style*="color: #f87171"],
    :root[data-theme="light"] body #mainDashboard [style*="color:#f87171"],
    :root[data-theme="light"] body #mainDashboard [style*="color: #ef4444"],
    :root[data-theme="light"] body #mainDashboard [style*="color:#ef4444"] { color: var(--danger) !important; }
    :root[data-theme="light"] body #mainDashboard [style*="color: #fbbf24"],
    :root[data-theme="light"] body #mainDashboard [style*="color:#fbbf24"],
    :root[data-theme="light"] body #mainDashboard [style*="color: #f59e0b"],
    :root[data-theme="light"] body #mainDashboard [style*="color:#f59e0b"] { color: var(--warning) !important; }
    @media (max-width: 900px) {
      body #mainDashboard .core-financial-cards > div:last-child { grid-template-columns: minmax(0,1fr) !important; }
      body #mainDashboard .core-financial-cards .stat-val { white-space: nowrap; font-size: clamp(18px,5vw,27px) !important; overflow-wrap: normal; }
      body #mainDashboard #forecastDeficitAlert { flex-wrap: wrap; align-items: flex-start !important; }
      body #mainDashboard #forecastDeficitAlert > div { min-width: 0; flex: 1 1 180px; }
      body #mainDashboard #forecastDeficitBadge { white-space: nowrap; }
      body #mainDashboard #dashGoalsCard > div:first-child,
      body #mainDashboard #dashEnvelopesCard > div:first-child { flex-wrap: wrap; gap: 12px; }
      body #mainDashboard #dashGoalsCard > div:first-child > div { flex-wrap: wrap; }
      body #mainDashboard #dashGoalsCard h3 { min-width: 0; }
      body #mainDashboard #debtsListContainer .badge { white-space: normal !important; max-width: 100%; overflow-wrap: anywhere; }
      body #mainDashboard #debtsListContainer > .card > div:first-child { flex-wrap: wrap; gap: 10px; }
      body #mainDashboard #debtsListContainer > .card > div:first-child > div { min-width: 0; max-width: 100%; flex-wrap: wrap; }
      body #mainDashboard #tab-obligations .obligations-table,
      body #mainDashboard #tab-obligations .obligations-table tbody { display: block; width: 100%; min-width: 0; }
      body #mainDashboard #tab-obligations .obligations-table thead { display: none; }
      body #mainDashboard #tab-obligations .obligations-table tr { display: block; height: auto !important; padding: 16px 0; border-bottom: 1px solid var(--border); }
      body #mainDashboard #tab-obligations .obligations-table td { display: grid; grid-template-columns: 80px minmax(0,1fr); gap: 12px; height: auto !important; min-height: 32px; padding: 6px 0 !important; border: 0 !important; overflow-wrap: anywhere; }
      body #mainDashboard #tab-obligations .obligations-table td::before { content: attr(data-label); color: var(--text-muted); font-size: 12px; font-weight: 400; }
      body #mainDashboard #tab-obligations .obligations-table td > div { flex-wrap: wrap; }
      body #mainDashboard #tab-obligations .obligations-table td .badge { justify-self: start; }
    }
    @media (max-width: 600px) {
      body #mainDashboard #tab-envelopes .grid-3,
      body #mainDashboard #tab-debts .grid-3 { grid-template-columns: minmax(0,1fr) !important; }
      body #mainDashboard #tab-envelopes .grid-3 p { overflow-wrap: anywhere; }
    }

  </style>

</head>

<body>

  <div class="container">

    <div class="header">
      <div class="brand-block">
        <div class="brand-logo" onclick="switchTab('tab-overview')">
          <div class="brand-icon" aria-label="FamilyOS">
            <!-- Apple HIG Geometric Mark: Concentric Financial Shields + Interconnected Family & Capital Circles -->
            <svg class="brand-logo-svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <!-- Outer Vault Shield -->
              <path d="M12 2.5C12 2.5 19.5 5.5 19.5 5.5C19.5 5.5 19.5 12 19.5 12C19.5 16.8 16.3 20.2 12 21.5C7.7 20.2 4.5 16.8 4.5 12C4.5 12 4.5 5.5 4.5 5.5C4.5 5.5 12 2.5 12 2.5Z" />
              <!-- Concentric Inner Protection Shield -->
              <path d="M12 6C12 6 17 8 17 8C17 8 17 12 17 12C17 15.2 14.8 17.6 12 18.5C9.2 17.6 7 15.2 7 12C7 12 7 8 7 8C7 8 12 6 12 6Z" stroke-width="1.2" stroke-opacity="0.65" />
              <!-- Interconnected Family Nodes -->
              <circle cx="10" cy="12" r="2.2" stroke-width="1.3" />
              <circle cx="14" cy="12" r="2.2" stroke-width="1.3" />
              <!-- Shared Capital Core -->
              <circle cx="12" cy="12" r="0.75" fill="currentColor" />
            </svg>
          </div>
          <div class="brand-text">
            <span class="brand-title">FamilyOS</span>
            <span class="brand-tag">Семейный бюджет</span>
          </div>
        </div>
        <div class="family-scope-chip" title="Текущий режим: общий семейный бюджет">
          <span>👨‍👩‍👧</span>
          <span>Вся семья</span>
        </div>
      </div>

      <div class="header-actions">
        <!-- 1. Privacy Mask Toggle Button: Clean iOS-Style Pill with Eye Icon -->
        <button id="btnPrivacyToggle" class="privacy-mask-pill hidden" onclick="togglePrivacyMask()" title="Скрыть/показать суммы (режим приватности)">
          <span id="privacyIcon">👁️</span>
          <span class="desktop-only-text">Маска</span>
        </button>

        <!-- 2. Status Indicator: Clean iOS System Pill (Green Dot + 'Локально AES-256') -->
        <button id="btnStatusIndicator" class="status-indicator-btn hidden" onclick="openSettingsModal()" title="Система защищена AES-256 • Данные хранятся локально">
          <span class="status-dot"></span>
          <span class="status-dot-label desktop-only-text">Локально AES-256</span>
        </button>

        <!-- 3. Theme Toggle: Clean iOS Circular Icon Button ('☀️' / '🌙') -->
        <button id="themeToggleBtn" class="btn-icon-circle" onclick="toggleTheme()" title="Переключить тему оформления" aria-label="Переключить тему">
          <span id="themeToggleIcon" style="font-size: 15px; line-height: 1;">☀️</span>
          <span id="themeToggleText" style="display: none;">Светлая</span>
        </button>

        <!-- 4. Settings Button: Clean iOS Circular Button with SF-Style Gear Icon -->
        <button id="btnOpenSettings" class="btn-icon-circle hidden" onclick="openSettingsModal()" title="Настройки и безопасность" aria-label="Настройки">
          <svg class="header-gear-svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="3"></circle>
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
          </svg>
        </button>
      </div>
    </div>

    <!-- Modal: Unified Settings & Security Sheet -->
    <div id="settingsModal" class="hidden" style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.75); backdrop-filter: blur(6px); z-index: 10000; display: flex; align-items: center; justify-content: center; padding: 16px;">
      <div class="card settings-sheet" style="max-width: 500px; width: 100%; border-color: rgba(255,255,255,0.12); position: relative; max-height: 90vh; overflow-y: auto; padding: 22px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; border-bottom: 1px solid var(--border); padding-bottom: 12px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 20px;">⚙️</span>
            <h3 style="margin: 0; font-size: 18px; font-weight: 700;">Настройки и безопасность</h3>
          </div>
          <button class="btn btn-secondary" onclick="closeSettingsModal()" style="padding: 4px 10px; font-size: 14px; border-radius: 50%;">✕</button>
        </div>

        <!-- Section 1: User & Family Context -->
        <div class="settings-section">
          <div class="settings-section-title">👤 Профиль и семейный доступ</div>
          <div style="background: var(--card-hover); border: 1px solid var(--border); border-radius: 12px; padding: 12px 14px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
            <div style="display: flex; align-items: center; gap: 10px;">
              <div style="width: 38px; height: 38px; border-radius: 50%; background: var(--primary-gradient); display: flex; align-items: center; justify-content: center; font-size: 18px; color: #fff;">
                👑
              </div>
              <div>
                <div style="font-weight: 700; font-size: 14px;" id="settingsUserName">Глава семьи</div>
                <div style="font-size: 11px; color: var(--text-muted);" id="settingsUserRole">Администратор (admin)</div>
              </div>
            </div>
            <button class="btn btn-secondary" id="btnLogout" onclick="logout()" style="padding: 6px 12px; font-size: 12px; color: #ef4444; border-color: rgba(239,68,68,0.3);">
              🚪 Выйти
            </button>
          </div>
          <button class="btn btn-secondary" id="btnHeaderQrPair" onclick="closeSettingsModal(); openQrPairModal();" style="width: 100%; display: flex; align-items: center; justify-content: center; gap: 8px; font-size: 13px;">
            📱 Подключить телефон супруги (QR-код)
          </button>
        </div>

        <!-- Section 2: Security & Protection -->
        <div class="settings-section">
          <div class="settings-section-title">🛡️ Защита данных и шифрование</div>
          <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 12px; padding: 12px 14px; margin-bottom: 10px; font-size: 12px; line-height: 1.5;">
            <div style="font-weight: 700; color: #34d399; margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
              <span>🔒</span> <span>100% Локально и зашифровано</span>
            </div>
            <div style="color: var(--text-muted);">
              База защищена шифрованием <strong style="color: var(--text);">AES-256-GCM</strong> (PBKDF2 600 000 итераций). Ни один сторонний сервер не имеет доступа к вашим чекам и балансам.
            </div>
            <div style="margin-top: 8px; display: flex; gap: 6px; flex-wrap: wrap;">
              <span class="badge" id="storageBadge" style="font-size: 10px; padding: 2px 8px;">AES-256-GCM / Память</span>
              <span class="badge" id="offlineModeBadge" style="background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); font-size: 10px; padding: 2px 8px;">🏠 100% Локально</span>
              <span class="badge hidden" id="syncBadge" style="font-size: 10px; padding: 2px 8px;">📡 P2P: 0 пиров</span>
            </div>
          </div>
          <button class="btn btn-secondary" id="btnHeaderLock" onclick="closeSettingsModal(); submitLock();" style="width: 100%; display: flex; align-items: center; justify-content: center; gap: 8px; font-size: 13px; color: #fbbf24; border-color: rgba(251,191,36,0.3);">
            🔒 Заблокировать экран мастер-паролем
          </button>
        </div>

        <!-- Section 3: Vault & Backup Storage -->
        <div class="settings-section">
          <div class="settings-section-title">💾 Резервные копии и хранилище</div>
          <div id="settingsVaultInfo" style="margin-bottom: 8px;"></div>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 8px;">
            <button class="btn btn-secondary" onclick="syncVaultNow(); updateSettingsModalInfo();" style="display: flex; align-items: center; justify-content: center; gap: 6px; font-size: 12px; padding: 8px;">
              🔄 Сохранить в память
            </button>
            <button class="btn btn-secondary" onclick="downloadVaultBackup()" style="display: flex; align-items: center; justify-content: center; gap: 6px; font-size: 12px; padding: 8px;">
              📥 Скачать .db
            </button>
          </div>
          <label class="btn btn-secondary" style="width: 100%; display: flex; align-items: center; justify-content: center; gap: 6px; font-size: 12px; padding: 8px; cursor: pointer; margin-bottom: 0;">
            📂 Восстановить из файла .db
            <input type="file" id="settingsVaultFileInput" accept=".db,.sqlite,.sqlite3" style="display: none;" onchange="restoreVaultFromFile(this.files[0])">
          </label>
          <span class="badge hidden" id="localVaultBadge" onclick="openVaultModal()"><span id="vaultTime"></span></span>
        </div>

        <!-- Section 4: Preferences & App Install -->
        <div class="settings-section" style="margin-bottom: 0;">
          <div class="settings-section-title">📱 Установка на телефон</div>
          <button class="btn btn-secondary" id="btnInstallPwa" onclick="installPwaPrompt()" style="width: 100%; display: flex; align-items: center; justify-content: center; gap: 8px; font-size: 12px; background: rgba(30, 58, 138, 0.4); color: #93c5fd; border-color: rgba(59, 130, 246, 0.4);">
            📥 Установить приложение на телефон (PWA)
          </button>
        </div>
      </div>
    </div>

    <!-- Modal: Local Phone Database Vault -->
    <div id="vaultModal" class="hidden" style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.85); z-index: 9999; display: flex; align-items: center; justify-content: center; padding: 16px;">
      <div class="card" style="max-width: 440px; width: 100%; border-color: #6366f1; position: relative; max-height: 90vh; overflow-y: auto;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
          <h3 style="margin: 0; font-size: 17px; display: flex; align-items: center; gap: 8px;">💾 Хранилище на телефоне</h3>
          <button class="btn btn-secondary" onclick="closeVaultModal()" style="padding: 2px 8px; font-size: 14px;">✕</button>
        </div>
        <div id="vaultStatusInfo"></div>
        <div style="display: flex; flex-direction: column; gap: 8px;">
          <button class="btn btn-primary" onclick="syncVaultNow()" style="width: 100%; display: flex; align-items: center; justify-content: center; gap: 8px;">
            🔄 Сохранить базу в память сейчас
          </button>
          <button class="btn btn-secondary" onclick="downloadVaultBackup()" style="width: 100%; display: flex; align-items: center; justify-content: center; gap: 8px;">
            📥 Скачать файл (.db) на телефон
          </button>
          <label class="btn btn-secondary" style="width: 100%; display: flex; align-items: center; justify-content: center; gap: 8px; cursor: pointer; margin-bottom: 0;">
            📂 Восстановить из файла (.db)
            <input type="file" id="vaultFileInput" accept=".db,.sqlite,.sqlite3" style="display: none;" onchange="restoreVaultFromFile(this.files[0])">
          </label>
        </div>
      </div>
    </div>

    <!-- Modal: QR-Code Pairing for Smartphones -->

    <div id="modalQrPair" class="hidden" style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.85); z-index: 9999; display: flex; align-items: center; justify-content: center; padding: 16px;">

      <div class="card" style="max-width: 440px; width: 100%; text-align: center; border-color: #10b981; position: relative; max-height: 90vh; overflow-y: auto;">

        <button onclick="closeQrPairModal()" style="position: absolute; top: 12px; right: 14px; background: transparent; border: none; color: #94a3b8; font-size: 22px; cursor: pointer;">✕</button>

        <div style="font-size: 32px; margin-bottom: 6px;">📱</div>

        <h3 style="font-size: 18px; font-weight: 700; color: var(--text); margin-bottom: 6px;">Подключение смартфона</h3>

        <p style="color: #94a3b8; font-size: 13px; margin-bottom: 16px; line-height: 1.4;">

          Отсканируйте QR-код штатной камерой iPhone или Android для мгновенного входа в семейную систему.

        </p>

        <!-- QR SVG Container -->

        <div id="qrPairSvgBox" style="background: #ffffff; padding: 10px; border-radius: 12px; display: inline-block; box-shadow: 0 4px 20px rgba(0,0,0,0.5); margin-bottom: 14px; min-width: 220px; min-height: 220px;">

          <div style="color: #64748b; font-size: 13px; padding-top: 90px;">Генерация QR-кода...</div>

        </div>

        <!-- Pairing URL with copy button -->

        <div style="margin-bottom: 14px; background: var(--card-hover); padding: 8px 12px; border-radius: 8px; border: 1px solid var(--border); display: flex; align-items: center; gap: 8px;">

          <input type="text" id="qrPairUrlInput" readonly style="background: transparent; border: none; color: #38bdf8; font-family: monospace; font-size: 12px; flex: 1; outline: none;" value="..." />

          <button class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="copyQrPairUrl()">Копировать</button>

        </div>

        <!-- IP Override if needed (e.g. running localhost or multi-network) -->

        <div style="background: rgba(255,255,255,0.03); border-radius: 8px; padding: 10px; margin-bottom: 14px; text-align: left; font-size: 12px;">

          <div style="color: var(--text-muted); font-weight: 600; margin-bottom: 4px;">Сетевой адрес компьютера:</div>

          <div style="display: flex; gap: 6px; align-items: center;">

            <input type="text" id="qrPairOverrideIp" placeholder="192.168.1.XX" style="background: var(--input-bg); border: 1px solid var(--border); color: var(--text); border-radius: 6px; padding: 6px 10px; flex: 1; font-family: monospace; font-size: 12px;" />

            <button class="btn btn-secondary" style="padding: 6px 10px; font-size: 12px;" onclick="regenerateQrPair()">Обновить QR</button>

          </div>

          <div style="color: #64748b; font-size: 11px; margin-top: 4px;">Если телефон не открывает страницу, убедитесь что телефон и ПК подключены к одной Wi-Fi сети.</div>

        </div>

        <div style="text-align: left; font-size: 12px; color: #94a3b8; border-top: 1px solid var(--border); padding-top: 12px; line-height: 1.5;">

          <div style="font-weight: 600; color: var(--text); margin-bottom: 4px;">Инструкция по установке (PWA):</div>

          <div>1. Наведите камеру телефона на QR-код и откройте ссылку.</div>

          <div>2. В браузере нажмите кнопку <b>«Поделиться»</b> (iOS) или меню <b>⋮</b> (Android).</div>

          <div>3. Выберите <b>«На экран 'Домой'»</b> — приложение установится как полноценная нативная программа без адресной строки!</div>

        </div>

      </div>

    </div>

    <!-- Modal: Create / Edit Envelope (Конверт-копилка) -->

    <div id="modalEnvelope" class="hidden" style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.85); z-index: 9999; display: flex; align-items: center; justify-content: center; padding: 16px;">

      <div class="card" style="max-width: 460px; width: 100%; border-color: #3b82f6; position: relative; max-height: 90vh; overflow-y: auto;">

        <button onclick="closeEnvelopeModal()" style="position: absolute; top: 12px; right: 14px; background: transparent; border: none; color: #94a3b8; font-size: 22px; cursor: pointer;">✕</button>

        <h3 id="envelopeModalTitle" style="font-size: 17px; font-weight: 700; color: var(--text); margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">

          <span>✉️</span> <span>Новый конверт-копилка</span>

        </h3>

        <div id="envelopeModalMsg"></div>

        <input type="hidden" id="envelopeEditId" value="">

        <div class="form-group">

          <label>Название конверта-копилки:</label>

          <input type="text" id="envelopeInputName" placeholder="Например: Отпуск на море, На чёрный день, Подарки, Авто">

        </div>

        <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 10px;">

          <div class="form-group">

            <label>Целевая сумма (₽, опционально):</label>

            <input type="number" step="0.01" id="envelopeInputTarget" placeholder="0.00 (или без ограничения)">

          </div>

          <div class="form-group">

            <label>Иконка:</label>

            <select id="envelopeInputIcon">

              <option value="✉️">✉️ Конверт</option>

              <option value="🐷">🐷 Копилка</option>

              <option value="🏖️">🏖️ Отпуск</option>

              <option value="🛡️">🛡️ Резерв</option>

              <option value="🚗">🚗 Авто</option>

              <option value="🏠">🏠 Жильё</option>

              <option value="🎁">🎁 Подарки</option>

              <option value="💻">💻 Техника</option>

              <option value="👶">👶 Дети</option>

              <option value="👗">👗 Одежда</option>

            </select>

          </div>

        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">

          <div class="form-group">

            <label>Цвет карточки:</label>

            <select id="envelopeInputColor">

              <option value="#3b82f6">🔵 Синий</option>

              <option value="#10b981">🟢 Изумрудный</option>

              <option value="#f59e0b">🟡 Янтарный</option>

              <option value="#ec4899">🌸 Розовый</option>

              <option value="#8b5cf6">🟣 Фиолетовый</option>

              <option value="#06b6d4">🌊 Бирюзовый</option>

            </select>

          </div>

          <div class="form-group">

            <label id="envelopeInitialLabel">Начальный баланс (₽):</label>

            <input type="number" step="0.01" id="envelopeInputInitial" placeholder="0.00" value="0">

          </div>

        </div>

        <div class="form-group">

          <label>Счет физического хранения (опционально):</label>

          <select id="envelopeInputAccount"></select>

        </div>

        <div class="form-group">

          <label>Заметка / Назначение:</label>

          <input type="text" id="envelopeInputNote" placeholder="Например: Откладывать по 5 000 ₽ с каждого аванса">

        </div>

        <div style="display: flex; gap: 10px; margin-top: 14px;">

          <button class="btn btn-success" style="flex: 1;" onclick="submitSaveEnvelope()">💾 Сохранить конверт</button>

          <button class="btn btn-secondary" onclick="closeEnvelopeModal()">Отмена</button>

        </div>

      </div>

    </div>

    <!-- Modal: Deposit into Envelope (Положить в конверт) -->

    <div id="modalEnvelopeDeposit" class="hidden" style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.85); z-index: 9999; display: flex; align-items: center; justify-content: center; padding: 16px;">

      <div class="card" style="max-width: 440px; width: 100%; border-color: #10b981; position: relative; max-height: 90vh; overflow-y: auto;">

        <button onclick="closeEnvelopeDepositModal()" style="position: absolute; top: 12px; right: 14px; background: transparent; border: none; color: #94a3b8; font-size: 22px; cursor: pointer;">✕</button>

        <h3 style="font-size: 17px; font-weight: 700; color: var(--text); margin-bottom: 6px; display: flex; align-items: center; gap: 8px;">

          <span>💰</span> <span id="envDepositTitle">Положить в конверт-копилку</span>

        </h3>

        <p id="envDepositCurrentBal" style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;"></p>

        <div id="envDepositMsg"></div>

        <input type="hidden" id="envDepositId" value="">

        <div class="form-group">

          <label>Счет списания (Откуда перевести):</label>

          <select id="envDepositSourceAccount"></select>

        </div>

        <div class="form-group">

          <label>Сумма пополнения (₽):</label>

          <input type="number" step="0.01" id="envDepositAmount" placeholder="1000.00" style="font-size: 18px; font-weight: 700; color: #34d399;">

        </div>

        <div style="display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 14px;">

          <button type="button" class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="addEnvDepositAmount(500)">+500 ₽</button>

          <button type="button" class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="addEnvDepositAmount(1000)">+1 000 ₽</button>

          <button type="button" class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="addEnvDepositAmount(5000)">+5 000 ₽</button>

          <button type="button" class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="addEnvDepositAmount(10000)">+10 000 ₽</button>

        </div>

        <div class="form-group">

          <label>Комментарий / примечание:</label>

          <input type="text" id="envDepositNote" placeholder="Пополнение копилки">

        </div>

        <div style="display: flex; gap: 10px; margin-top: 14px;">

          <button class="btn btn-success" style="flex: 1;" onclick="submitEnvelopeDeposit()">📥 Положить в конверт</button>

          <button class="btn btn-secondary" onclick="closeEnvelopeDepositModal()">Отмена</button>

        </div>

      </div>

    </div>

    <!-- Modal: Withdraw from Envelope (Взять из конверта) -->

    <div id="modalEnvelopeWithdraw" class="hidden" style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.85); z-index: 9999; display: flex; align-items: center; justify-content: center; padding: 16px;">

      <div class="card" style="max-width: 440px; width: 100%; border-color: #f59e0b; position: relative; max-height: 90vh; overflow-y: auto;">

        <button onclick="closeEnvelopeWithdrawModal()" style="position: absolute; top: 12px; right: 14px; background: transparent; border: none; color: #94a3b8; font-size: 22px; cursor: pointer;">✕</button>

        <h3 style="font-size: 17px; font-weight: 700; color: var(--text); margin-bottom: 6px; display: flex; align-items: center; gap: 8px;">

          <span>📤</span> <span id="envWithdrawTitle">Взять из конверта-копилки</span>

        </h3>

        <p id="envWithdrawCurrentBal" style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;"></p>

        <div id="envWithdrawMsg"></div>

        <input type="hidden" id="envWithdrawId" value="">

        <div class="form-group">

          <label>Счет зачисления (Куда вернуть средства):</label>

          <select id="envWithdrawDestAccount"></select>

        </div>

        <div class="form-group">

          <label>Сумма списания (₽):</label>

          <input type="number" step="0.01" id="envWithdrawAmount" placeholder="1000.00" style="font-size: 18px; font-weight: 700; color: #f59e0b;">

        </div>

        <div style="display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 14px;">

          <button type="button" class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="setEnvWithdrawAll()">Вся сумма</button>

          <button type="button" class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="addEnvWithdrawAmount(1000)">+1 000 ₽</button>

          <button type="button" class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="addEnvWithdrawAmount(5000)">+5 000 ₽</button>

        </div>

        <div class="form-group">

          <label>Причина изъятия / расход:</label>

          <input type="text" id="envWithdrawNote" placeholder="Например: Покупка билетов, подарок">

        </div>

        <div style="display: flex; gap: 10px; margin-top: 14px;">

          <button class="btn btn-warning" style="flex: 1;" onclick="submitEnvelopeWithdraw()">📤 Изъять из конверта</button>

          <button class="btn btn-secondary" onclick="closeEnvelopeWithdrawModal()">Отмена</button>

        </div>

      </div>

    </div>

    <!-- Modal: Transfer between Envelopes (Переложить между конвертами) -->

    <div id="modalEnvelopeTransfer" class="hidden" style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.85); z-index: 9999; display: flex; align-items: center; justify-content: center; padding: 16px;">

      <div class="card" style="max-width: 440px; width: 100%; border-color: #8b5cf6; position: relative; max-height: 90vh; overflow-y: auto;">

        <button onclick="closeEnvelopeTransferModal()" style="position: absolute; top: 12px; right: 14px; background: transparent; border: none; color: #94a3b8; font-size: 22px; cursor: pointer;">✕</button>

        <h3 style="font-size: 17px; font-weight: 700; color: var(--text); margin-bottom: 6px; display: flex; align-items: center; gap: 8px;">

          <span>🔄</span> <span>Переложить между конвертами</span>

        </h3>

        <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">Перемещение накоплений из одного конверта-копилки в другой.</p>

        <div id="envTransferMsg"></div>

        <div class="form-group">

          <label>Из какого конверта взять:</label>

          <select id="envTransferFromSelect" onchange="onEnvTransferFromChanged()"></select>

        </div>

        <div id="envTransferAvailInfo" style="font-size: 12px; color: var(--text-muted); margin-top: -6px; margin-bottom: 10px;"></div>

        <div class="form-group">

          <label>В какой конверт переложить:</label>

          <select id="envTransferToSelect"></select>

        </div>

        <div class="form-group">

          <label>Сумма перевода (₽):</label>

          <input type="number" step="0.01" id="envTransferAmount" placeholder="1000.00" style="font-size: 18px; font-weight: 700; color: #a78bfa;">

        </div>

        <div class="form-group">

          <label>Примечание:</label>

          <input type="text" id="envTransferNote" placeholder="Перераспределение копилок">

        </div>

        <div style="display: flex; gap: 10px; margin-top: 14px;">

          <button class="btn btn-primary" style="flex: 1;" onclick="submitEnvelopeTransfer()">🔄 Переложить средства</button>

          <button class="btn btn-secondary" onclick="closeEnvelopeTransferModal()">Отмена</button>

        </div>

      </div>

    </div>

    <!-- Modal: Create / Edit Financial Goal -->

    <div id="modalGoal" class="hidden" style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.85); z-index: 9999; display: flex; align-items: center; justify-content: center; padding: 16px;">

      <div class="card" style="max-width: 480px; width: 100%; border-color: #10b981; position: relative; max-height: 90vh; overflow-y: auto;">

        <button onclick="closeGoalModal()" style="position: absolute; top: 12px; right: 14px; background: transparent; border: none; color: #94a3b8; font-size: 22px; cursor: pointer;">✕</button>

        <h3 id="goalModalTitle" style="font-size: 17px; font-weight: 700; color: var(--text); margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">

          <span>🎯</span> <span>Новая цель накоплений</span>

        </h3>

        <div id="goalModalMsg"></div>

        <input type="hidden" id="goalEditId" value="">

        <div class="form-group">

          <label>Название цели:</label>

          <input type="text" id="goalInputName" placeholder="Например: Подушка безопасности, Отпуск, Ремонт">

        </div>

        <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 10px;">

          <div class="form-group">

            <label>Целевая сумма (₽):</label>

            <input type="number" step="0.01" id="goalInputTarget" placeholder="100000.00">

          </div>

          <div class="form-group">

            <label>Иконка:</label>

            <select id="goalInputIcon">

              <option value="🎯">🎯 Мишень</option>

              <option value="🛡️">🛡️ Резерв</option>

              <option value="🏖️">🏖️ Отпуск</option>

              <option value="🚗">🚗 Авто</option>

              <option value="🏠">🏠 Жилье</option>

              <option value="💻">💻 Техника</option>

              <option value="💍">💍 Свадьба</option>

              <option value="👶">👶 Дети</option>

              <option value="🎓">🎓 Обучение</option>

            </select>

          </div>

        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">

          <div class="form-group">

            <label>Желаемый срок (до):</label>

            <input type="date" id="goalInputDate">

          </div>

          <div class="form-group">

            <label>Уже накоплено (₽):</label>

            <input type="number" step="0.01" id="goalInputInitial" placeholder="0.00" value="0">

          </div>

        </div>

        <div class="form-group">

          <label>Привязанный счет для накоплений (опционально):</label>

          <select id="goalInputAccount"></select>

        </div>

        <div class="form-group">

          <label>Заметка / мотивация:</label>

          <input type="text" id="goalInputNote" placeholder="Например: Откладывать по 15 000 ₽ с зарплаты">

        </div>

        <div style="display: flex; gap: 10px; margin-top: 14px;">

          <button class="btn btn-success" style="flex: 1;" onclick="submitSaveGoal()">💾 Сохранить цель</button>

          <button class="btn btn-secondary" onclick="closeGoalModal()">Отмена</button>

        </div>

      </div>

    </div>

    <!-- Modal: Contribute to Financial Goal -->

    <div id="modalContributeGoal" class="hidden" style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.85); z-index: 9999; display: flex; align-items: center; justify-content: center; padding: 16px;">

      <div class="card" style="max-width: 440px; width: 100%; border-color: #3b82f6; position: relative; max-height: 90vh; overflow-y: auto;">

        <button onclick="closeContributeGoalModal()" style="position: absolute; top: 12px; right: 14px; background: transparent; border: none; color: #94a3b8; font-size: 22px; cursor: pointer;">✕</button>

        <h3 style="font-size: 17px; font-weight: 700; color: var(--text); margin-bottom: 6px; display: flex; align-items: center; gap: 8px;">

          <span>💰</span> <span id="contribGoalTitle">Пополнить цель</span>

        </h3>

        <p id="contribGoalRemaining" style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;"></p>

        <div id="contribGoalMsg"></div>

        <input type="hidden" id="contribGoalId" value="">

        <div class="form-group">

          <label>Счет списания (Откуда перевести):</label>

          <select id="contribSourceAccount"></select>

        </div>

        <div class="form-group">

          <label>Сумма пополнения (₽):</label>

          <input type="number" step="0.01" id="contribGoalAmount" placeholder="5000.00" style="font-size: 18px; font-weight: 700; color: #34d399;">

        </div>

        <div style="display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 14px;">

          <button type="button" class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="addContribAmount(1000)">+1 000 ₽</button>

          <button type="button" class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="addContribAmount(5000)">+5 000 ₽</button>

          <button type="button" class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="addContribAmount(10000)">+10 000 ₽</button>

          <button type="button" class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" id="btnContribAllRemaining" onclick="setContribAllRemaining()">Вся сумма</button>

        </div>

        <div class="form-group">

          <label>Комментарий / примечание:</label>

          <input type="text" id="contribGoalNote" placeholder="Пополнение цели">

        </div>

        <div style="display: flex; gap: 10px; margin-top: 14px;">

          <button class="btn btn-success" style="flex: 1;" onclick="submitContributeGoal()">🚀 Внести в накопления</button>

          <button class="btn btn-secondary" onclick="closeContributeGoalModal()">Отмена</button>

        </div>

      </div>

    </div>

    <!-- Modal: Pay Debt / Liabilities -->

    <div id="modalPayDebt" class="hidden" style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.85); z-index: 9999; display: flex; align-items: center; justify-content: center; padding: 16px;">

      <div class="card" style="max-width: 480px; width: 100%; border-color: #ef4444; position: relative; max-height: 90vh; overflow-y: auto;">

        <button onclick="closePayDebtModal()" style="position: absolute; top: 12px; right: 14px; background: transparent; border: none; color: #94a3b8; font-size: 22px; cursor: pointer;">✕</button>

        <h3 style="font-size: 17px; font-weight: 700; color: var(--text); margin-bottom: 6px; display: flex; align-items: center; gap: 8px;">

          <span>💳</span> <span>Погашение задолженности</span>

        </h3>

        <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">

          Двойная бухгалтерская запись (Дт Обязательства / Кт Активы). Погашает долг и мгновенно восстанавливает Safe-to-Spend.

        </p>

        <div id="payDebtMsg"></div>

        <div class="form-group">

          <label>Выберите задолженность для погашения:</label>

          <select id="payDebtLiabilityAccount" onchange="onDebtLiabilityChanged()"></select>

        </div>

        <div id="payDebtInfoBox" style="background: rgba(239,68,68,0.1); border: 1px dashed #ef4444; border-radius: 8px; padding: 10px 14px; margin-bottom: 14px; font-size: 13px;">

          <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">

            <span style="color: var(--text-muted);">Текущий долг:</span>

            <span style="font-weight: 700; color: #f87171;" id="payDebtCurrentAmount">0.00 ₽</span>

          </div>

          <div style="display: flex; justify-content: space-between;" id="payDebtLimitRow">

            <span style="color: var(--text-muted);">Кредитный лимит:</span>

            <span style="color: #94a3b8;" id="payDebtLimitAmount">0.00 ₽</span>

          </div>

        </div>

        <div class="form-group">

          <label>Счет списания (Откуда оплатить):</label>

          <select id="payDebtSourceAccount"></select>

        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 6px;">
          <div class="form-group" style="margin-bottom: 0;">
            <label style="font-size: 12px;">Сумма в рублях (₽):</label>
            <input type="number" step="0.01" id="payDebtAmount" placeholder="0.00" style="font-size: 17px; font-weight: 700; color: #60a5fa;" oninput="onPayDebtAmountRubChanged()">
          </div>
          <div class="form-group" style="margin-bottom: 0;">
            <label style="font-size: 12px;">Или в процентах (% от долга):</label>
            <div style="position: relative;">
              <input type="number" step="0.1" id="payDebtAmountPercent" placeholder="0.0" style="font-size: 17px; font-weight: 700; color: #34d399; padding-right: 28px;" oninput="onPayDebtAmountPercentChanged()">
              <span style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); color: #94a3b8; font-weight: 700;">%</span>
            </div>
          </div>
        </div>

        <div style="display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 8px;">
          <button type="button" class="btn btn-secondary" style="padding: 3px 7px; font-size: 11px; border-color: rgba(251,191,36,0.4); color: #fbbf24;" onclick="setPayDebtPercent(3.0)">3% (Мин. платеж)</button>
          <button type="button" class="btn btn-secondary" style="padding: 3px 7px; font-size: 11px;" onclick="setPayDebtPercent(5.0)">5%</button>
          <button type="button" class="btn btn-secondary" style="padding: 3px 7px; font-size: 11px;" onclick="setPayDebtPercent(10.0)">10%</button>
          <button type="button" class="btn btn-secondary" style="padding: 3px 7px; font-size: 11px;" onclick="setPayDebtPercent(25.0)">25%</button>
          <button type="button" class="btn btn-secondary" style="padding: 3px 7px; font-size: 11px;" onclick="setPayDebtPercent(50.0)">50%</button>
          <button type="button" class="btn btn-secondary" style="padding: 3px 7px; font-size: 11px; color: #34d399; border-color: rgba(52,211,153,0.4);" onclick="setPayDebtPercent(100.0)">100% (Весь долг)</button>
        </div>

        <div style="display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 12px;">
          <button type="button" class="btn btn-secondary" style="padding: 3px 7px; font-size: 11px;" onclick="addPayDebtAmount(1000)">+1 000 ₽</button>
          <button type="button" class="btn btn-secondary" style="padding: 3px 7px; font-size: 11px;" onclick="addPayDebtAmount(5000)">+5 000 ₽</button>
          <button type="button" class="btn btn-secondary" style="padding: 3px 7px; font-size: 11px;" onclick="addPayDebtAmount(10000)">+10 000 ₽</button>
        </div>

        <!-- Live Payoff Forecast Box -->
        <div id="payDebtForecastBox" style="background: var(--card-hover); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 8px; padding: 10px 12px; margin-bottom: 14px; font-size: 12px;">
          <div style="font-weight: 700; color: #38bdf8; display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
            <span>🚀 Прогноз погашения при таком платеже:</span>
            <span id="payDebtForecastStatus" style="font-size: 11px; color: #94a3b8;"></span>
          </div>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 6px; color: var(--text-muted); line-height: 1.4;">
            <div>Срок до закрытия: <strong id="payDebtForecastDays" style="color: var(--text);">—</strong></div>
            <div>Дата погашения: <strong id="payDebtForecastDate" style="color: var(--text);">—</strong></div>
            <div>Переплата банку: <strong id="payDebtForecastInterest" style="color: #fca5a5;">—</strong></div>
            <div>Экономия семейного бюджета: <strong id="payDebtForecastSavings" style="color: #34d399;">—</strong></div>
          </div>
        </div>

        <div class="form-group">

          <label>Категория погашения задолженности:</label>

          <select id="payDebtCategory"></select>

        </div>

        <div class="form-group">

          <label>Назначение платежа:</label>

          <input type="text" id="payDebtDesc" value="Погашение задолженности">

        </div>

        <div style="display: flex; gap: 10px; margin-top: 14px;">

          <button class="btn btn-danger" style="flex: 1;" onclick="submitPayDebt()">✅ Оплатить задолженность</button>

          <button class="btn btn-secondary" onclick="closePayDebtModal()">Отмена</button>

        </div>

      </div>

    </div>

    <!-- 0. Error / Offline Recovery Screen -->

    <div id="errorScreen" class="card hidden" style="max-width: 440px; margin: 30px auto; border-color: #ef4444; text-align: center;">

      <div style="font-size: 42px; margin-bottom: 10px;">⚠️</div>

      <h2 style="font-size: 19px; color: var(--text); margin-bottom: 6px;" id="errorScreenTitle">Ошибка загрузки</h2>

      <p style="color: var(--text-muted); font-size: 13px; margin-bottom: 16px; line-height: 1.4;" id="errorScreenMsg">
        Не удалось связаться с сервером Family Finances OS.
      </p>

      <div style="display: flex; gap: 10px; justify-content: center; flex-wrap: wrap;">

        <button class="btn btn-primary" onclick="retryLoadApp()" style="padding: 9px 18px; font-size: 13px;">
          🔄 Повторить загрузку
        </button>

        <button class="btn btn-secondary" onclick="showLoginFallback()" style="padding: 9px 16px; font-size: 13px;">
          🔑 Форма входа
        </button>

      </div>

    </div>

    <!-- 1. Lock Screen (Master Password Unlock) -->

    <div id="lockScreen" class="card hidden" style="max-width: 440px; margin: 30px auto; border-color: #3b82f6; text-align: center;">

      <div style="font-size: 42px; margin-bottom: 10px;">🔒</div>

      <h2 style="font-size: 19px; color: var(--text); margin-bottom: 6px;">База данных заблокирована</h2>

      <p style="color: var(--text-muted); font-size: 13px; margin-bottom: 16px; line-height: 1.4;">

        Введите мастер-пароль для расшифровки в оперативную память (AES-256-GCM + PBKDF2 600k).

      </p>

      <div style="background: rgba(59, 130, 246, 0.12); border: 1px solid rgba(59, 130, 246, 0.4); border-radius: 8px; padding: 10px 14px; margin-bottom: 16px; text-align: left; font-size: 13px;">

        <div style="color: #94a3b8; font-size: 12px; margin-bottom: 4px;">Мастер-пароль по умолчанию:</div>

        <div style="display: flex; justify-content: space-between; align-items: center;">

          <code style="font-family: monospace; font-size: 14px; font-weight: 700; color: #34d399; background: var(--card-hover); padding: 2px 8px; border-radius: 4px; border: 1px solid var(--border);">Family2026!</code>

          <button type="button" class="btn btn-secondary" style="padding: 2px 8px; font-size: 11px;" onclick="document.getElementById('masterUnlockPassword').value='Family2026!'">Вставить</button>

        </div>

      </div>

      <div id="lockMsg"></div>

      <div class="form-group" style="text-align: left;">

        <label>Мастер-пароль семьи:</label>

        <div style="position: relative;">

          <input type="password" id="masterUnlockPassword" value="Family2026!" placeholder="••••••••••••" onkeyup="if(event.key==='Enter')submitUnlock()" style="padding-right: 44px;">

          <button type="button" onclick="togglePasswordVisibility('masterUnlockPassword', this)" title="Показать/скрыть пароль" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: transparent; border: none; font-size: 18px; cursor: pointer; color: #94a3b8; padding: 4px;">👁️</button>

        </div>

      </div>

      <button class="btn" style="width: 100%; padding: 11px;" id="btnUnlock" onclick="submitUnlock()">Разблокировать систему</button>

    </div>

    <!-- 2. Setup Screen -->

    <div id="setupScreen" class="card hidden" style="max-width: 500px; margin: 30px auto;">

      <h2 style="margin-bottom: 12px; font-size: 18px;">Первичная настройка: Создание Владельца семьи</h2>

      

      <div style="background: rgba(59, 130, 246, 0.12); border: 1px solid rgba(59, 130, 246, 0.4); border-radius: 8px; padding: 12px 14px; margin-bottom: 16px; text-align: left; font-size: 13px;">

        <div style="font-weight: 700; color: #60a5fa; margin-bottom: 6px; display: flex; align-items: center; gap: 6px;">

          <span>🔑</span> <span>Данные для входа в систему (по умолчанию):</span>

        </div>

        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">

          <span style="color: #94a3b8;">Логин:</span>

          <span style="font-family: monospace; font-size: 14px; font-weight: 700; color: #38bdf8; background: var(--card-hover); padding: 2px 8px; border-radius: 4px; border: 1px solid var(--border);">admin</span>

        </div>

        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">

          <span style="color: #94a3b8;">Мастер-пароль:</span>

          <span style="font-family: monospace; font-size: 14px; font-weight: 700; color: #34d399; background: var(--card-hover); padding: 2px 8px; border-radius: 4px; border: 1px solid var(--border);">Family2026!</span>

        </div>

        <div style="color: #94a3b8; font-size: 11px;">Поля ниже уже заполнены. Нажмите кнопку <b>«Инициализировать»</b> или измените данные на свои.</div>

      </div>

      <div id="setupMsg"></div>

      <div class="form-group"><label>Логин:</label><input type="text" id="setupUsername" value="admin"></div>

      <div class="form-group"><label>Отображаемое имя:</label><input type="text" id="setupDisplayName" value="Глава семьи"></div>

      <div class="form-group">

        <label>Мастер-пароль (PBKDF2 600 000 итераций):</label>

        <div style="position: relative;">

          <input type="password" id="setupPassword" value="Family2026!" style="padding-right: 44px;">

          <button type="button" onclick="togglePasswordVisibility('setupPassword', this)" title="Показать/скрыть пароль" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: transparent; border: none; font-size: 18px; cursor: pointer; color: #94a3b8; padding: 4px;">👁️</button>

        </div>

      </div>

      <button class="btn" style="width: 100%;" id="btnSetup" onclick="submitSetup()">Инициализировать защищенную семью</button>

    </div>

    <!-- 3. Login Screen -->

    <div id="loginScreen" class="card hidden" style="max-width: 420px; margin: 30px auto;">

      <h2 style="margin-bottom: 12px; font-size: 18px;">Вход в семейную систему</h2>

      

      <div style="background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.4); border-radius: 8px; padding: 12px 14px; margin-bottom: 16px; text-align: left; font-size: 13px;">

        <div style="font-weight: 700; color: #34d399; margin-bottom: 6px; display: flex; align-items: center; gap: 6px;">

          <span>🔑</span> <span>Данные учетной записи:</span>

        </div>

        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">

          <span style="color: #94a3b8;">Логин:</span>

          <span style="font-family: monospace; font-size: 14px; font-weight: 700; color: #38bdf8; background: var(--card-hover); padding: 2px 8px; border-radius: 4px; border: 1px solid var(--border);">admin</span>

        </div>

        <div style="display: flex; justify-content: space-between; align-items: center;">

          <span style="color: #94a3b8;">Пароль:</span>

          <span style="font-family: monospace; font-size: 14px; font-weight: 700; color: #34d399; background: var(--card-hover); padding: 2px 8px; border-radius: 4px; border: 1px solid var(--border);">Family2026!</span>

        </div>

      </div>

      <div id="loginMsg"></div>

      <div class="form-group"><label>Логин:</label><input type="text" id="loginUsername" value="admin"></div>

      <div class="form-group">

        <label>Пароль:</label>

        <div style="position: relative;">

          <input type="password" id="loginPassword" value="Family2026!" onkeyup="if(event.key==='Enter')submitLogin()" style="padding-right: 44px;">

          <button type="button" onclick="togglePasswordVisibility('loginPassword', this)" title="Показать/скрыть пароль" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: transparent; border: none; font-size: 18px; cursor: pointer; color: #94a3b8; padding: 4px;">👁️</button>

        </div>

      </div>

      <button class="btn" style="width: 100%;" id="btnLogin" onclick="submitLogin()">Войти</button>

    </div>

    <!-- Modal: New Transaction (Revolut Modal on Desktop & Authentic Mobile Bottom Sheet) -->
    <div id="modalNewTx" class="modal hidden" onclick="if(event.target===this) closeNewTxModal()">
      <div class="card bottom-sheet-card" onclick="stopPropagation(event)">
        <!-- Subtle swipe/drag handle at top for mobile -->
        <div class="bottom-sheet-handle-bar">
          <div class="bottom-sheet-handle"></div>
        </div>

        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span id="modalTxHeaderIcon" style="font-size: 22px;">🔴</span>
            <h3 id="modalTxHeaderTitle" style="font-size: 18px; font-weight: 700; margin: 0; background: transparent;">Новый расход семьи</h3>
          </div>
          <button type="button" onclick="closeNewTxModal()" class="bottom-sheet-close-btn" aria-label="Закрыть">✕</button>
        </div>

        <div id="modalTxMsg"></div>

        <!-- Expense / Income Segmented Switcher -->
        <div class="tx-type-segment-group" style="margin-bottom: 16px;">
          <button type="button" id="modalSegBtnExpense" class="tx-type-segment-btn active-expense" onclick="setModalTxType('EXPENSE')">
            <span style="font-size: 16px;">🔴</span> Расход семьи
          </button>
          <button type="button" id="modalSegBtnIncome" class="tx-type-segment-btn" onclick="setModalTxType('INCOME')">
            <span style="font-size: 16px;">🟢</span> Доход семьи
          </button>
        </div>

        <!-- Prominent Hero Amount Input -->
        <div class="form-group" style="margin-bottom: 16px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <label style="margin-bottom: 0; font-weight: 600; font-size: 13px;">Сумма операции:</label>
            <button type="button" class="btn btn-secondary" style="padding: 2px 8px; font-size: 11px; border-radius: 8px;" onclick="resetModalTxAmount()">Сброс</button>
          </div>
          <div class="revolut-amount-wrapper">
            <span class="revolut-amount-currency" id="modalTxCurrencySign">₽</span>
            <input type="number" step="0.01" min="0" id="txInputAmount" class="revolut-amount-input" placeholder="0" oninput="syncTxAmount(this.value)" onkeydown="if(event.key==='Enter') submitModalTransaction()">
          </div>
          <!-- Quick Amount Chips (+100, +500, +1000) -->
          <div class="revolut-chips-row">
            <button type="button" class="revolut-chip" onclick="addTxInputAmount(100)">+100 ₽</button>
            <button type="button" class="revolut-chip" onclick="addTxInputAmount(500)">+500 ₽</button>
            <button type="button" class="revolut-chip" onclick="addTxInputAmount(1000)">+1 000 ₽</button>
            <button type="button" class="revolut-chip" onclick="addTxInputAmount(5000)">+5 000 ₽</button>
          </div>
        </div>

        <!-- Category Dropdown / Selector -->
        <div class="form-group" style="position: relative; margin-bottom: 16px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <label style="margin-bottom: 0; font-weight: 600; font-size: 13px;">Статья / Категория:</label>
            <span id="modalTxCatBadge" class="badge" style="background: rgba(239,68,68,0.2); color: #fca5a5; font-size: 11px;">Расход</span>
          </div>
          <div id="modalTxCatTrigger" class="category-dropdown-trigger" onclick="toggleCategoryDropdown('modalTxCatMenu')">
            <div style="display: flex; align-items: center; gap: 10px; overflow: hidden;">
              <span id="modalTxCatSelectedIcon" style="font-size: 22px; line-height: 1;">🛒</span>
              <div style="text-align: left; line-height: 1.25;">
                <div id="modalTxCatSelectedName" style="font-size: 14px; font-weight: 600; background: transparent;">Продукты и супермаркеты</div>
                <div id="modalTxCatSelectedParent" style="font-size: 11px; background: transparent;">Нажмите для выбора из меню категорий</div>
              </div>
            </div>
            <div style="display: flex; align-items: center; gap: 8px;">
              <span style="font-size: 12px; color: #60a5fa; background: rgba(59,130,246,0.15); padding: 3px 8px; border-radius: 6px; font-weight: 600;">Выбрать ▼</span>
            </div>
          </div>
          <div id="modalTxCatMenu" class="category-dropdown-menu hidden" style="position: absolute; width: 100%; z-index: 10001;">
            <div class="category-dropdown-search">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span style="font-size: 13px; font-weight: 700; color: var(--text);">🏷️ Выберите статью / категорию</span>
                <button type="button" onclick="document.getElementById('modalTxCatMenu').classList.add('hidden')" style="background: transparent; border: none; font-size: 18px; color: var(--text-muted); cursor: pointer; padding: 0 4px; line-height: 1;">✕</button>
              </div>
              <input type="text" id="modalTxCatSearchInput" placeholder="🔍 Найти категорию (еда, бензин, аптека...)" oninput="filterCategoryDropdown('modalTxCatMenu', this.value)">
            </div>
            <div id="modalTxCatList" class="category-dropdown-list" style="max-height: 220px; overflow-y: auto;"></div>
          </div>
          <!-- Native select with ID txInputCategory required by specification -->
          <select id="txInputCategory" style="display: none;"></select>
        </div>

        <!-- Account Selector -->
        <div class="form-group" style="margin-bottom: 16px;">
          <label style="font-weight: 600; font-size: 13px;">Счет списания / зачисления:</label>
          <select id="txInputAccount" class="form-control" style="width: 100%; padding: 10px; border-radius: 12px;"></select>
        </div>

        <!-- Date Selector -->
        <div class="form-group" style="margin-bottom: 16px;">
          <label style="font-weight: 600; font-size: 13px;">📅 Дата операции:</label>
          <div style="display: flex; gap: 8px; align-items: center;">
            <input type="date" id="txInputDate" class="form-control" style="flex: 1; padding: 10px 12px; font-size: 14px; border-radius: 12px;">
            <button type="button" class="btn btn-secondary" style="font-size: 12px; padding: 8px 12px; border-radius: 10px;" onclick="setModalTxDateToday()">Сегодня</button>
          </div>
        </div>

        <!-- Description / Note -->
        <div class="form-group" style="margin-bottom: 20px;">
          <label style="font-weight: 600; font-size: 13px;">Описание / комментарий:</label>
          <input type="text" id="txInputDesc" class="form-control" placeholder="Например: Супермаркет Продукты" style="width: 100%; padding: 10px; border-radius: 12px;" oninput="autoSelectCategoryByDesc(this.value)" onkeydown="if(event.key==='Enter') submitModalTransaction()">
        </div>

        <!-- Large CTA Button -->
        <button type="button" class="btn revolut-cta-btn" id="modalBtnSubmitTx" onclick="submitModalTransaction()">
          <span id="modalBtnSubmitLabel">💾 Записать расход</span>
        </button>
      </div>
    </div>

    <!-- Modal: Edit Past / Existing Transaction -->
<div id="modalEditTx" class="hidden" style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.85); z-index: 9999; display: flex; align-items: center; justify-content: center; padding: 16px;">
  <div class="card" style="max-width: 520px; width: 100%; border-color: var(--primary); position: relative; max-height: 90vh; overflow-y: auto;">
    <button onclick="closeEditTxModal()" style="position: absolute; top: 12px; right: 14px; background: transparent; border: none; color: #94a3b8; font-size: 22px; cursor: pointer;">✕</button>
    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">
      <span style="font-size: 22px;">✏️</span>
      <h3 style="font-size: 18px; font-weight: 700; color: var(--text); margin: 0;">Редактирование операции</h3>
    </div>
    <div id="editTxMsg"></div>
    <input type="hidden" id="editTxId">
    
    <div class="form-group">
      <label>📅 Дата операции (любое число выбранного месяца):</label>
      <input type="date" id="editTxDate" style="width: 100%; padding: 10px; font-size: 14px;">
    </div>

    <div class="form-group">
      <label>Сумма операции (₽):</label>
      <input type="number" id="editTxAmount" step="0.01" min="0.01" style="width: 100%; font-size: 16px; font-weight: 700; padding: 10px;">
    </div>

    <div class="form-group">
      <label>Тип операции:</label>
      <select id="editTxType" onchange="onEditTxTypeChange()" style="width: 100%; padding: 10px;">
        <option value="EXPENSE">Расход семьи</option>
        <option value="INCOME">Доход семьи</option>
      </select>
    </div>

    <div class="form-group">
      <label>Категория / статья:</label>
      <select id="editTxCategory" style="width: 100%; padding: 10px;">
        <!-- Populated dynamically -->
      </select>
    </div>

    <div class="form-group">
      <label>Счет (списание / зачисление):</label>
      <select id="editTxAccount" style="width: 100%; padding: 10px;">
        <!-- Populated dynamically -->
      </select>
    </div>

    <div class="form-group">
      <label>Описание / комментарий:</label>
      <input type="text" id="editTxDescription" placeholder="Например: Супермаркет Продукты" style="width: 100%; padding: 10px;">
    </div>

    <div style="display: flex; gap: 10px; margin-top: 20px;">
      <button class="btn" id="btnSaveEditTx" style="flex: 1;" onclick="submitEditTransaction()">💾 Сохранить</button>
      <button class="btn btn-secondary" style="background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #fca5a5;" onclick="deleteTransactionFromModal()">🗑️ Удалить</button>
      <button class="btn btn-secondary" onclick="closeEditTxModal()">Отмена</button>
    </div>
  </div>
</div>



      <!-- Modal: Add New Debt / Loan / Credit Card -->
      <div id="modalNewDebt" class="hidden" style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.85); z-index: 100000; display: flex; align-items: center; justify-content: center; padding: 16px;">
        <div class="card" style="max-width: 600px; width: 100%; border-color: var(--primary); position: relative; max-height: 90vh; overflow-y: auto;">
          <button onclick="closeNewDebtModal()" style="position: absolute; top: 12px; right: 14px; background: transparent; border: none; color: #94a3b8; font-size: 22px; cursor: pointer;">✕</button>
          
          <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 14px;">
            <span style="font-size: 26px;">➕</span>
            <div>
              <h3 style="font-size: 18px; color: var(--text); margin: 0;">Добавление задолженности или кредита</h3>
              <p style="font-size: 12px; color: var(--text-muted); margin: 2px 0 0 0;">Выберите тип и укажите условия банка или договора</p>
            </div>
          </div>

          <!-- Type Selection Buttons Grid -->
          <div class="debt-type-grid" style="margin-bottom: 12px;">
            <button type="button" class="btn btn-secondary debt-type-btn active" data-type="CREDIT_CARD" onclick="selectDebtType('CREDIT_CARD')">💳 Кредитка</button>
            <button type="button" class="btn btn-secondary debt-type-btn" data-type="CONSUMER_LOAN" onclick="selectDebtType('CONSUMER_LOAN')">📋 Потребкредит</button>
            <button type="button" class="btn btn-secondary debt-type-btn" data-type="MORTGAGE" onclick="selectDebtType('MORTGAGE')">🏠 Ипотека</button>
            <button type="button" class="btn btn-secondary debt-type-btn" data-type="AUTO_LOAN" onclick="selectDebtType('AUTO_LOAN')">🚗 Автокредит</button>
            <button type="button" class="btn btn-secondary debt-type-btn" data-type="INSTALLMENT_BNPL" onclick="selectDebtType('INSTALLMENT_BNPL')">🛍️ Рассрочка/Сплит</button>
            <button type="button" class="btn btn-secondary debt-type-btn" data-type="PERSONAL_DEBT" onclick="selectDebtType('PERSONAL_DEBT')">🤝 Долг человеку</button>
          </div>
          <input type="hidden" id="newDebtSubtype" value="CREDIT_CARD">

          <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px; display: flex; align-items: center; gap: 6px; background: var(--card-hover); padding: 8px 12px; border-radius: 6px; border: 1px solid rgba(148,163,184,0.15);">
            <span>📂 Категория учета:</span> <strong id="newDebtCategoryLabel" style="color: #60a5fa;">💳 Погашение кредитных карт</strong>
          </div>

          <div class="form-group" style="margin-bottom: 12px;">
            <label id="lblDebtName">Название карты / банк:</label>
            <input type="text" id="newDebtName" placeholder="Например: Кредитная СберКарта ТП-1001" style="width: 100%; padding: 10px;">
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 12px;">
            <div class="form-group" id="groupCreditLimit">
              <label>Кредитный лимит (₽):</label>
              <input type="text" inputmode="decimal" id="newDebtCreditLimit" placeholder="165000" style="width: 100%; padding: 10px;">
            </div>
            <div class="form-group">
              <label id="lblDebtAmount">Текущий долг (₽):</label>
              <input type="text" inputmode="decimal" id="newDebtCurrentAmount" placeholder="50000" style="width: 100%; padding: 10px;">
            </div>
          </div>

          <!-- Credit Card Banking Conditions Block (visible for CREDIT_CARD) -->
          <div id="groupCreditCardBanking" style="background: var(--card-hover); border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 8px; padding: 12px; margin-bottom: 14px;">
            <div style="font-size: 12px; font-weight: 700; color: #38bdf8; margin-bottom: 8px; display: flex; align-items: center; gap: 6px;">
              <span>🏦</span> <span>Банковские условия и грейс-период (договор Сбербанка / стандарт банков РФ)</span>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 8px;">
              <div class="form-group" style="margin-bottom: 0;">
                <label style="font-size: 11px;">📅 Дата окончания грейса / платежа:</label>
                <input type="date" id="newDebtGraceDueDate" style="width: 100%; padding: 8px; font-size: 12px;">
              </div>
              <div class="form-group" style="margin-bottom: 0;">
                <label style="font-size: 11px;">📊 Ставка банка (% годовых):</label>
                <input type="text" inputmode="decimal" id="newDebtApr" value="24.8" style="width: 100%; padding: 8px; font-size: 12px;">
              </div>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px;">
              <div class="form-group" style="margin-bottom: 0;">
                <label style="font-size: 11px;">⏳ Грейс (дней):</label>
                <input type="text" inputmode="numeric" id="newDebtGraceDays" value="120" style="width: 100%; padding: 8px; font-size: 12px;">
              </div>
              <div class="form-group" style="margin-bottom: 0;">
                <label style="font-size: 11px;">💳 Мин. платеж (%):</label>
                <input type="text" inputmode="decimal" id="newDebtMinPaymentPct" value="3.0" style="width: 100%; padding: 8px; font-size: 12px;">
              </div>
              <div class="form-group" style="margin-bottom: 0;">
                <label style="font-size: 11px;">⚠️ Неустойка (%):</label>
                <input type="text" inputmode="decimal" id="newDebtLatePenaltyPct" value="36.0" style="width: 100%; padding: 8px; font-size: 12px;">
              </div>
            </div>
          </div>

          <div class="form-group" style="margin-bottom: 12px;">
            <label>Принадлежность задолженности:</label>
            <select id="newDebtScope" style="width: 100%; padding: 10px;">
              <option value="COMMON">Общий семейный долг</option>
              <option value="PERSONAL_HUSBAND">Личный долг Мужа</option>
              <option value="PERSONAL_WIFE">Личный долг Жены</option>
            </select>
          </div>

          <!-- Recurring Obligation Option -->
          <div style="background: var(--card-hover); padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border); margin-bottom: 12px;">
            <label style="display: flex; align-items: center; gap: 8px; cursor: pointer; font-size: 13px; font-weight: 600;">
              <input type="checkbox" id="chkCreateObligation" onchange="toggleDebtObligationFields(this.checked)">
              <span>Создать ежемесячный обязательный платеж в календаре</span>
            </label>
            <div id="debtObligationFields" style="display: none; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 10px;">
              <div class="form-group" style="margin-bottom: 0;">
                <label style="font-size: 11px;">Сумма платежа (₽):</label>
                <input type="text" inputmode="decimal" id="newDebtMonthlyPayment" placeholder="3000" style="width: 100%; padding: 8px; font-size: 12px;">
              </div>
              <div class="form-group" style="margin-bottom: 0;">
                <label style="font-size: 11px;">Число месяца (день):</label>
                <input type="text" inputmode="numeric" id="newDebtDueDay" value="15" min="1" max="31" style="width: 100%; padding: 8px; font-size: 12px;">
              </div>
            </div>
          </div>

          <!-- Received funds option (for loans) -->
          <div id="groupReceiveMoney" style="background: var(--card-hover); padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border); margin-bottom: 12px;">
            <label style="display: flex; align-items: center; gap: 8px; cursor: pointer; font-size: 13px; font-weight: 600;">
              <input type="checkbox" id="chkReceiveMoney" onchange="toggleDebtReceiveAccount(this.checked)">
              <span>Зачислить полученные заёмные деньги на текущий счет семьи</span>
            </label>
            <div id="debtReceiveAccountField" style="display: none; margin-top: 10px;">
              <label style="font-size: 11px;">Счет зачисления средств:</label>
              <select id="newDebtReceiveAccount" style="width: 100%; padding: 8px; font-size: 12px;"></select>
            </div>
          </div>

          <div class="form-group" style="margin-bottom: 14px;">
            <label>Заметки / примечания (условия, договор):</label>
            <input type="text" id="newDebtNotes" placeholder="Кредитная СберКарта ТП-1001, договор №..." style="width: 100%; padding: 10px;">
          </div>

          <div id="newDebtMsg" style="margin-bottom: 12px;"></div>

          <div style="display: flex; gap: 10px;">
            <button class="btn" id="btnSubmitNewDebt" style="flex: 1;" onclick="submitNewDebt()">💾 Создать задолженность</button>
            <button class="btn btn-secondary" onclick="closeNewDebtModal()">Отмена</button>
          </div>
        </div>
      </div>

      <!-- Modal: Card Banking Settings & Due Date Modification -->
      <div id="modalCardSettings" class="hidden" style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.85); z-index: 9999; display: flex; align-items: center; justify-content: center; padding: 16px;">
        <div class="card" style="max-width: 520px; width: 100%; border-color: #38bdf8; position: relative; max-height: 90vh; overflow-y: auto;">
          <button onclick="closeCardSettingsModal()" style="position: absolute; top: 12px; right: 14px; background: transparent; border: none; color: #94a3b8; font-size: 22px; cursor: pointer;">✕</button>
          
          <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px;">
            <span style="font-size: 24px;">⚙️</span>
            <div>
              <h3 id="cardSettingsTitle" style="font-size: 17px; color: var(--text); margin: 0;">Условия кредитной карты</h3>
              <p style="font-size: 12px; color: var(--text-muted); margin: 2px 0 0 0;">Текущий долг: <strong id="cardSettingsDebtBal" style="color:#f87171;">0.00 ₽</strong></p>
            </div>
          </div>

          <input type="hidden" id="cardSettingsAccId">

          <div class="form-group" style="margin-bottom: 12px;">
            <label>📅 Дата окончания беспроцентного периода / платежа:</label>
            <input type="date" id="cardSettingsDueDate" style="width: 100%; padding: 10px; font-weight: 600; font-size: 14px;">
            <small style="color: var(--text-muted); font-size: 11px;">Указывается из выписки или СМС от банка (дата до которой нужно внести платеж)</small>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 12px;">
            <div class="form-group">
              <label>💳 Кредитный лимит (₽):</label>
              <input type="number" id="cardSettingsLimit" step="1000" style="width: 100%; padding: 10px;">
            </div>
            <div class="form-group">
              <label>📊 Ставка (% годовых):</label>
              <input type="number" id="cardSettingsApr" step="0.1" style="width: 100%; padding: 10px;">
            </div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; margin-bottom: 14px;">
            <div class="form-group">
              <label style="font-size: 11px;">⏳ Грейс (дней):</label>
              <input type="number" id="cardSettingsGraceDays" style="width: 100%; padding: 8px; font-size: 12px;">
            </div>
            <div class="form-group">
              <label style="font-size: 11px;">💳 Мин. платеж (%):</label>
              <input type="number" id="cardSettingsMinPaymentPct" step="0.5" style="width: 100%; padding: 8px; font-size: 12px;">
            </div>
            <div class="form-group">
              <label style="font-size: 11px;">⚠️ Неустойка (%):</label>
              <input type="number" id="cardSettingsLatePenaltyPct" step="0.5" style="width: 100%; padding: 8px; font-size: 12px;">
            </div>
          </div>

          <div id="cardSettingsMsg" style="margin-bottom: 12px;"></div>

          <div style="display: flex; gap: 10px;">
            <button class="btn" style="flex: 1;" onclick="submitCardSettings()">💾 Сохранить условия</button>
            <button class="btn btn-secondary" onclick="closeCardSettingsModal()">Отмена</button>
          </div>
        </div>
      </div>

      <!-- 4. App Main Body -->

    <div id="mainDashboard" class="hidden">

<!-- Month Selector & Period Navigator Bar -->
<div class="month-navigator-bar">
  <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
    <span class="month-navigator-label">
      <span style="font-size: 18px;">📅</span>
      <span>Период учёта:</span>
    </span>
    <div style="display: flex; align-items: center; gap: 6px;">
      <button type="button" class="month-chevron-btn" onclick="shiftSelectedMonth(-1)" title="Предыдущий месяц" aria-label="Предыдущий месяц">◀</button>
      <select id="globalMonthSelect" class="month-select-input" onchange="onGlobalMonthSelectChange(this.value)">
        <!-- Filled dynamically -->
      </select>
      <button type="button" class="month-chevron-btn" onclick="shiftSelectedMonth(1)" title="Следующий месяц" aria-label="Следующий месяц">▶</button>
    </div>
    <button type="button" id="btnCurrentMonthReset" class="btn btn-secondary" style="padding: 6px 14px; font-size: 12px; display: none; border-radius: 10px;" onclick="resetToCurrentMonth()">🔄 Текущий месяц</button>
  </div>
  <div id="pastMonthNotice" style="display: none; align-items: center; gap: 8px; font-size: 13px; color: #fbbf24; background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.35); border-radius: 10px; padding: 6px 14px;">
    <span>⚠️ <strong>Архивный режим:</strong> <span id="pastMonthNoticeLabel"></span>. Все операции и бюджеты фильтруются за этот месяц.</span>
  </div>
</div>

<!-- Desktop Navigation Tabs -->
<div class="nav-tabs-wrapper">
  <button class="nav-tab-scroll-btn" id="navScrollLeft" onclick="scrollNavigation(-200)" aria-label="Прокрутить разделы влево">‹</button>
  <div class="nav-tabs" id="navTabsBar" role="navigation" aria-label="Разделы семейного бюджета" role="navigation" aria-label="Разделы семейного бюджета" role="navigation" aria-label="Разделы семейного бюджета" role="navigation" aria-label="Разделы семейного бюджета" role="navigation" aria-label="Разделы семейного бюджета" role="navigation" aria-label="Разделы семейного бюджета">
        <button class="tab-btn active" onclick="switchTab('tab-overview')">📊 Сводный дашборд</button>
        <button class="tab-btn" onclick="switchTab('tab-goals')">🎯 Цели накоплений</button>
        <button class="tab-btn" onclick="switchTab('tab-envelopes')">✉️ Конверты-копилки</button>
        <button class="tab-btn" onclick="switchTab('tab-debts')">💳 Долги и кредиты</button>
        <button class="tab-btn" onclick="switchTab('tab-analytics')">📈 Аналитика и прогноз</button>
        <button class="tab-btn" onclick="switchTab('tab-tx')">➕ Новая операция</button>
        <button class="tab-btn" onclick="switchTab('tab-obligations')">📅 Обязательные платежи</button>
        <button class="tab-btn" onclick="switchTab('tab-accounts')">💳 Счета семьи</button>
        <button class="tab-btn" onclick="switchTab('tab-categories')">📂 Категории</button>
        <button class="tab-btn" onclick="switchTab('tab-transfer')">🔄 Внутренний перевод</button>
        <button class="tab-btn" onclick="switchTab('tab-ledger')">📜 Журнал проводок</button>
        <button class="tab-btn" onclick="switchTab('tab-import')">📥 Импорт выписок</button>
  </div>
  <button class="nav-tab-scroll-btn" id="navScrollRight" onclick="scrollNavigation(200)" aria-label="Прокрутить разделы вправо">›</button>
</div>

      <!-- Tab 1: Overview -->
      <div id="tab-overview">

        <!-- Revolut Desktop Grid: Main Column (Hero, Metrics, Ledger, Accounts) + Widget Column (Envelopes, Goals) -->
        <div class="desktop-dashboard-grid">

          <!-- Left / Center Main Column -->
          <div class="desktop-main-column">
<!-- Revolut Hero Balance Card -->
        <div class="appetite-hero-card revolut-hero-card appetite-hero-stripes hero-card-container">
          <div class="hero-balance-header-row">
            <div class="hero-primary-balance-box">
              <div class="hero-label">Свободный баланс семьи (Safe-to-Spend)</div>
              <div class="hero-balance-val" id="valSafeToSpend">0.00 ₽</div>
              <div class="hero-badge-pill" id="valSafeToSpendBadge">
                <span id="valSafeToSpendNote">Ликвидные активы за вычетом обязательств и кредиток</span>
              </div>
            </div>
            <div class="hero-secondary-balance-box">
              <div class="hero-secondary-label">Общий баланс счетов</div>
              <div class="hero-secondary-val" id="valHeroTotalBalance">0.00 ₽</div>
              <div class="hero-secondary-pill">
                <span>💳 Всего на картах и счетах</span>
              </div>
            </div>
          </div>

          <!-- 4 Quick Actions (Sleek Revolut Circular / Pill Style) -->
          <div class="hero-actions-grid revolut-actions-grid">
            <button class="hero-action-btn revolut-action-btn" id="heroBtnExpense" onclick="openNewTxModal('EXPENSE')">
              <div class="hero-action-icon revolut-icon-expense">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                  <line x1="12" y1="5" x2="12" y2="19"></line>
                  <line x1="5" y1="12" x2="19" y2="12"></line>
                </svg>
              </div>
              <span class="revolut-action-label" style="font-weight: 700;">Расход</span>
            </button>

            <button class="hero-action-btn revolut-action-btn" id="heroBtnIncome" onclick="openNewTxModal('INCOME')">
              <div class="hero-action-icon revolut-icon-income">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                  <line x1="12" y1="5" x2="12" y2="19"></line>
                  <line x1="5" y1="12" x2="19" y2="12"></line>
                </svg>
              </div>
              <span class="revolut-action-label" style="font-weight: 700;">Доход</span>
            </button>

            <button class="hero-action-btn revolut-action-btn" id="heroBtnTransfer" onclick="openTransferModal()">
              <div class="hero-action-icon revolut-icon-transfer">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">
                  <polyline points="17 1 21 5 17 9"></polyline>
                  <path d="M3 5h18"></path>
                  <polyline points="7 23 3 19 7 15"></polyline>
                  <path d="M21 19H3"></path>
                </svg>
              </div>
              <span class="revolut-action-label" style="font-weight: 600;">Перевод</span>
            </button>

            <button class="hero-action-btn revolut-action-btn" id="heroBtnGoals" onclick="switchTab('goals')">
              <div class="hero-action-icon revolut-icon-goals">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="12" cy="12" r="10"></circle>
                  <circle cx="12" cy="12" r="6"></circle>
                  <circle cx="12" cy="12" r="2"></circle>
                </svg>
              </div>
              <span class="revolut-action-label" style="font-weight: 600;">Цели</span>
            </button>
          </div>
        </div>

        <!-- Smart Quick Entry Bar -->
        <div class="card" style="padding: 14px 18px; margin-bottom: 20px;">
          <div class="quick-input-bar" style="display: flex; gap: 8px; align-items: center; position: relative;">
            <div style="position: relative;">
              <button type="button" id="dashCatDropdownBtn" class="btn btn-secondary" 
                      style="padding: 10px 14px; font-size: 13px; display: flex; align-items: center; gap: 6px; white-space: nowrap; height: 44px; border-radius: 12px;" 
                      onclick="toggleCategoryDropdown('dashCatMenu')">
                <span id="dashCatSelectedIcon">🏷️</span>
                <span id="dashCatSelectedName">Категория</span>
                <span style="font-size: 10px; opacity: 0.7;">▼</span>
              </button>
              <div id="dashCatMenu" class="category-dropdown-menu hidden" style="left: 0; min-width: 290px;">
                <div class="category-dropdown-search">
                  <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <span style="font-size: 13px; font-weight: 700; color: var(--text);">🏷️ Выберите категорию</span>
                    <button type="button" onclick="document.getElementById('dashCatMenu').classList.add('hidden')" style="background: transparent; border: none; font-size: 18px; color: var(--text-muted); cursor: pointer; padding: 0 4px; line-height: 1;">✕</button>
                  </div>
                  <input type="text" id="dashCatSearchInput" placeholder="🔍 Поиск категории..." oninput="filterCategoryDropdown('dashCatMenu', this.value)">
                  <div style="display: flex; gap: 4px; margin-top: 6px;">
                    <button type="button" class="btn btn-secondary cat-filter-btn active" onclick="setCatMenuFilter('dashCatMenu', 'ALL', this)" style="padding: 2px 8px; font-size: 11px;">Все</button>
                    <button type="button" class="btn btn-secondary cat-filter-btn" onclick="setCatMenuFilter('dashCatMenu', 'EXPENSE', this)" style="padding: 2px 8px; font-size: 11px;">🔴 Расход</button>
                    <button type="button" class="btn btn-secondary cat-filter-btn" onclick="setCatMenuFilter('dashCatMenu', 'INCOME', this)" style="padding: 2px 8px; font-size: 11px;">🟢 Доход</button>
                  </div>
                </div>
                <div id="dashCatList" class="category-dropdown-list"></div>
              </div>
            </div>

            <input type="text" id="dashQuickInput" placeholder="Умная запись: 500 кофе, 1500 продукты, 850 аптека..." 
                   style="font-size: 14px; padding: 11px 16px; border-radius: 12px; flex: 1;"
                   oninput="onQuickInputLive(this.value, 'dashQuickPreview')" 
                   onkeydown="if(event.key==='Enter')submitQuickInput('dashQuickInput', 'dashQuickMsg')">

            <button class="btn" style="padding: 11px 20px; font-size: 14px; font-weight: 600; white-space: nowrap; border-radius: 12px;" onclick="submitQuickInput('dashQuickInput', 'dashQuickMsg')">
              ⚡ Записать
            </button>
          </div>

          <div id="dashQuickPreview" class="alert alert-info hidden" style="margin-top: 8px; padding: 8px 12px; font-size: 12px;"></div>
          <div id="dashQuickMsg"></div>

          <!-- Quick presets -->
          <div style="display: flex; gap: 6px; flex-wrap: wrap; align-items: center; margin-top: 10px;">
            <span style="font-size: 11px; color: var(--text-muted); margin-right: 4px; font-weight: 500;">Частые:</span>
            <button type="button" class="btn btn-secondary" style="padding: 3px 9px; font-size: 11px; border-radius: 9999px;" onclick="applyQuickPreset('1000 продукты')">🛒 Продукты 1000 ₽</button>
            <button type="button" class="btn btn-secondary" style="padding: 3px 9px; font-size: 11px; border-radius: 9999px;" onclick="applyQuickPreset('300 кофе')">☕ Кофе 300 ₽</button>
            <button type="button" class="btn btn-secondary" style="padding: 3px 9px; font-size: 11px; border-radius: 9999px;" onclick="applyQuickPreset('500 такси')">🚖 Такси 500 ₽</button>
            <button type="button" class="btn btn-secondary" style="padding: 3px 9px; font-size: 11px; border-radius: 9999px;" onclick="applyQuickPreset('2000 бензин')">⛽ Бензин 2000 ₽</button>
            <button type="button" class="btn btn-secondary" style="padding: 3px 9px; font-size: 11px; border-radius: 9999px;" onclick="applyQuickPreset('500 аптека')">💊 Аптека 500 ₽</button>
          </div>
        </div>

        <!-- Hidden Onboarding Form (preserved for state initialization if triggered) -->
        <div id="onboardingBanner" class="card onboarding-card hidden" style="margin-bottom: 20px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 12px;">
            <h3 style="font-size: 16px; color: var(--primary);">✨ Мастер настройки семейного бюджета</h3>
            <button class="btn btn-secondary" style="font-size: 12px; padding: 4px 10px;" onclick="document.getElementById('onboardingBanner').classList.add('hidden')">✕ Закрыть</button>
          </div>
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; margin-bottom: 14px;">
            <div style="background: var(--card-hover); padding: 12px; border-radius: 12px;">
              <h4 style="font-size: 12px; margin-bottom: 6px;">1. Остатки на картах</h4>
              <input type="number" id="obMainCard" placeholder="0" value="0" style="margin-bottom: 6px;">
              <input type="number" id="obWifeCard" placeholder="0" value="0" style="margin-bottom: 6px;">
              <input type="number" id="obCash" placeholder="0" value="0">
            </div>
            <div style="background: var(--card-hover); padding: 12px; border-radius: 12px;">
              <h4 style="font-size: 12px; margin-bottom: 6px;">2. Кредитная карта (2020)</h4>
              <input type="number" id="obCreditLimit" placeholder="Лимит" value="0" style="margin-bottom: 6px;">
              <input type="number" id="obCreditDebt" placeholder="Долг" value="0">
            </div>
            <div style="background: var(--card-hover); padding: 12px; border-radius: 12px;">
              <h4 style="font-size: 12px; margin-bottom: 6px;">3. Обязательный платеж</h4>
              <input type="text" id="obOblName" placeholder="Аренда / ЖКХ" style="margin-bottom: 6px;">
              <input type="number" id="obOblAmount" placeholder="Сумма" style="margin-bottom: 6px;">
              <input type="number" id="obOblDay" value="15">
            </div>
          </div>
          <button class="btn" style="width: 100%; padding: 10px;" onclick="submitOnboarding()">Зафиксировать бюджет</button>
        </div>

        <!-- Core Financial Cards: Revolut Debit Card + Meso Metrics -->
        <div class="core-financial-cards" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin-bottom: 20px;">
          <!-- Left: Revolut Family Debit Card -->
          <div class="appetite-debit-card revolut-debit-card">
            <div class="appetite-card-sheen"></div>
            <div style="display: flex; justify-content: space-between; align-items: center; position: relative; z-index: 2;">
              <span style="font-size: 15px; font-weight: 600; letter-spacing: -0.01em;">Семейная карта • Black Edition</span>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
                <path d="M8.5 16.5a5 5 0 0 1 0-7"></path>
                <path d="M12 19a8.5 8.5 0 0 0 0-12"></path>
                <path d="M15.5 21.5a12 12 0 0 0 0-17"></path>
              </svg>
            </div>

            <div style="margin: 24px 0 16px 0; position: relative; z-index: 2;">
              <div style="font-size: 11px; opacity: 0.8; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 2px;">Ликвидный остаток всех карт</div>
              <div style="font-size: 28px; font-weight: 800; letter-spacing: -0.02em;" id="valLiquid">0.00 ₽</div>
            </div>

            <div style="display: flex; justify-content: space-between; align-items: flex-end; position: relative; z-index: 2; font-size: 13px;">
              <div>
                <div style="font-size: 10px; opacity: 0.7; text-transform: uppercase;">Владелец</div>
                <div style="font-weight: 600;">Семья • 1010</div>
              </div>
            </div>
          </div>

          <!-- Right: Revolut Metric Cards Grid -->
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px;">
            <div class="card" style="margin-bottom: 0; padding: 18px; display: flex; flex-direction: column; justify-content: space-between;">
              <div>
                <div class="stat-label">Обязательства</div>
                <div class="stat-val purple" id="valObligations">0.00 ₽</div>
              </div>
              <p style="font-size: 11px; color: var(--text-muted); margin-top: 6px;" id="valObligationsDetail">Платежи месяца</p>
            </div>

            <div class="card" style="margin-bottom: 0; padding: 18px; display: flex; flex-direction: column; justify-content: space-between;">
              <div>
                <div class="stat-label">Резерв</div>
                <div class="stat-val warning" id="valReserve">0.00 ₽</div>
              </div>
              <p style="font-size: 11px; color: var(--text-muted); margin-top: 6px;">Подушка безопасности</p>
            </div>

            <div class="card" style="margin-bottom: 0; padding: 18px; display: flex; flex-direction: column; justify-content: space-between;">
              <div>
                <div class="stat-label">Капитал</div>
                <div class="stat-val" style="color: #60a5fa;" id="valNetWorth">0.00 ₽</div>
              </div>
              <p style="font-size: 11px; color: var(--text-muted); margin-top: 6px;">Чистый капитал семьи</p>
            </div>

            <div class="card" style="margin-bottom: 0; padding: 18px; display: flex; flex-direction: column; justify-content: space-between;">
              <div>
                <div class="stat-label">Кредиты и долги</div>
                <div class="stat-val danger" id="valCreditSummary">0.00 ₽</div>
                <p style="font-size: 11px; color: var(--text-muted); margin-top: 4px;" id="valCreditDetail">Доступно: 0.00 ₽</p>
              </div>
              <button class="btn btn-secondary" style="width: 100%; font-size: 11px; padding: 6px 8px; margin-top: 8px; color: #f87171;" onclick="openPayDebtModal()">
                Погасить
              </button>
            </div>
          </div>
        </div>

            <!-- Main Transaction Ledger Table (Revolut Desktop Ledger with crisp row borders & right-aligned amounts) -->
            <div class="card desktop-ledger-card" id="dashLedgerCard" style="margin-bottom: 20px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; flex-wrap: wrap; gap: 8px;">
                <h3 style="font-size: 16px; font-weight: 700; display: flex; align-items: center; gap: 8px; margin: 0;">
                  <span>📜</span> <span>Последние операции</span>
                </h3>
                <div style="display: flex; gap: 8px; align-items: center;">
                  <button class="btn btn-secondary" style="font-size: 12px; padding: 4px 10px;" onclick="loadTransactions(currentSelectedMonth)">Обновить</button>
                  <button class="btn btn-secondary" style="font-size: 12px; padding: 4px 10px;" onclick="switchTab('tab-ledger')">Все проводки →</button>
                </div>
              </div>
              <div style="overflow-x: auto; -webkit-overflow-scrolling: touch;">
                <table class="revolut-ledger-table">
                  <thead>
                    <tr>
                      <th style="width: 100px;">Дата</th>
                      <th style="width: 140px;">Категория</th>
                      <th>Описание</th>
                      <th style="text-align: right; width: 130px;">Сумма</th>
                      <th style="text-align: right; width: 50px;"></th>
                    </tr>
                  </thead>
                  <tbody id="dashTxTableBody">
                    <tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 18px;">Загрузка операций...</td></tr>
                  </tbody>
                </table>
              </div>
            </div>

<!-- Accounts Overview Table -->

        <div class="card accounts-card">
          <h3 id="overviewAccountsHeading" style="margin-bottom: 12px; font-size: 16px;">Балансы всех счетов семьи</h3>
          <p class="account-list-hint">Все счета · прокрутите список, чтобы увидеть остальные</p>
          <div class="accounts-list-viewport" tabindex="0" role="region" aria-labelledby="overviewAccountsHeading">
            <div id="overviewAccountsBody" class="accounts-list" role="list"></div>
          </div>

        </div>
          </div><!-- /desktop-main-column -->

          <!-- Right Side Widget Column (Envelopes and Goal Progress) -->
          <div class="desktop-widget-column">
<!-- Dashboard Envelopes & Piggy Banks Widget -->

        <div class="card" id="dashEnvelopesCard" style="margin-bottom: 20px;">

          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 8px;">

            <div style="display: flex; align-items: center; gap: 8px;">

              <span style="font-size: 20px;">✉️</span>

              <h3 style="font-size: 16px; font-weight: 700; color: var(--text); margin: 0;">Конверты-копилки</h3>

            </div>

            <div style="display: flex; align-items: center; gap: 8px;">

              <span id="dashEnvelopesTotalBadge" class="badge" style="background: rgba(59, 130, 246, 0.2); color: #60a5fa; font-size: 12px;">0.00 ₽</span>

              <button class="btn btn-secondary" style="font-size: 12px; padding: 4px 10px;" onclick="switchTab('tab-envelopes')">Все конверты →</button>

            </div>

          </div>

          <div id="dashEnvelopesContainer" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px;">

            <div style="color: var(--text-muted); font-size: 13px;">Загрузка конвертов...</div>

          </div>

        </div>
<!-- Goals Progress Widget on Dashboard -->

        <div class="card" id="dashGoalsCard" style="margin-bottom: 18px;">

          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">

            <h3 style="font-size: 16px; display: flex; align-items: center; gap: 6px;">

              <span>🎯</span> <span>Семейные цели накоплений</span>

            </h3>

            <div style="display: flex; gap: 8px;">

              <button class="btn btn-secondary" style="font-size: 12px; padding: 4px 10px;" onclick="openNewGoalModal()">➕ Новая цель</button>

              <button class="btn btn-secondary" style="font-size: 12px; padding: 4px 10px;" onclick="switchTab('tab-goals')">Все цели →</button>

            </div>

          </div>

          <div id="dashGoalsContainer" style="display: flex; flex-direction: column; gap: 10px;">

            <div style="color: var(--text-muted); font-size: 13px;">Загрузка целей...</div>

          </div>

        </div>
          </div><!-- /desktop-widget-column -->

        </div><!-- /desktop-dashboard-grid -->

      </div>

      <!-- Tab: Financial Goals (Цели накоплений) -->

      <div id="tab-goals" class="hidden">

        <div class="card">

          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 10px;">

            <div>

              <h3 style="font-size: 18px; color: var(--text); display: flex; align-items: center; gap: 8px;">

                <span>🎯</span> <span>Семейные цели накоплений</span>

              </h3>

              <p style="font-size: 13px; color: var(--text-muted); margin-top: 2px;">

                Ставьте финансовые цели, откладывайте средства и отслеживайте прогресс накоплений.

              </p>

            </div>

            <button class="btn btn-success" onclick="openNewGoalModal()">➕ Создать цель</button>

          </div>

          <div id="goalsListContainer" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px;">

            <div style="color: var(--text-muted); font-size: 13px;">Загрузка целей...</div>

          </div>

        </div>

      </div>

      <!-- Tab: Envelopes / Piggy Banks (Конверты-копилки) -->

      <div id="tab-envelopes" class="hidden">

        <div class="card">

          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 10px;">

            <div>

              <h3 style="font-size: 18px; color: var(--text); display: flex; align-items: center; gap: 8px;">

                <span>✉️</span> <span>Конверты-копилки семьи</span>

              </h3>

              <p style="font-size: 13px; color: var(--text-muted); margin-top: 2px;">

                Метод конвертов: откладывайте деньги по виртуальным конвертам-копилкам на мечты, отпуск, резервы и подарки.

              </p>

            </div>

            <div style="display: flex; gap: 8px; flex-wrap: wrap;">

              <button class="btn btn-success" onclick="openNewEnvelopeModal()">➕ Создать конверт</button>

              <button class="btn btn-secondary" onclick="openEnvelopeTransferModal()">🔄 Переложить между конвертами</button>

            </div>

          </div>

          <div class="grid-3" style="margin-bottom: 18px;">

            <div class="card" style="margin-bottom: 0;">

              <div class="stat-label">Всего отложено в конвертах</div>

              <div class="stat-val success" id="envelopesTotalSaved">0.00 ₽</div>

              <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Зарезервировано в копилках</p>

            </div>

            <div class="card" style="margin-bottom: 0;">

              <div class="stat-label">Активных конвертов</div>

              <div class="stat-val" style="color: #60a5fa;" id="envelopesCount">0</div>

              <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Направления сбережений</p>

            </div>

            <div class="card" style="margin-bottom: 0;">

              <div class="stat-label">Целевой объём накоплений</div>

              <div class="stat-val warning" id="envelopesTotalTarget">0.00 ₽</div>

              <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Сумма целей всех копилок</p>

            </div>

          </div>

          <div id="envelopesListContainer" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px;">

            <div style="color: var(--text-muted); font-size: 13px;">Загрузка конвертов...</div>

          </div>

        </div>

      </div>

      <!-- Tab: Debts & Credit Cards (Stage 12 & 13) -->
      <div id="tab-debts" class="hidden">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 12px;">
          <div>
            <h3 style="font-size: 18px; color: var(--text); display: flex; align-items: center; gap: 8px;">
              <span>💳</span> <span>Задолженности и кредитные карты семьи</span>
            </h3>
            <p style="font-size: 13px; color: var(--text-muted); margin-top: 2px;">
              Банковский контроль кредитных карт, грейс-периода, расчет процентов и неустойки при просрочке.
            </p>
          </div>
          <div style="display: flex; gap: 8px; flex-wrap: wrap;">
            <button class="btn" onclick="openNewDebtModal()" style="display: flex; align-items: center; gap: 6px;">
              <span>➕</span> <span>Добавить долг или карту</span>
            </button>
            <button class="btn btn-danger" onclick="openPayDebtModal()" style="display: flex; align-items: center; gap: 6px;">
              <span>💳</span> <span>Погасить задолженность</span>
            </button>
          </div>
        </div>

        <div class="grid-3" style="margin-bottom: 18px;">
          <div class="card" style="margin-bottom: 0;">
            <div class="stat-label">Общая задолженность семьи</div>
            <div class="stat-val danger" id="debtsTabTotal">0.00 ₽</div>
            <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Все кредиты и карты</p>
          </div>
          <div class="card" style="margin-bottom: 0;">
            <div class="stat-label">Долг по кредитным картам</div>
            <div class="stat-val" style="color: #fb7185;" id="debtsTabCards">0.00 ₽</div>
            <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Вычитается из Safe-to-Spend</p>
          </div>
          <div class="card" style="margin-bottom: 0;">
            <div class="stat-label">Кредиты и ипотека</div>
            <div class="stat-val warning" id="debtsTabLoans">0.00 ₽</div>
            <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Долгосрочные обязательства</p>
          </div>
        </div>

        <!-- Credit Card Urgent Alert Banner -->
        <div id="debtsUrgentBanner" class="hidden" style="margin-bottom: 18px; padding: 14px 18px; border-radius: 10px; background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.35); color: #fca5a5; display: flex; align-items: center; gap: 12px;">
          <span style="font-size: 24px;">🚨</span>
          <div id="debtsUrgentBannerText" style="font-size: 13px; line-height: 1.4;"></div>
        </div>

        <div id="debtsListContainer" style="display: flex; flex-direction: column; gap: 12px;">
          <div style="color: var(--text-muted); font-size: 13px;">Загрузка задолженностей...</div>
        </div>
      </div>

      <!-- Tab: Financial Analytics & Cash Flow Forecast -->

      <div id="tab-analytics" class="hidden">

        <!-- Period Filter Pills -->

        <div class="period-pills">

          <button class="pill-btn active" id="pillCurrentMonth" onclick="changeAnalyticsPeriod('current_month')">Текущий месяц</button>

          <button class="pill-btn" id="pillPrevMonth" onclick="changeAnalyticsPeriod('prev_month')">Прошлый месяц</button>

          <button class="pill-btn" id="pill30d" onclick="changeAnalyticsPeriod('30d')">Последние 30 дней</button>

          <button class="pill-btn" id="pill90d" onclick="changeAnalyticsPeriod('90d')">Последние 90 дней</button>

          <button class="pill-btn" id="pillAll" onclick="changeAnalyticsPeriod('all')">За всё время</button>

        </div>

        <!-- 4 KPI Summary Cards -->

        <div class="grid-3" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">

          <div class="card">

            <div class="stat-label">Доходы за период</div>

            <div class="stat-val success" id="analyticsTotalIncome">0.00 ₽</div>

            <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;" id="analyticsIncomeSub">Зарплата и поступления</p>

          </div>

          <div class="card">

            <div class="stat-label">Расходы за период</div>

            <div class="stat-val danger" id="analyticsTotalExpense">0.00 ₽</div>

            <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;" id="analyticsExpenseSub">Все покупки и платежи</p>

          </div>

          <div class="card">

            <div class="stat-label">Норма сбережений (Savings Rate)</div>

            <div class="stat-val" id="analyticsSavingsRate" style="color: #60a5fa;">0.0%</div>

            <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;" id="analyticsSavingsSub">Чистая дельта: 0.00 ₽</p>

          </div>

          <div class="card">

            <div class="stat-label">Автономность (Runway)</div>

            <div class="stat-val warning" id="analyticsRunway">∞ дней</div>

            <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;" id="analyticsRunwaySub">Средний расход: 0.00 ₽/день</p>

          </div>

        </div>

        <!-- Category Breakdown & Visual Donut Chart -->

        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin-bottom: 20px;">

          <!-- Left: SVG Donut Chart -->

          <div class="card">

            <h3 style="font-size: 16px; margin-bottom: 12px; display: flex; align-items: center; justify-content: space-between;">

              <span>🍩 Структура расходов семьи</span>

              <span id="analyticsPeriodLabel" style="font-size: 12px; color: var(--text-muted); font-weight: normal;"></span>

            </h3>

            <div id="donutChartContainer" style="display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 240px;">

              <!-- Pure SVG Donut will be rendered here -->

            </div>

            <div id="donutLegend" style="margin-top: 12px; max-height: 160px; overflow-y: auto;"></div>

          </div>

          <!-- Right: Category List with Progress Bars & Members Attribution -->

          <div class="card">

            <h3 style="font-size: 16px; margin-bottom: 12px;">📊 Рейтинг категорий расходов</h3>

            <div id="categoriesBarsContainer" style="max-height: 220px; overflow-y: auto; margin-bottom: 16px;"></div>

            <h4 style="font-size: 14px; margin-bottom: 8px; border-top: 1px solid var(--border); padding-top: 12px;">

              👥 Распределение по членам семьи

            </h4>

            <div id="membersBarsContainer"></div>

          </div>

        </div>

        <!-- Top 5 Largest Expenses -->

        <div class="card" style="margin-bottom: 20px;">

          <h3 style="font-size: 16px; margin-bottom: 10px;">🏆 Топ-5 крупнейших расходов периода</h3>

          <table>

            <thead>

              <tr>

                <th>Дата</th>

                <th>Описание</th>

                <th>Категория</th>

                <th>Сумма</th>

              </tr>

            </thead>

            <tbody id="topExpensesBody"></tbody>

          </table>

        </div>

        <!-- Cash Flow 30/60/90-Day Predictive Forecast Section -->

        <div class="card" style="border: 1px solid #3b82f6;">

          <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 14px;">

            <div>

              <h3 style="font-size: 17px; color: #60a5fa; display: flex; align-items: center; gap: 8px;">

                <span>🔮</span> Прогноз ликвидности (Cash Flow)

              </h3>

              <p style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">

                Моделирует ежедневную траекторию с учётом графика обязательств и повседневных трат.

              </p>

            </div>

            <div style="display: flex; gap: 8px; align-items: center;">

              <button class="pill-btn active" id="btnForecast30" onclick="changeForecastHorizon(30)">30 дней</button>

              <button class="pill-btn" id="btnForecast60" onclick="changeForecastHorizon(60)">60 дней</button>

              <button class="pill-btn" id="btnForecast90" onclick="changeForecastHorizon(90)">90 дней</button>

              <label style="font-size: 12px; color: var(--text-muted); display: inline-flex; align-items: center; gap: 4px; margin-left: 8px; cursor: pointer;">

                <input type="checkbox" id="chkIncludeBurn" checked onchange="toggleForecastBurn()"> Повседневные траты

              </label>

            </div>

          </div>

          <!-- Deficit Alert Banner if Gap Detected -->

          <div id="forecastDeficitAlert" class="hidden alert alert-error" style="display: flex; align-items: center; justify-content: space-between; gap: 12px;">

            <div>

              <strong style="display: block; font-size: 15px;">⚠️ Обнаружен прогнозный кассовый разрыв!</strong>

              <span id="forecastDeficitText" style="font-size: 13px;"></span>

            </div>

            <div style="font-size: 20px; font-weight: 700; color: #ef4444; white-space: nowrap;" id="forecastDeficitBadge"></div>

          </div>

          <!-- Forecast Stats Strip -->

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; margin-bottom: 16px; background: var(--card-hover); border-radius: 8px; padding: 12px;">

            <div>

              <div style="font-size: 11px; color: var(--text-muted);">Стартовая ликвидность:</div>

              <div style="font-size: 15px; font-weight: 700;" id="fcStartLiquid">0.00 ₽</div>

            </div>

            <div>

              <div style="font-size: 11px; color: var(--text-muted);">Долг по кредиткам:</div>

              <div style="font-size: 15px; font-weight: 700; color: #f87171;" id="fcCreditDebt">0.00 ₽</div>

            </div>

            <div>

              <div style="font-size: 11px; color: var(--text-muted);">Оценка трат/день:</div>

              <div style="font-size: 15px; font-weight: 700; color: #fbbf24;" id="fcDailyBurn">0.00 ₽</div>

            </div>

            <div>

              <div style="font-size: 11px; color: var(--text-muted);">Мин. баланс периода:</div>

              <div style="font-size: 15px; font-weight: 700;" id="fcMinBalance">0.00 ₽</div>

            </div>

          </div>

          <!-- SVG Cash Flow Area / Line Chart Container -->

          <div class="chart-box" style="padding: 10px;">

            <div id="cashFlowChartSvg" style="width: 100%; min-height: 220px; overflow-x: auto;">

              <!-- Pure SVG Cash Flow Line Chart rendered here -->

            </div>

          </div>

          <!-- Upcoming Critical Milestones in Forecast Period -->

          <h4 style="font-size: 14px; margin-top: 14px; margin-bottom: 8px;">🗓️ Ближайшие обязательные списания по календарю:</h4>

          <div id="forecastMilestonesList" style="display: flex; gap: 8px; overflow-x: auto; padding-bottom: 8px;"></div>

        </div>

      </div>

      <!-- Tab 2: New Transaction (Fast Mobile Entry) -->

      <div id="tab-tx" class="hidden">

        <div class="card" style="max-width: 600px; margin: 0 auto;">

          <!-- Express 1-Line Input -->

          <div style="border-left: 4px solid var(--primary); background: var(--card-hover); border-radius: 8px; padding: 12px; margin-bottom: 18px;">

            <div style="font-weight: 600; font-size: 14px; margin-bottom: 6px; color: var(--text);">⚡ Экспресс-запись в 1 строку:</div>

            <div style="display: flex; gap: 8px;">

              <input type="text" id="txQuickInput" placeholder="Например: 500 кофе, 1500 продукты, 850 аптека..." 

                     style="flex: 1;" oninput="onQuickInputLive(this.value, 'txQuickPreview')"

                     onkeydown="if(event.key==='Enter')submitQuickInput('txQuickInput', 'txQuickMsg')">

              <button class="btn" onclick="submitQuickInput('txQuickInput', 'txQuickMsg')">⚡ Записать</button>

            </div>

            <div id="txQuickPreview" class="alert alert-info hidden" style="margin-top: 8px; margin-bottom: 4px; padding: 6px 12px; font-size: 12px;"></div>

            <div id="txQuickMsg" style="margin-top: 6px;"></div>

            <div style="display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px;">

              <span style="font-size: 11px; color: var(--text-muted); align-self: center;">Частые траты:</span>

              <button type="button" class="btn btn-secondary" style="padding: 3px 8px; font-size: 11px;" onclick="applyQuickPreset('1000 продукты')">🛒 Продукты 1000 ₽</button>

              <button type="button" class="btn btn-secondary" style="padding: 3px 8px; font-size: 11px;" onclick="applyQuickPreset('300 кофе')">☕ Кофе 300 ₽</button>

              <button type="button" class="btn btn-secondary" style="padding: 3px 8px; font-size: 11px;" onclick="applyQuickPreset('500 такси')">🚖 Такси 500 ₽</button>

              <button type="button" class="btn btn-secondary" style="padding: 3px 8px; font-size: 11px;" onclick="applyQuickPreset('2000 бензин')">⛽ Бензин 2000 ₽</button>

              <button type="button" class="btn btn-secondary" style="padding: 3px 8px; font-size: 11px;" onclick="applyQuickPreset('500 аптека')">💊 Аптека 500 ₽</button>

            </div>

          </div>

          <h3 style="margin-bottom: 14px; font-size: 16px; border-top: 1px solid var(--border); padding-top: 14px;">📝 Подробная форма записи операции</h3>

          <div id="txMsg"></div>

          

          <div class="form-group">
<label>📅 Дата операции (можно указать прошлый месяц):</label>
<div style="display: flex; gap: 8px; align-items: center;">
<input type="date" id="txDate" class="form-control" style="flex: 1; padding: 10px 12px; font-size: 14px;">
<button type="button" class="btn btn-secondary" style="font-size: 12px; padding: 8px 12px; white-space: nowrap;" onclick="setTxDateToday()">Сегодня</button>
<button type="button" class="btn btn-secondary" style="font-size: 12px; padding: 8px 12px; white-space: nowrap;" onclick="setTxDateYesterday()">Вчера</button>
</div>
</div>
<div class="form-group">
            <label style="margin-bottom: 8px;">Тип операции (нажмите для переключения):</label>
            <div class="tx-type-segment-group">
              <button type="button" id="segBtnExpense" class="tx-type-segment-btn active-expense" onclick="setTxTypeSegment('EXPENSE')">
                <span style="font-size: 16px;">🔴</span> Расход семьи
              </button>
              <button type="button" id="segBtnIncome" class="tx-type-segment-btn" onclick="setTxTypeSegment('INCOME')">
                <span style="font-size: 16px;">🟢</span> Доход семьи
              </button>
            </div>
            <select id="txType" onchange="onTxTypeChange()" style="display: none;">
              <option value="EXPENSE">Расход семьи</option>
              <option value="INCOME">Доход семьи</option>
            </select>
          </div>

          <!-- Выпадающее меню выбора категории (Category Dropdown Menu) -->

          <div class="form-group" style="position: relative;">

            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">

              <label style="margin-bottom: 0;">Статья / Категория (выпадающее меню):</label>

              <span id="txCatBadge" class="badge" style="background: rgba(239,68,68,0.2); color: #fca5a5; font-size: 11px;">Расход</span>

            </div>

            

            <div id="txCatTrigger" class="category-dropdown-trigger" onclick="toggleCategoryDropdown('txCatMenu')">

              <div style="display: flex; align-items: center; gap: 10px; overflow: hidden;">

                <span id="txCatSelectedIcon" style="font-size: 22px; line-height: 1;">🛒</span>

                <div style="text-align: left; line-height: 1.25;">

                  <div id="txCatSelectedName" style="font-size: 14px; font-weight: 600; color: var(--text);">Продукты и супермаркеты</div>

                  <div id="txCatSelectedParent" style="font-size: 11px; color: var(--text-muted);">Нажмите для выбора из меню категорий</div>

                </div>

              </div>

              <div style="display: flex; align-items: center; gap: 8px;">

                <span style="font-size: 12px; color: #60a5fa; background: rgba(59,130,246,0.15); padding: 3px 8px; border-radius: 6px; font-weight: 600;">Выбрать категорию ▼</span>

              </div>

            </div>

            <div id="txCatMenu" class="category-dropdown-menu hidden">

              <div class="category-dropdown-search">

                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                  <span style="font-size: 13px; font-weight: 700; color: var(--text);">🏷️ Выберите статью / категорию</span>
                  <button type="button" onclick="document.getElementById('txCatMenu').classList.add('hidden')" style="background: transparent; border: none; font-size: 18px; color: var(--text-muted); cursor: pointer; padding: 0 4px; line-height: 1;">✕</button>
                </div>

                <input type="text" id="txCatSearchInput" placeholder="🔍 Найти категорию (еда, бензин, аптека...)" 

                       oninput="filterCategoryDropdown('txCatMenu', this.value)">

                <div style="display: flex; gap: 4px; margin-top: 6px;">

                  <button type="button" class="btn btn-secondary cat-filter-btn active" onclick="setCatMenuFilter('txCatMenu', 'ALL', this)" style="padding: 2px 8px; font-size: 11px;">Все</button>

                  <button type="button" class="btn btn-secondary cat-filter-btn" onclick="setCatMenuFilter('txCatMenu', 'EXPENSE', this)" style="padding: 2px 8px; font-size: 11px;">🔴 Расходы</button>

                  <button type="button" class="btn btn-secondary cat-filter-btn" onclick="setCatMenuFilter('txCatMenu', 'INCOME', this)" style="padding: 2px 8px; font-size: 11px;">🟢 Доходы</button>

                </div>

              </div>

              <div id="txCatList" class="category-dropdown-list"></div>

            </div>

            <!-- Скрытый нативный select для обратной совместимости -->

            <select id="txCategorySelect" style="display: none;"></select>

          </div>

          <div class="form-group">

            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">

              <label style="margin-bottom: 0;">Сумма в рублях:</label>

              <div style="display: flex; gap: 4px;">

                <button type="button" class="btn btn-secondary" style="padding: 2px 6px; font-size: 11px;" onclick="addTxAmount(100)">+100</button>

                <button type="button" class="btn btn-secondary" style="padding: 2px 6px; font-size: 11px;" onclick="addTxAmount(500)">+500</button>

                <button type="button" class="btn btn-secondary" style="padding: 2px 6px; font-size: 11px;" onclick="addTxAmount(1000)">+1000</button>

                <button type="button" class="btn btn-secondary" style="padding: 2px 6px; font-size: 11px;" onclick="addTxAmount(5000)">+5000</button>

                <button type="button" class="btn btn-secondary" style="padding: 2px 6px; font-size: 11px;" onclick="document.getElementById('txAmount').value=''">Сброс</button>

              </div>

            </div>

            <input type="number" step="0.01" id="txAmount" placeholder="1500.00" style="font-size: 18px; font-weight: 700; color: #60a5fa;">

          </div>

          <div class="form-group"><label>Счет списания/зачисления:</label><select id="txAccount" onchange="checkPersonalCardExpense()"></select></div>

          <div class="form-group"><label>Описание / комментарий:</label><input type="text" id="txDescription" placeholder="Например: Супермаркет Продукты" oninput="autoSelectCategoryByDesc(this.value)"></div>

          

          <div class="form-group" id="personalExpenseOption" style="display: none; background: rgba(59,130,246,0.1); padding: 10px; border-radius: 6px; border: 1px dashed var(--primary);">

            <label style="color: #93c5fd; display: flex; align-items: center; gap: 8px; cursor: pointer;">

              <input type="checkbox" id="chkPersonalForCommon" style="width: auto;">

              <span><strong>Оплата общих нужд с личной карты</strong> (списание в единый семейный бюджет без образования автодолга)</span>

            </label>

          </div>

          

          <button class="btn" style="width: 100%; padding: 12px; font-size: 16px;" id="btnSubmitTx" onclick="submitTransaction()">💾 Сохранить операцию</button>

        </div>

      </div>

      <!-- Tab 3: Monthly Fixed Obligations -->

      <div id="tab-obligations" class="hidden">

        <div class="card">

          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; flex-wrap: wrap; gap: 8px;">

            <div>

              <h3 style="font-size: 17px;">Регулярные обязательные платежи</h3>

              <p style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">Аренда, ипотека, ЖКХ, связь, кредиты. Неоплаченные платежи автоматически вычитаются из Safe-to-Spend.</p>

            </div>

            <button class="btn btn-secondary" onclick="toggleNewObligationForm()">➕ Добавить платеж</button>

          </div>

          <!-- Add Obligation Form -->

          <div id="divNewObligation" class="card hidden" style="background: var(--card-hover); border-color: var(--primary);">

            <h4 style="margin-bottom: 12px;">Новый обязательный платеж</h4>

            <div id="oblMsg"></div>

            <div style="display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 12px;">

              <div class="form-group"><label>Название платежа:</label><input type="text" id="newOblName" placeholder="Например: Аренда квартиры"></div>

              <div class="form-group"><label>Сумма в месяц (₽):</label><input type="number" step="0.01" id="newOblAmount" placeholder="35000.00"></div>

              <div class="form-group"><label>День списания (1-31):</label><input type="number" min="1" max="31" id="newOblDueDay" value="15"></div>

            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">

              <div class="form-group"><label>Категория:</label><select id="newOblCategory"></select></div>

              <div class="form-group"><label>Счет списания (по умолчанию):</label><select id="newOblAccount"></select></div>

            </div>

            <div class="form-group"><label>Заметка / примечание:</label><input type="text" id="newOblNote" placeholder="Опционально"></div>

            <div style="display: flex; gap: 10px;">

              <button class="btn" onclick="submitCreateObligation()">Сохранить платеж</button>

              <button class="btn btn-secondary" onclick="toggleNewObligationForm()">Отмена</button>

            </div>

          </div>

          <!-- Obligations Table / Cards -->

          <div id="obligationsListContainer"></div>

        </div>

      </div>

      <!-- Tab 4: Accounts Management -->

      <div id="tab-accounts" class="hidden">

        <div class="card">

          <h3 style="margin-bottom: 14px; font-size: 16px;">Добавить новый счет</h3>

          <div id="accMsg"></div>

          <div style="display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 12px;">

            <div class="form-group"><label>Название счета:</label><input type="text" id="newAccName" placeholder="Например: Т-Банк Black Муж"></div>

            <div class="form-group"><label>Тип счета:</label>

              <select id="newAccSubtype" onchange="toggleCreditLimitField()">

                <option value="DEBIT_CARD">Дебетовая карта</option>

                <option value="CASH">Наличные</option>

                <option value="CHECKING">Текущий счет</option>

                <option value="SAVINGS">Накопительный счет</option>

                <option value="DEPOSIT">Вклад</option>

                <option value="CREDIT_CARD">Кредитная карта</option>

              </select>

            </div>

            <div class="form-group"><label>Принадлежность:</label>

              <select id="newAccScope">

                <option value="COMMON">Общий семейный</option>

                <option value="PERSONAL_HUSBAND">Муж (Личный)</option>

                <option value="PERSONAL_WIFE">Жена (Личный)</option>

              </select>

            </div>

          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">

            <div class="form-group"><label>Начальный остаток (₽):</label><input type="number" step="0.01" id="newAccInitBal" placeholder="0.00"></div>

            <div class="form-group" id="divCreditLimit" style="display: none;"><label>Кредитный лимит (₽):</label><input type="number" step="0.01" id="newAccCreditLimit" placeholder="0.00"></div>

          </div>

          <div class="form-group"><label>Описание / Заметка:</label><input type="text" id="newAccDesc" placeholder="Опционально"></div>

          <button class="btn" id="btnCreateAcc" onclick="submitCreateAccount()">Создать счет</button>

        </div>

        <div class="card">

          <h3 style="margin-bottom: 12px; font-size: 16px;">Список активных счетов</h3>

          <table>

            <thead>

              <tr>

                <th>Код</th>

                <th>Название</th>

                <th>Тип</th>

                <th>Принадлежность</th>

                <th>Баланс</th>

                <th>Кредитный лимит</th>

                <th>Действия</th>

              </tr>

            </thead>

            <tbody id="manageAccountsBody"></tbody>

          </table>

        </div>

      </div>

      <!-- Tab 5: Categories Hierarchy -->

      <div id="tab-categories" class="hidden">

        <div class="card">

          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; flex-wrap: wrap; gap: 8px;">

            <div>

              <h3 style="font-size: 17px;">Дерево категорий семьи</h3>

              <p style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">Иерархический каталог расходов и доходов с подкатегориями</p>

            </div>

            <button class="btn btn-secondary" onclick="toggleNewCategoryForm()">➕ Новая категория</button>

          </div>

          <!-- Add Category Form -->

          <div id="divNewCategory" class="card hidden" style="background: var(--card-hover); border-color: var(--primary);">

            <h4 style="margin-bottom: 12px;">Создать категорию</h4>

            <div id="catMsg"></div>

            <div style="display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 12px;">

              <div class="form-group"><label>Название:</label><input type="text" id="newCatName" placeholder="Например: Стоматология"></div>

              <div class="form-group"><label>Тип:</label>

                <select id="newCatType">

                  <option value="EXPENSE">Расход</option>

                  <option value="INCOME">Доход</option>

                </select>

              </div>

              <div class="form-group"><label>Иконка / Эмодзи:</label><input type="text" id="newCatIcon" value="🏷️"></div>

            </div>

            <div class="form-group"><label>Родительская категория (оставьте пустым для корневой):</label>

              <select id="newCatParent"></select>

            </div>

            <div style="display: flex; gap: 10px;">

              <button class="btn" onclick="submitCreateCategory()">Сохранить категорию</button>

              <button class="btn btn-secondary" onclick="toggleNewCategoryForm()">Отмена</button>

            </div>

          </div>

          <div id="categoryTreeContainer"></div>

        </div>

      </div>

      <!-- Tab 6: Internal Transfer -->

      <div id="tab-transfer" class="hidden">

        <div class="card" style="max-width: 600px; margin: 0 auto;">

          <h3 style="margin-bottom: 14px; font-size: 16px;">Внутренний перевод между счетами</h3>

          <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">

            Двойная запись Дт/Кт: перемещение средств между картами, наличными, вкладами или погашение кредитных карт. Не меняет общий капитал семьи.

          </p>

          <div id="trMsg"></div>

          <div class="form-group"><label>Счет списания (Откуда):</label><select id="trFromAccount"></select></div>

          <div class="form-group"><label>Счет зачисления (Куда):</label><select id="trToAccount"></select></div>

          <div class="form-group"><label>Сумма перевода (₽):</label><input type="number" step="0.01" id="trAmount" placeholder="5000.00"></div>

          <div class="form-group"><label>Назначение перевода:</label><input type="text" id="trDesc" value="Внутренний перевод средств"></div>

          <button class="btn" style="width: 100%;" id="btnSubmitTransfer" onclick="submitTransfer()">Выполнить перевод</button>

        </div>

      </div>

      <!-- Tab 7: Ledger / Change Log -->

      <div id="tab-ledger" class="hidden">

        <div class="card">

          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">

            <h3 style="font-size: 16px;">Журнал бухгалтерских проводок (Аудит)</h3>

            <button class="btn btn-secondary" style="font-size: 12px; padding: 4px 10px;" onclick="loadTransactions()">Обновить</button>

          </div>

          <div style="overflow-x: auto; -webkit-overflow-scrolling: touch;">
          <table class="revolut-ledger-table">

            <thead>

              <tr>

                <th>Дата</th>

                <th>Категория</th>

                <th>Описание</th>

                <th>Проводки (Дт / Кт)</th>
<th style="text-align: right;">Сумма</th>
<th style="text-align: right; width: 120px;">Действия</th>
</tr>

            </thead>

            <tbody id="txTableBody"></tbody>

          </table>
          </div>

        </div>

      </div>

      <!-- Tab 8: Bank Statement Importer -->

      <div id="tab-import" class="hidden">

        <div class="card" style="max-width: 850px; margin: 0 auto;">

          <h3 style="font-size: 17px; margin-bottom: 8px;">📥 Универсальный импорт банковских выписок</h3>

          <p style="color: var(--text-muted); font-size: 13px; margin-bottom: 16px;">

            Загрузите выписку банка (Сбер, Т-Банк, Альфа, ВТБ) в формате CSV или вставьте текст выписки.

            Система автоматически определит доходы и расходы, подберет категории и защитит от повторного добавления.

          </p>

          <div class="form-group">

            <label>Целевой счет зачисления / списания:</label>

            <select id="importAccountSelect"></select>

          </div>

          <div class="form-group">

            <label>Выберите файл выписки (.csv, .txt):</label>

            <input type="file" id="importFileInput" accept=".csv,.txt" onchange="handleFileSelect(event)">

          </div>

          <div class="form-group">

            <label>Или вставьте текст CSV выписки напрямую:</label>

            <textarea id="importRawText" rows="6" style="width:100%; font-family:monospace; font-size:12px; background:var(--input-bg); border:1px solid var(--border); border-radius:6px; color:var(--text); padding:8px;" placeholder="Дата;Описание;Сумма&#10;09.11.2026;Супермаркет Перекресток;-1450.00&#10;08.11.2026;Зарплата от работодателя;+85000.00"></textarea>

          </div>

          <button class="btn" style="width:100%; margin-bottom: 16px;" onclick="runImportPreview()">

            🔍 Распознать операции и показать предпросмотр

          </button>

          <div id="importPreviewContainer" class="hidden">

            <h4 style="font-size: 15px; margin-bottom: 8px;" id="importPreviewCount">Распознано операций: 0</h4>

            <div style="max-height: 350px; overflow-y: auto; margin-bottom: 16px;">

              <table>

                <thead>

                  <tr>

                    <th>Дата</th>

                    <th>Направление</th>

                    <th>Описание</th>

                    <th>Категория</th>

                    <th>Сумма</th>

                  </tr>

                </thead>

                <tbody id="importPreviewBody"></tbody>

              </table>

            </div>

            <button class="btn" style="width:100%; background: #10b981;" id="btnConfirmImport" onclick="confirmImport()">

              ✅ Провести операции в семейную книгу

            </button>

          </div>

        </div>

      </div>

    </div>

  </div>

  <!-- Mobile Bottom Navigation Bar -->

  <div id="mobileBottomNav" class="mobile-bottom-nav hidden">

    <button class="mobile-nav-item active" onclick="switchTab('tab-overview')">

      <span class="icon">📊</span>

      <span>Сводка</span>

    </button>

    <button class="mobile-nav-item" onclick="switchTab('tab-analytics')">

      <span class="icon">📈</span>

      <span>Анализ</span>

    </button>

    <button class="mobile-nav-item" onclick="switchTab('tab-tx')">

      <span class="icon">➕</span>

      <span>Расход</span>

    </button>

    <button class="mobile-nav-item" onclick="switchTab('tab-obligations')">

      <span class="icon">📅</span>

      <span>Платежи</span>

    </button>

    <button class="mobile-nav-item" onclick="switchTab('tab-accounts')">

      <span class="icon">💳</span>

      <span>Счета</span>

    </button>

  </div>

  <script>

    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str)
        .split('&').join('&amp;')
        .split('<').join('&lt;')
        .split('>').join('&gt;')
        .split(String.fromCharCode(34)).join('&quot;')
        .split(String.fromCharCode(39)).join('&#039;');
    }

    function initTheme() {
      const saved = localStorage.getItem('ffos_theme') || (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
      applyTheme(saved);
    }

    function applyTheme(theme) {
      document.documentElement.setAttribute('data-theme', theme);
      localStorage.setItem('ffos_theme', theme);
      const iconEl = document.getElementById('themeToggleIcon');
      const textEl = document.getElementById('themeToggleText');
      if (iconEl && textEl) {
        if (theme === 'light') {
          iconEl.innerText = '🌙';
          textEl.innerText = 'Тёмная';
        } else {
          iconEl.innerText = '☀️';
          textEl.innerText = 'Светлая';
        }
      }
    }

    function toggleTheme() {
      const current = document.documentElement.getAttribute('data-theme') || 'dark';
      const next = (current === 'light') ? 'dark' : 'light';
      applyTheme(next);
    }

    initTheme();

    let sessionToken = sessionStorage.getItem('ffos_session_token') || localStorage.getItem('ffos_session_token');

    let overviewData = null;

    let categoryData = null;

    let selectedChipCategoryId = null;

    let activeTxIdempotencyKey = generateFormKey('tx');

    let activeTrIdempotencyKey = generateFormKey('tr');

    // Auto-lock on idle timer (15 minutes)

    let lastActivityTime = Date.now();

    const IDLE_TIMEOUT_MS = 15 * 60 * 1000;

    function resetActivityTimer() {

      lastActivityTime = Date.now();

    }

    ['mousemove', 'keydown', 'touchstart', 'scroll'].forEach(evt => {

      window.addEventListener(evt, resetActivityTimer, { passive: true });

    });

    setInterval(() => {

      if (sessionToken && Date.now() - lastActivityTime > IDLE_TIMEOUT_MS) {

        console.warn('Auto-locking due to inactivity...');

        submitLock();

      }

    }, 30000);

    function generateFormKey(prefix) {

      return prefix + '_' + Date.now() + '_' + Math.random().toString(36).substring(2, 9);

    }

    function authHeaders() {

      const headers = { 'Content-Type': 'application/json' };

      if (sessionToken) headers['Authorization'] = 'Bearer ' + sessionToken;

      return headers;

    }

    // --- Stage 8 PWA & Offline Support ---

    if ('serviceWorker' in navigator) {

      window.addEventListener('load', () => {

        navigator.serviceWorker.register('/sw.js')

          .then(reg => console.log('[PWA] Service Worker зарегистрирован:', reg.scope))

          .catch(err => console.log('[PWA] Ошибка регистрации Service Worker:', err));

      });

    }

    let deferredInstallPrompt = null;

    window.addEventListener('beforeinstallprompt', (e) => {

      e.preventDefault();

      deferredInstallPrompt = e;

      const btn = document.getElementById('btnInstallPwa');

      if (btn) btn.classList.remove('hidden');

    });

    function installPwaPrompt() {

      if (!deferredInstallPrompt) return;

      deferredInstallPrompt.prompt();

      deferredInstallPrompt.userChoice.then((choiceResult) => {

        if (choiceResult.outcome === 'accepted') {

          const btn = document.getElementById('btnInstallPwa');

          if (btn) btn.classList.add('hidden');

        }

        deferredInstallPrompt = null;

      });

    }

    // --- Stage 8 QR Pairing & Auto-Login ---

    async function checkPairTokenInUrl() {

      const urlParams = new URLSearchParams(window.location.search);

      const pairToken = urlParams.get('pair_token');

      if (!pairToken) return false;

      try {

        const res = await fetch('/api/auth/pair-login', {

          method: 'POST',

          headers: { 'Content-Type': 'application/json' },

          body: JSON.stringify({ token: pairToken })

        });

        const data = await res.json();

        if (data.status === 'ok' && data.session_token) {

          sessionStorage.setItem('ffos_session_token', data.session_token);

          sessionToken = data.session_token;

          if (data.user) sessionStorage.setItem('ffos_user', JSON.stringify(data.user));

          window.history.replaceState({}, document.title, window.location.pathname);

          return true;

        }

      } catch (err) {

        console.warn('[Pairing] Не удалось войти по QR-токену:', err);

      }

      return false;

    }

    async function openQrPairModal() {

      const modal = document.getElementById('modalQrPair');

      if (!modal) return;

      modal.classList.remove('hidden');

      await loadQrPairData();

    }

    function closeQrPairModal() {

      const modal = document.getElementById('modalQrPair');

      if (modal) modal.classList.add('hidden');

    }

    async function loadQrPairData(overrideIp = '') {

      const token = sessionToken || sessionStorage.getItem('ffos_session_token');

      const svgBox = document.getElementById('qrPairSvgBox');

      const urlInput = document.getElementById('qrPairUrlInput');

      const ipInput = document.getElementById('qrPairOverrideIp');

      let apiUrl = '/api/device/qr-pair';

      if (overrideIp) {

        apiUrl += '?override_ip=' + encodeURIComponent(overrideIp);

      }

      try {

        const res = await fetch(apiUrl, {

          headers: { 'Authorization': 'Bearer ' + token }

        });

        if (!res.ok) {

          if (svgBox) svgBox.innerHTML = '<div style="color:#ef4444; padding:20px;">Требуется авторизация</div>';

          return;

        }

        const data = await res.json();

        if (data.ok) {

          if (svgBox) svgBox.innerHTML = data.qr_svg;

          if (urlInput) urlInput.value = data.pair_url;

          if (ipInput && !overrideIp) ipInput.value = data.lan_ip;

        }

      } catch (err) {

        if (svgBox) svgBox.innerHTML = '<div style="color:#ef4444; padding:20px;">Ошибка генерации QR-кода</div>';

      }

    }

    function regenerateQrPair() {

      const ipInput = document.getElementById('qrPairOverrideIp');

      const customIp = ipInput ? ipInput.value.trim() : '';

      loadQrPairData(customIp);

    }

    function copyQrPairUrl() {

      const urlInput = document.getElementById('qrPairUrlInput');

      if (!urlInput) return;

      urlInput.select();

      navigator.clipboard.writeText(urlInput.value).then(() => {

        alert('Ссылка сопряжения скопирована в буфер обмена!');

      }).catch(() => {

        document.execCommand('copy');

        alert('Ссылка скопирована!');

      });

    }

    let modalTxActiveType = 'EXPENSE';

    // Open New Transaction Modal / Bottom Sheet (Revolut mobile bottom sheet & desktop modal)
    function openNewTxModal(type = 'EXPENSE') {
      type = (type || 'EXPENSE').toUpperCase();
      const modal = document.getElementById('modalNewTx');
      if (modal) {
        modal.classList.remove('hidden');
        setModalTxType(type);
        const dateEl = document.getElementById('txInputDate') || document.getElementById('txDate');
        if (dateEl && !dateEl.value) {
          dateEl.value = new Date().toISOString().slice(0, 10);
        }
        setTimeout(() => {
          const amountEl = document.getElementById('txInputAmount') || document.getElementById('txAmount');
          if (amountEl) {
            amountEl.focus();
            if (amountEl.select) amountEl.select();
          }
        }, 150);
      } else {
        switchTab('tab-tx');
        setTxTypeSegment(type);
        setTimeout(() => {
          const amountEl = document.getElementById('txAmount');
          if (amountEl) {
            amountEl.focus();
          } else {
            const quickEl = document.getElementById('txQuickInput');
            if (quickEl) quickEl.focus();
          }
        }, 120);
      }
    }

    function stopPropagation(e) {
      if (e && e.stopPropagation) {
        e.stopPropagation();
      }
    }

    function closeNewTxModal() {
      const modal = document.getElementById('modalNewTx');
      if (modal) {
        modal.classList.add('hidden');
        const catMenu = document.getElementById('modalTxCatMenu');
        if (catMenu) catMenu.classList.add('hidden');
      }
    }

    function setModalTxType(type = 'EXPENSE') {
      type = (type || 'EXPENSE').toUpperCase();
      modalTxActiveType = type;
      const btnExp = document.getElementById('modalSegBtnExpense');
      const btnInc = document.getElementById('modalSegBtnIncome');
      const ctaBtn = document.getElementById('modalBtnSubmitTx');
      const ctaLabel = document.getElementById('modalBtnSubmitLabel');
      const currSign = document.getElementById('modalTxCurrencySign');
      const badgeEl = document.getElementById('modalTxCatBadge');
      const headerIcon = document.getElementById('modalTxHeaderIcon');
      const headerTitle = document.getElementById('modalTxHeaderTitle');

      if (type === 'EXPENSE') {
        if (btnExp) btnExp.classList.add('active-expense');
        if (btnInc) btnInc.classList.remove('active-income');
        if (ctaBtn) ctaBtn.classList.remove('cta-income');
        if (ctaLabel) ctaLabel.innerText = '💾 Записать расход';
        if (currSign) currSign.style.color = '#f87171';
        if (badgeEl) {
          badgeEl.innerText = 'Расход';
          badgeEl.style.background = 'rgba(239,68,68,0.2)';
          badgeEl.style.color = '#fca5a5';
        }
        if (headerIcon) headerIcon.innerText = '🔴';
        if (headerTitle) headerTitle.innerText = 'Новый расход семьи';
      } else {
        if (btnInc) btnInc.classList.add('active-income');
        if (btnExp) btnExp.classList.remove('active-expense');
        if (ctaBtn) ctaBtn.classList.add('cta-income');
        if (ctaLabel) ctaLabel.innerText = '💾 Записать доход';
        if (currSign) currSign.style.color = '#34d399';
        if (badgeEl) {
          badgeEl.innerText = 'Доход';
          badgeEl.style.background = 'rgba(16,185,129,0.2)';
          badgeEl.style.color = '#6ee7b7';
        }
        if (headerIcon) headerIcon.innerText = '🟢';
        if (headerTitle) headerTitle.innerText = 'Новый доход семьи';
      }

      setTxTypeSegment(type);
      if (typeof filterCategoryDropdown === 'function') {
        filterCategoryDropdown('modalTxCatMenu', '');
      }
    }

    function addTxInputAmount(delta) {
      const el = document.getElementById('txInputAmount');
      const alt = document.getElementById('txAmount');
      const current = parseFloat((el || alt)?.value) || 0;
      const next = current + delta;
      if (el) el.value = next;
      if (alt) alt.value = next;
    }

    function resetModalTxAmount() {
      const el = document.getElementById('txInputAmount');
      const alt = document.getElementById('txAmount');
      if (el) el.value = '';
      if (alt) alt.value = '';
    }

    function syncTxAmount(val) {
      const alt = document.getElementById('txAmount');
      if (alt && alt !== document.activeElement) {
        alt.value = val;
      }
    }

    function setModalTxDateToday() {
      const el = document.getElementById('txInputDate');
      const alt = document.getElementById('txDate');
      const today = new Date().toISOString().slice(0, 10);
      if (el) el.value = today;
      if (alt) alt.value = today;
    }

    function openTransferModal() {
      switchTab('tab-transfer');
    }

    function setTxTypeSegment(type = 'EXPENSE') {
      type = (type || 'EXPENSE').toUpperCase();
      const sel = document.getElementById('txType');
      if (sel) {
        sel.value = type;
      }
      const btnExp = document.getElementById('segBtnExpense');
      const btnInc = document.getElementById('segBtnIncome');
      if (btnExp && btnInc) {
        if (type === 'EXPENSE') {
          btnExp.classList.add('active-expense');
          btnInc.classList.remove('active-income');
        } else {
          btnInc.classList.add('active-income');
          btnExp.classList.remove('active-expense');
        }
      }
      // Also highlight Hero buttons if visible
      const heroExp = document.getElementById('heroBtnExpense');
      const heroInc = document.getElementById('heroBtnIncome');
      if (heroExp && heroInc) {
        if (type === 'EXPENSE') {
          heroExp.classList.add('active-expense');
          heroInc.classList.remove('active-income');
        } else {
          heroInc.classList.add('active-income');
          heroExp.classList.remove('active-expense');
        }
      }
      if (typeof onTxTypeChange === 'function') {
        onTxTypeChange();
      }
    }

    function switchTab(tabId) {
      if (tabId === 'goals') tabId = 'tab-goals';
      if (tabId === 'transfer') tabId = 'tab-transfer';
      if (tabId === 'tx') tabId = 'tab-tx';
      if (tabId && !tabId.startsWith('tab-') && document.getElementById('tab-' + tabId)) {
        tabId = 'tab-' + tabId;
      }

      ['tab-overview', 'tab-analytics', 'tab-accounts', 'tab-tx', 'tab-obligations', 'tab-categories', 'tab-transfer', 'tab-ledger', 'tab-import', 'tab-goals', 'tab-envelopes', 'tab-debts'].forEach(id => {

        const el = document.getElementById(id);

        if (el) el.classList.add('hidden');

      });

      document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));

      document.querySelectorAll('.mobile-nav-item').forEach(btn => btn.classList.remove('active'));

      const targetEl = document.getElementById(tabId);

      if (targetEl) targetEl.classList.remove('hidden');

      // Update desktop buttons

      document.querySelectorAll('.tab-btn').forEach(btn => {

        if (btn.getAttribute('onclick')?.includes(tabId)) {
          btn.classList.add('active');
          try {
            btn.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
          } catch(e) {}
        }

      });

      // Update mobile items

      document.querySelectorAll('.mobile-nav-item').forEach(btn => {

        if (btn.getAttribute('onclick')?.includes(tabId)) btn.classList.add('active');

      });

      if (tabId === 'tab-overview') { loadDashboard(); loadGoalsWidget(); loadEnvelopesWidget(); }

      if (tabId === 'tab-goals') loadGoals();

      if (tabId === 'tab-envelopes') loadEnvelopes();

      if (tabId === 'tab-debts') loadDebts();

      if (tabId === 'tab-analytics') { loadAnalytics(); loadForecast(); }

      if (tabId === 'tab-ledger') loadTransactions(currentSelectedMonth);

      if (tabId === 'tab-obligations') loadObligations();

      if (tabId === 'tab-categories') loadCategories();

      if (tabId === 'tab-tx') renderCategoryCustomDropdowns();

      if (tabId === 'tab-import') populateImportAccounts();

    }

    // --- Stage 7 Analytics & Forecast State & Functions ---

    let currentAnalyticsPeriod = 'current_month';

    let analyticsRequestSequence = 0;
    let analyticsRequestController = null;

    let currentForecastDays = 30;

    let forecastRequestSequence = 0;
    let forecastRequestController = null;

    let forecastIncludeBurn = true;

    function syncAnalyticsPeriodButtons(period) {
      const activeBtnMap = {

        'current_month': 'pillCurrentMonth',

        'prev_month': 'pillPrevMonth',

        '30d': 'pill30d',

        '90d': 'pill90d',

        'all': 'pillAll'

      };

      document.querySelectorAll('.period-pills .pill-btn').forEach(btn => {
        const active = btn.id === activeBtnMap[period];
        btn.classList.toggle('active', active);
        btn.setAttribute('aria-pressed', String(active));
      });
    }

    syncAnalyticsPeriodButtons(currentAnalyticsPeriod);
    [30, 60, 90].forEach(days => {
      const btn = document.getElementById('btnForecast' + days);
      if (btn) btn.setAttribute('aria-pressed', String(days === currentForecastDays));
    });

    function changeAnalyticsPeriod(period) {
      return loadAnalytics(period);
    }

    function changeForecastHorizon(days) {

      currentForecastDays = days;

      [30, 60, 90].forEach(d => {

        const btn = document.getElementById('btnForecast' + d);

        if (btn) {
          btn.classList.toggle('active', d === days);
          btn.setAttribute('aria-pressed', String(d === days));
        }

      });

      loadForecast();

    }

    function toggleForecastBurn() {

      const chk = document.getElementById('chkIncludeBurn');

      forecastIncludeBurn = chk ? chk.checked : true;

      loadForecast();

    }

    async function loadAnalytics(period) {
      const requestSequence = ++analyticsRequestSequence;
      if (analyticsRequestController) analyticsRequestController.abort();
      analyticsRequestController = new AbortController();
      const targetPeriod = period || currentAnalyticsPeriod || currentSelectedMonth || 'current_month';
      currentAnalyticsPeriod = targetPeriod;
      syncAnalyticsPeriodButtons(targetPeriod);
      const analyticsSection = document.getElementById('tab-analytics');
      analyticsSection?.setAttribute('aria-busy', 'true');
      document.getElementById('analyticsPeriodLabel').innerText = 'Загрузка выбранного периода…';
      try {
        const res = await fetch('/api/analytics/summary?period=' + encodeURIComponent(targetPeriod), {
          headers: authHeaders(), signal: analyticsRequestController.signal
        });

        if (res.status === 401 || res.status === 423) return;

        if (!res.ok) throw new Error('HTTP ' + res.status);

        const data = await res.json();

        if (requestSequence !== analyticsRequestSequence) return;

        // 1. KPI Cards

        document.getElementById('analyticsTotalIncome').innerText = data.total_income_rub + ' ₽';

        document.getElementById('analyticsTotalExpense').innerText = data.total_expense_rub + ' ₽';

        

        const srEl = document.getElementById('analyticsSavingsRate');

        srEl.innerText = (data.savings_rate_percent >= 0 ? '+' : '') + data.savings_rate_percent + '%';

        srEl.style.color = data.savings_rate_percent >= 15 ? '#34d399' : (data.savings_rate_percent < 0 ? '#f87171' : '#60a5fa');

        

        document.getElementById('analyticsSavingsSub').innerText = 'Чистая дельта: ' + data.net_savings_rub + ' ₽';

        

        const rwEl = document.getElementById('analyticsRunway');

        if (data.cash_runway_days !== null) {

          rwEl.innerText = data.cash_runway_days + ' дн.';

          rwEl.className = 'stat-val ' + (data.cash_runway_days >= 60 ? 'success' : (data.cash_runway_days < 20 ? 'danger' : 'warning'));

        } else {

          rwEl.innerText = '∞ дней';

          rwEl.className = 'stat-val warning';

        }

        document.getElementById('analyticsRunwaySub').innerText = 'Средний расход: ' + data.daily_avg_expense_rub + ' ₽/день';

        document.getElementById('analyticsPeriodLabel').innerText = data.period_label;

        // 2. Render Donut Chart

        renderDonutChart(data.categories, data.total_expense_cents, data.total_expense_rub);

        // 3. Render Category Bars

        const catBox = document.getElementById('categoriesBarsContainer');

        if (!data.categories || data.categories.length === 0) {

          catBox.innerHTML = '<div style="color:var(--text-muted); font-size:13px; text-align:center; padding:16px;">Расходов в выбранном периоде нет</div>';

        } else {

          catBox.innerHTML = data.categories.slice(0, 7).map(c => `

            <div style="margin-bottom: 10px;">

              <div style="display:flex; justify-content:space-between; font-size:13px;">

                <span>${c.icon || '🏷️'} ${c.name}</span>

                <span style="font-weight:600;">${c.amount_rub} ₽ <span style="color:var(--text-muted); font-weight:normal; font-size:11px;">(${c.percent}%)</span></span>

              </div>

              <div class="progress-bar-bg">

                <div class="progress-bar-fill" style="width: ${c.percent}%;"></div>

              </div>

            </div>

          `).join('');

        }

        // 4. Render Members Bars

        const memBox = document.getElementById('membersBarsContainer');

        if (!data.members || data.members.length === 0) {

          memBox.innerHTML = '<div style="color:var(--text-muted); font-size:13px;">Нет данных</div>';

        } else {

          memBox.innerHTML = data.members.map(m => `

            <div style="margin-bottom: 8px;">

              <div style="display:flex; justify-content:space-between; font-size:13px;">

                <span>${m.icon} ${m.label}</span>

                <span style="font-weight:600;">${m.amount_rub} ₽ <span style="color:var(--text-muted); font-size:11px;">(${m.percent}%)</span></span>

              </div>

              <div class="progress-bar-bg">

                <div class="progress-bar-fill" style="width: ${m.percent}%; background: ${m.scope === 'PERSONAL_HUSBAND' ? '#3b82f6' : (m.scope === 'PERSONAL_WIFE' ? '#ec4899' : '#10b981')};"></div>

              </div>

            </div>

          `).join('');

        }

        // 5. Render Top 5 Expenses

        const topBody = document.getElementById('topExpensesBody');

        if (!data.top_expenses || data.top_expenses.length === 0) {

          topBody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--text-muted);">Крупных операций нет</td></tr>';

        } else {

          topBody.innerHTML = data.top_expenses.map(t => `

            <tr>

              <td>${t.date}</td>

              <td style="font-weight:500;">${escapeHtml(t.description || '')}</td>

              <td>${t.category_icon} ${escapeHtml(t.category_name)}</td>

              <td style="font-weight:600; color:#f87171;">-${t.amount_rub} ₽</td>

            </tr>

          `).join('');

        }

      } catch (err) {

        if (err.name === 'AbortError' || requestSequence !== analyticsRequestSequence) return;
        console.error('Error loading analytics:', err);
        document.getElementById('analyticsPeriodLabel').innerText = 'Не удалось загрузить период. Повторите выбор.';
        ['analyticsTotalIncome', 'analyticsTotalExpense', 'analyticsSavingsRate', 'analyticsRunway'].forEach(id => {
          document.getElementById(id).innerText = '—';
        });
        ['analyticsSavingsSub', 'analyticsRunwaySub', 'donutChartContainer', 'donutLegend',
         'categoriesBarsContainer', 'membersBarsContainer', 'topExpensesBody'].forEach(id => {
          document.getElementById(id).textContent = '';
        });
      } finally {
        if (requestSequence === analyticsRequestSequence) analyticsSection?.setAttribute('aria-busy', 'false');
      }

    }

    function renderDonutChart(categories, totalCents, totalRub) {

      const container = document.getElementById('donutChartContainer');

      const legend = document.getElementById('donutLegend');

      if (!categories || categories.length === 0 || totalCents <= 0) {

        container.innerHTML = `

          <svg viewBox="0 0 240 240" style="width:100%; max-width:220px;">

            <circle cx="120" cy="120" r="70" fill="transparent" stroke="#334155" stroke-width="24" />

            <text x="120" y="118" text-anchor="middle" fill="#94a3b8" font-size="12">Нет расходов</text>

            <text x="120" y="136" text-anchor="middle" fill="#64748b" font-size="11">за период</text>

          </svg>

        `;

        legend.innerHTML = '';

        return;

      }

      const colors = ['#3b82f6', '#10b981', '#f59e0b', '#ec4899', '#8b5cf6', '#06b6d4', '#f97316', '#64748b'];

      const R = 70;

      const C = 2 * Math.PI * R;

      let accumulatedOffset = 0;

      let circlesHtml = '';

      let legendHtml = '';

      categories.slice(0, 8).forEach((cat, idx) => {

        const color = colors[idx % colors.length];

        const sliceLen = (cat.amount_cents / totalCents) * C;

        circlesHtml += `

          <circle cx="120" cy="120" r="${R}" fill="transparent" stroke="${color}" stroke-width="26"

                  stroke-dasharray="${sliceLen.toFixed(1)} ${(C - sliceLen).toFixed(1)}"

                  stroke-dashoffset="${(-accumulatedOffset).toFixed(1)}"

                  transform="rotate(-90 120 120)" style="transition: stroke-width 0.2s;" />

        `;

        accumulatedOffset += sliceLen;

        legendHtml += `

          <div class="legend-item">

            <span style="display:flex; align-items:center;">

              <span class="legend-dot" style="background:${color};"></span>

              <span>${cat.icon || '🏷️'} ${cat.name}</span>

            </span>

            <span style="font-weight:600;">${cat.amount_rub} ₽ <span style="color:var(--text-muted); font-size:11px;">(${cat.percent}%)</span></span>

          </div>

        `;

      });

      container.innerHTML = `

        <svg viewBox="0 0 240 240" style="width:100%; max-width:230px;">

          <circle cx="120" cy="120" r="${R}" fill="transparent" stroke="#1e293b" stroke-width="26" />

          ${circlesHtml}

          <text x="120" y="112" text-anchor="middle" fill="#94a3b8" font-size="11" font-weight="600">ИТОГО ТРАТ</text>

          <text x="120" y="132" text-anchor="middle" fill="#f8fafc" font-size="14" font-weight="700">${totalRub} ₽</text>

        </svg>

      `;

      legend.innerHTML = legendHtml;

    }

    async function loadForecast() {
      const requestSequence = ++forecastRequestSequence;
      if (forecastRequestController) forecastRequestController.abort();
      forecastRequestController = new AbortController();
      const forecastChart = document.getElementById('cashFlowChartSvg');
      forecastChart?.setAttribute('aria-busy', 'true');
      try {

        const res = await fetch('/api/forecast/cashflow?days=' + currentForecastDays + '&include_burn=' + (forecastIncludeBurn ? '1' : '0'), {
          headers: authHeaders(), signal: forecastRequestController.signal
        });

        if (res.status === 401 || res.status === 423) return;

        if (!res.ok) throw new Error('HTTP ' + res.status);

        const data = await res.json();

        if (requestSequence !== forecastRequestSequence) return;

        // 1. Stats strip

        document.getElementById('fcStartLiquid').innerText = data.starting_liquid_rub + ' ₽';

        document.getElementById('fcCreditDebt').innerText = '-' + data.credit_debt_rub + ' ₽';

        document.getElementById('fcDailyBurn').innerText = data.daily_burn_rub + ' ₽/дн';

        document.getElementById('fcMinBalance').innerText = data.min_projected_balance_rub + ' ₽';

        document.getElementById('fcMinBalance').style.color = data.min_projected_balance_cents < 0 ? '#ef4444' : '#34d399';
        let forecastPolicy = document.getElementById('forecastPolicyNote');
        if (!forecastPolicy) {
          forecastPolicy = document.createElement('p'); forecastPolicy.id = 'forecastPolicyNote';
          forecastPolicy.style.cssText = 'font-size:12px;color:var(--text-muted);line-height:1.5';
          document.getElementById('fcMinBalance').parentElement.appendChild(forecastPolicy);
        }
        forecastPolicy.innerText = data.model_note || '';


        // 2. Deficit Alert Banner

        const alertEl = document.getElementById('forecastDeficitAlert');

        if (data.has_deficit) {

          alertEl.classList.remove('hidden');

          const dateParts = data.first_deficit_date.split('-');

          const fmtDate = dateParts[2] + '.' + dateParts[1] + '.' + dateParts[0];

          document.getElementById('forecastDeficitText').innerText = 

            'Ожидается кассовый разрыв ' + fmtDate + ' из-за статьи "' + (data.first_deficit_trigger || 'Обязательства') + '". Рекомендуется сократить гибкие траты или перераспределить средства.';

          document.getElementById('forecastDeficitBadge').innerText = '-' + data.first_deficit_rub + ' ₽';

        } else {

          alertEl.classList.add('hidden');

        }

        // 3. Render Milestones

        const mlContainer = document.getElementById('forecastMilestonesList');

        if (!data.milestones || data.milestones.length === 0) {

          mlContainer.innerHTML = '<div style="color:var(--text-muted); font-size:12px; padding:6px;">В выбранном горизонте нет крупных обязательств</div>';

        } else {

          mlContainer.innerHTML = data.milestones.map(m => {

            const dp = m.date.split('-');

            const dStr = dp[2] + '.' + dp[1];

            return `

              <div style="background:var(--card-hover); border:1px solid var(--border); border-radius:8px; padding:6px 12px; white-space:nowrap; font-size:12px;">

                <div style="color:#60a5fa; font-weight:600;">${dStr} (через ${m.day} дн.)</div>

                <div style="color:var(--text); margin-top:2px;">${m.label}</div>

              </div>

            `;

          }).join('');

        }

        // 4. Render Cash Flow Chart

        renderCashFlowChart(data);

      } catch (err) {

        if (err.name === 'AbortError' || requestSequence !== forecastRequestSequence) return;
        console.error('Error loading forecast:', err);
        if (forecastChart) forecastChart.textContent = 'Не удалось загрузить прогноз. Повторите выбор горизонта.';
        ['fcStartLiquid', 'fcCreditDebt', 'fcDailyBurn', 'fcMinBalance'].forEach(id => {
          document.getElementById(id).innerText = '—';
        });
        document.getElementById('forecastMilestonesList').textContent = '';
        document.getElementById('forecastDeficitAlert').classList.add('hidden');
      } finally {
        if (requestSequence === forecastRequestSequence) forecastChart?.setAttribute('aria-busy', 'false');
      }

    }

    function renderCashFlowChart(data) {

      const container = document.getElementById('cashFlowChartSvg');

      const timeline = data.timeline;

      if (!timeline || timeline.length === 0) {

        container.innerHTML = '<div style="color:var(--text-muted); text-align:center; padding:20px;">Нет данных для прогноза</div>';

        return;

      }

      const W = 620;

      const H = 220;

      const padL = 65;

      const padR = 25;

      const padT = 20;

      const padB = 30;

      const plotW = W - padL - padR;

      const plotH = H - padT - padB;

      let minVal = 0;

      let maxVal = Math.max(data.starting_liquid_cents, 100000);

      timeline.forEach(p => {

        if (p.balance_cents < minVal) minVal = p.balance_cents;

        if (p.balance_cents > maxVal) maxVal = p.balance_cents;

      });

      const span = Math.max(1, maxVal - minVal);

      const yMax = maxVal + span * 0.08;

      const yMin = minVal - span * 0.08;

      const totalYRange = yMax - yMin;

      function getY(cents) {

        return padT + plotH * (1 - (cents - yMin) / totalYRange);

      }

      const zeroY = getY(0);

      const startX = padL;

      const endX = padL + plotW;

      let pointsStr = '';

      let areaStr = `${startX},${zeroY} `;

      const dotsHtml = [];

      timeline.forEach((pt, i) => {

        const x = padL + (i / (timeline.length - 1)) * plotW;

        const y = getY(pt.balance_cents);

        pointsStr += `${x.toFixed(1)},${y.toFixed(1)} `;

        areaStr += `${x.toFixed(1)},${y.toFixed(1)} `;

        if (pt.events && pt.events.some(e => e.type === 'OBLIGATION')) {

          dotsHtml.push(`<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="4.5" fill="#f59e0b" stroke="#0f172a" stroke-width="2" />`);

        }

      });

      areaStr += `${endX},${zeroY}`;

      const xLabelsHtml = [];

      const stepIdx = Math.max(1, Math.floor(timeline.length / 5));

      for (let i = 0; i < timeline.length; i += stepIdx) {

        const pt = timeline[i];

        const x = padL + (i / (timeline.length - 1)) * plotW;

        xLabelsHtml.push(`<text x="${x.toFixed(1)}" y="${H - 10}" text-anchor="middle" fill="#94a3b8" font-size="10">${pt.day_formatted}</text>`);

      }

      const strokeColor = data.has_deficit ? '#f59e0b' : '#34d399';

      const gradColor = data.has_deficit ? '#f59e0b' : '#10b981';

      container.innerHTML = `

        <svg viewBox="0 0 ${W} ${H}" style="width:100%; height:auto; display:block;">

          <defs>

            <linearGradient id="cfGrad" x1="0" y1="0" x2="0" y2="1">

              <stop offset="0%" stop-color="${gradColor}" stop-opacity="0.35" />

              <stop offset="100%" stop-color="${gradColor}" stop-opacity="0.02" />

            </linearGradient>

          </defs>

          

          <!-- Zero Baseline -->

          <line x1="${startX}" y1="${zeroY.toFixed(1)}" x2="${endX}" y2="${zeroY.toFixed(1)}" stroke="#ef4444" stroke-dasharray="4" stroke-width="1.2" opacity="0.8" />

          <text x="${startX - 6}" y="${(zeroY + 3).toFixed(1)}" text-anchor="end" fill="#f87171" font-size="10" font-weight="600">0 ₽</text>

          <!-- Top Grid Line & Value -->

          <line x1="${startX}" y1="${padT}" x2="${endX}" y2="${padT}" stroke="rgba(255,255,255,0.06)" stroke-width="1" />

          <text x="${startX - 6}" y="${padT + 4}" text-anchor="end" fill="#94a3b8" font-size="10">${Math.round(yMax / 100).toLocaleString('ru-RU')} ₽</text>

          <!-- Area & Trajectory Polyline -->

          <polygon points="${areaStr}" fill="url(#cfGrad)" />

          <polyline fill="none" stroke="${strokeColor}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" points="${pointsStr}" />

          <!-- Obligation Event Milestone Circles -->

          ${dotsHtml.join('')}

          <!-- Date Labels on X Axis -->

          ${xLabelsHtml.join('')}

        </svg>

      `;

    }

    function toggleCreditLimitField() {

      const subtype = document.getElementById('newAccSubtype').value;

      const div = document.getElementById('divCreditLimit');

      div.style.display = subtype === 'CREDIT_CARD' ? 'block' : 'none';

    }

    function toggleNewObligationForm() {

      document.getElementById('divNewObligation').classList.toggle('hidden');

    }

    function toggleNewCategoryForm() {

      document.getElementById('divNewCategory').classList.toggle('hidden');

    }

    // --- Centralized Screen Management & Fault-Tolerance ---

    function hideAllScreens() {
      ['errorScreen', 'lockScreen', 'setupScreen', 'loginScreen', 'mainDashboard'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.add('hidden');
      });
      document.getElementById('mobileBottomNav')?.classList.add('hidden');
      document.getElementById('btnOpenSettings')?.classList.add('hidden');
      document.getElementById('btnPrivacyToggle')?.classList.add('hidden');
      document.getElementById('btnStatusIndicator')?.classList.add('hidden');
      document.getElementById('btnHeaderLock')?.classList.add('hidden');
      document.getElementById('btnLogout')?.classList.add('hidden');
      document.getElementById('btnHeaderQrPair')?.classList.add('hidden');
    }

    function showScreen(screenId) {
      hideAllScreens();
      const target = document.getElementById(screenId);
      if (target) target.classList.remove('hidden');
      if (screenId === 'mainDashboard') {
        document.getElementById('mobileBottomNav')?.classList.remove('hidden');
        document.getElementById('btnOpenSettings')?.classList.remove('hidden');
        document.getElementById('btnPrivacyToggle')?.classList.remove('hidden');
        document.getElementById('btnStatusIndicator')?.classList.remove('hidden');
        document.getElementById('btnHeaderLock')?.classList.remove('hidden');
        document.getElementById('btnLogout')?.classList.remove('hidden');
        document.getElementById('btnHeaderQrPair')?.classList.remove('hidden');
      }
    }

    function showErrorScreen(title, message) {
      hideAllScreens();
      const errEl = document.getElementById('errorScreen');
      if (errEl) {
        const titleEl = document.getElementById('errorScreenTitle');
        if (titleEl && title) titleEl.innerText = title;
        const msgEl = document.getElementById('errorScreenMsg');
        if (msgEl && message) msgEl.innerText = message;
        errEl.classList.remove('hidden');
      }
    }

    function retryLoadApp() {
      hideAllScreens();
      loadStatus();
    }

    function showLoginFallback() {
      showScreen('loginScreen');
    }

    function openSettingsModal() {
      const modal = document.getElementById('settingsModal');
      if (!modal) return;
      modal.classList.remove('hidden');
      updateSettingsModalInfo();
    }

    function closeSettingsModal() {
      const modal = document.getElementById('settingsModal');
      if (modal) modal.classList.add('hidden');
    }

    function togglePrivacyMask() {
      const isMasked = document.body.classList.toggle('privacy-masked');
      localStorage.setItem('ffos_privacy_masked', isMasked ? 'true' : 'false');
      const icon = document.getElementById('privacyIcon');
      if (icon) icon.innerText = isMasked ? '🙈' : '👁️';
    }

    async function updateSettingsModalInfo() {
      const infoEl = document.getElementById('settingsVaultInfo');
      if (!infoEl) return;
      try {
        const snap = await LocalDatabaseVault.getSnapshot();
        if (snap && snap.updated_at) {
          const d = new Date(snap.updated_at);
          infoEl.innerHTML = `
            <div style="background: rgba(16,185,129,0.08); border: 1px solid rgba(16,185,129,0.25); border-radius: 10px; padding: 10px 12px; font-size: 12px;">
              <div style="font-weight: 600; color: #34d399; margin-bottom: 3px;">✅ База сохранена на телефоне</div>
              <div style="color: var(--text-muted);">Размер: <strong style="color: var(--text);">${Math.round((snap.size_bytes || 0) / 1024)} КБ</strong> • Сохранено: ${d.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</div>
            </div>
          `;
        } else {
          infoEl.innerHTML = `
            <div style="background: rgba(99,102,241,0.08); border: 1px solid rgba(99,102,241,0.25); border-radius: 10px; padding: 10px 12px; font-size: 12px; color: var(--text-muted);">
              ℹ️ Локальная копия создается автоматически при добавлении данных.
            </div>
          `;
        }
      } catch (e) {
        console.warn('updateSettingsModalInfo notice:', e);
      }
    }

    async function loadStatus() {
      try {
        const res = await fetch('/api/status');
        if (!res.ok) {
          showErrorScreen('Сервер недоступен (HTTP ' + res.status + ')', 'Не удалось связаться с сервером Family Finances OS. Попробуйте повторить запрос.');
          return;
        }
        const data = await res.json();

        // 1. If database is encrypted and locked
        if (data.is_locked) {
          showScreen('lockScreen');
          const badge = document.getElementById('storageBadge');
          if (badge) {
            badge.innerText = '🔒 Заблокировано';
            badge.style.background = '#dc2626';
          }
          document.getElementById('masterUnlockPassword')?.focus();
          return;
        }

        // Database is unlocked
        const badge = document.getElementById('storageBadge');
        if (badge) {
          badge.innerText = 'AES-256-GCM / Память';
          badge.style.background = '#10b981';
        }

        // 2. Check if owner exists
        if (!data.has_owner) {
          const restored = await LocalDatabaseVault.autoRestoreIfEmpty();
          if (restored) {
            return loadStatus();
          }
          showScreen('setupScreen');
          return;
        }

        // 3. Check authentication & URL QR pair token
        if (!sessionToken) {
          const paired = await checkPairTokenInUrl();
          if (paired) {
            sessionToken = sessionStorage.getItem('ffos_session_token') || localStorage.getItem('ffos_session_token');
          }
        }

        if (!sessionToken) {
          const manualLogout = sessionStorage.getItem('ffos_manual_logout') === 'true';
          let autoLoggedIn = false;
          if (!manualLogout && document.getElementById('loginUsername') && document.getElementById('loginPassword')) {
            try {
              autoLoggedIn = await submitLogin();
            } catch (loginErr) {
              console.warn('Auto-login skipped:', loginErr);
            }
          }

          if (!autoLoggedIn || !sessionToken) {
            showScreen('loginScreen');
          }
        } else {
          let ok = false;
          try {
            ok = await loadDashboard();
          } catch (dashErr) {
            console.error('loadDashboard error:', dashErr);
            ok = false;
          }

          if (!ok) {
            sessionToken = null;
            sessionStorage.removeItem('ffos_session_token');
            localStorage.removeItem('ffos_session_token');
            showScreen('loginScreen');
          } else {
            showScreen('mainDashboard');
          }
        }
      } catch (e) {
        console.error('loadStatus error:', e);
        showErrorScreen('Ошибка связи с сервером', 'Не удалось загрузить статус системы: ' + (e.message || 'Ошибка сети') + '. Пожалуйста, проверьте интернет-соединение.');
      }
    }

    function togglePasswordVisibility(inputId, btn) {

      const input = document.getElementById(inputId);

      if (!input) return;

      if (input.type === 'password') {

        input.type = 'text';

        btn.innerText = '🙈';

        btn.title = 'Скрыть пароль';

      } else {

        input.type = 'password';

        btn.innerText = '👁️';

        btn.title = 'Показать пароль';

      }

      input.focus();

    }

    async function submitUnlock() {

      const pwdInput = document.getElementById('masterUnlockPassword');

      const password = pwdInput.value;

      const msg = document.getElementById('lockMsg');

      const btn = document.getElementById('btnUnlock');

      if (!password) {

        msg.innerHTML = '<div class="alert alert-error">Введите мастер-пароль</div>';

        return;

      }

      btn.disabled = true;

      msg.innerHTML = '<div class="alert alert-info">Расшифровка базы данных (PBKDF2 600 000 итераций)...</div>';

      try {

        const res = await fetch('/api/unlock', {

          method: 'POST',

          headers: { 'Content-Type': 'application/json' },

          body: JSON.stringify({ password })

        });

        const data = await res.json();

        if (data.status === 'success') {

          pwdInput.value = '';

          msg.innerHTML = '';

          // Auto-login attempt if owner exists

          if (data.has_owner) {

            try {

              const loginRes = await fetch('/api/login', {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify({ username: 'admin', password })

              });

              const loginData = await loginRes.json();

              if (loginData.status === 'success') {

                sessionToken = loginData.user.session_token;

                sessionStorage.setItem('ffos_session_token', sessionToken); localStorage.setItem('ffos_session_token', sessionToken);

              }

            } catch (e) {}

          }

          await loadStatus();

        } else {

          msg.innerHTML = `<div class="alert alert-error">${data.message}</div>`;

        }

      } catch (err) {

        msg.innerHTML = `<div class="alert alert-error">Ошибка связи с сервером: ${err.message}</div>`;

      } finally {

        btn.disabled = false;

      }

    }

    async function submitLock() {

      try {

        await fetch('/api/lock', { method: 'POST', headers: authHeaders() });

      } catch (e) {}

      sessionToken = null;

      sessionStorage.removeItem('ffos_session_token'); localStorage.removeItem('ffos_session_token');

      await loadStatus();

    }

    async function submitSetup() {

      const username = document.getElementById('setupUsername').value;

      const displayName = document.getElementById('setupDisplayName').value;

      const password = document.getElementById('setupPassword').value;

      const btn = document.getElementById('btnSetup');

      btn.disabled = true;

      try {

        const res = await fetch('/api/setup-master', {

          method: 'POST',

          headers: { 'Content-Type': 'application/json' },

          body: JSON.stringify({ master_password: password, username, display_name: displayName })

        });

        const data = await res.json();

        if (data.status === 'success') {

          sessionToken = data.owner.session_token;

          sessionStorage.setItem('ffos_session_token', sessionToken); localStorage.setItem('ffos_session_token', sessionToken);

          loadStatus();

        } else {

          document.getElementById('setupMsg').innerHTML = `<div class="alert alert-error">${data.message}</div>`;

        }

      } finally {

        btn.disabled = false;

      }

    }

    async function submitLogin() {
      const usernameEl = document.getElementById('loginUsername');
      const passwordEl = document.getElementById('loginPassword');
      if (!usernameEl || !passwordEl) return false;

      const username = usernameEl.value.trim();
      const password = passwordEl.value;
      if (!username || !password) return false;

      const btn = document.getElementById('btnLogin');
      if (btn) btn.disabled = true;

      try {
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        const data = await res.json();

        if (data.status === 'success' && data.user) {
          sessionStorage.removeItem('ffos_manual_logout');
          sessionToken = data.user.session_token;
          sessionStorage.setItem('ffos_session_token', sessionToken);
          localStorage.setItem('ffos_session_token', sessionToken);
          LocalDatabaseVault.syncAfterMutation();

          const ok = await loadDashboard();
          if (ok) {
            showScreen('mainDashboard');
            return true;
          } else {
            console.error('loadDashboard returned false after successful login');
            sessionToken = null;
            sessionStorage.removeItem('ffos_session_token');
            localStorage.removeItem('ffos_session_token');
            showScreen('loginScreen');
            const msgEl = document.getElementById('loginMsg');
            if (msgEl) {
              msgEl.innerHTML = '<div class="alert alert-error">Вход выполнен, но данные дашборда не получены от сервера</div>';
            }
            return false;
          }
        } else {
          const msgEl = document.getElementById('loginMsg');
          if (msgEl) {
            msgEl.innerHTML = `<div class="alert alert-error">${data.message || 'Неверное имя пользователя или пароль'}</div>`;
          }
          showScreen('loginScreen');
          return false;
        }
      } catch (e) {
        console.error('submitLogin error:', e);
        const msgEl = document.getElementById('loginMsg');
        if (msgEl) {
          msgEl.innerHTML = `<div class="alert alert-error">Ошибка сети при входе: ${e.message}</div>`;
        }
        showScreen('loginScreen');
        return false;
      } finally {
        if (btn) btn.disabled = false;
      }
    }

    async function logout() {
      try {
        await fetch('/api/logout', { method: 'POST', headers: authHeaders() });
      } catch (e) {}
      sessionToken = null;
      sessionStorage.removeItem('ffos_session_token');
      localStorage.removeItem('ffos_session_token');
      sessionStorage.setItem('ffos_manual_logout', 'true');
      showScreen('loginScreen');
    }

    async function loadDashboard() {

      const res = await fetch('/api/overview', { headers: authHeaders() });

      if (res.status === 401 || res.status === 423) return false;

      overviewData = await res.json();

      LocalDatabaseVault.updateBadge();

      LocalDatabaseVault.syncAfterMutation();

      // Metrics

      if (overviewData.is_deficit) {

        document.getElementById('valSafeToSpend').innerHTML = `<span style="color:#ef4444;">0.00 ₽</span> <div class="badge" style="background:#ef4444; color:#fff; margin-top:4px; display:inline-block;">ДЕФИЦИТ: -${overviewData.deficit_rub} ₽</div>`;

        document.getElementById('valSafeToSpendNote').innerText = `Ликвидных средств не хватает для покрытия обязательств и долгов`;

      } else {

        document.getElementById('valSafeToSpend').innerText = overviewData.common_safe_to_spend_rub + ' ₽';

        document.getElementById('valSafeToSpendNote').innerText = `Свободные семейные деньги (за вычетом обязательств)`;

      }

      let moneyPolicy = document.getElementById('moneyPolicyNote');
      if (!moneyPolicy) {
        moneyPolicy = document.createElement('p');
        moneyPolicy.id = 'moneyPolicyNote';
        moneyPolicy.style.cssText = 'color:var(--text-muted);font-size:12px;line-height:1.5;margin:12px 0';
        document.getElementById('valSafeToSpend').closest('.card')?.appendChild(moneyPolicy);
      }
      moneyPolicy.innerText = 'Сводные итоги — только RUB. Валютные остатки показаны отдельно без пересчёта. Цели и конверты — планы накопления; одни деньги повторно из свободного остатка не вычитаются.';
      document.getElementById('valLiquid').innerText = overviewData.common_liquid_assets_rub + ' ₽';
      const heroTot = document.getElementById('valHeroTotalBalance');
      if (heroTot) heroTot.innerText = overviewData.common_liquid_assets_rub + ' ₽';

      document.getElementById('valReserve').innerText = overviewData.emergency_reserves_rub + ' ₽';

      if (document.getElementById('valNetWorth')) {

        document.getElementById('valNetWorth').innerText = overviewData.family_net_worth_rub + ' ₽';

      }

      // Obligations Metric

      document.getElementById('valObligations').innerText = overviewData.unpaid_obligations_rub + ' ₽';

      document.getElementById('valObligationsDetail').innerText = `Всего в месяц: ${overviewData.total_obligations_rub} ₽ | Оплачено: ${overviewData.paid_obligations_rub} ₽`;

      const cc = overviewData.credit_cards;

      document.getElementById('valCreditSummary').innerText = `Долг: ${cc.total_debt_rub} ₽`;

      document.getElementById('valCreditDetail').innerText = `Лимит: ${cc.total_limit_rub} ₽ | Доступно: ${cc.available_limit_rub} ₽`;

      renderOverviewAccounts();

      renderManageAccounts();

      populateSelects();

      await loadCategories();

      // Show Onboarding banner if system is clean (zero liquid assets and zero obligations)

      const isClean = (overviewData.common_liquid_assets_rub === "0.00" && overviewData.total_obligations_rub === "0.00");

      const obBanner = document.getElementById('onboardingBanner');

      if (obBanner) {

        if (isClean && !sessionStorage.getItem('ffos_onboarding_dismissed')) {

          obBanner.classList.remove('hidden');

        } else {

          obBanner.classList.add('hidden');

        }

      }

      await loadGoalsWidget();

      await loadEnvelopesWidget();
      await loadTransactions(currentSelectedMonth);
      if (document.getElementById('globalMonthSelect') && !document.getElementById('globalMonthSelect').options.length) {
        renderMonthSelector([currentSelectedMonth], currentSelectedMonth);
      }
      const txDateInput = document.getElementById('txDate');
      if (txDateInput && !txDateInput.value) {
        txDateInput.value = new Date().toISOString().slice(0, 10);
      }
      return true;

    }

    function renderOverviewAccounts() {
      const list = document.getElementById('overviewAccountsBody');
      const previousScroll = list.parentElement.scrollTop;
      list.replaceChildren();
      const scopes = {COMMON: 'Общий', PERSONAL_HUSBAND: 'Муж', PERSONAL_WIFE: 'Жена'};
      const types = {DEBIT_CARD: 'Дебетовая карта', CASH: 'Наличные', CHECKING: 'Текущий счёт', SAVINGS: 'Накопления', SAVINGS_LIQUID: 'Накопительный счёт', DEPOSIT: 'Вклад', RESERVE: 'Резерв', CREDIT_CARD: 'Кредитная карта', LOAN: 'Кредит', MORTGAGE: 'Ипотека', EQUITY: 'Капитал'};
      overviewData.accounts.forEach(a => {
        const row = document.createElement('div');
        row.className = 'account-list-row';
        row.setAttribute('role', 'listitem');
        const identity = document.createElement('div');
        identity.className = 'account-list-identity';
        const name = document.createElement('strong');
        name.className = 'account-list-name';
        name.textContent = a.name;
        name.title = a.name;
        name.tabIndex = 0;
        const metadata = document.createElement('span');
        metadata.className = 'account-list-meta';
        metadata.textContent = [a.code, types[a.subtype] || a.subtype, scopes[a.scope] || a.scope].filter(Boolean).join(' · ');
        metadata.title = metadata.textContent;
        identity.append(name, metadata);
        const amount = document.createElement('span');
        amount.className = 'account-list-amount';
        // balance_rub is the legacy name for native account cents / 100; no FX conversion is applied by the API.
        const currency = /^[A-Z]{3}$/.test(a.currency || '') ? a.currency : 'RUB';
        const [whole, fraction = '00'] = String(a.balance_rub ?? '0.00').split('.');
        amount.textContent = whole.replace(/\\B(?=(\\d{3})+(?!\\d))/g, '\u00a0') + ',' + fraction + '\u00a0' + currency;
        row.append(identity, amount);
        list.appendChild(row);
      });
      if (!overviewData.accounts.length) {
        const empty = document.createElement('p');
        empty.className = 'account-list-empty';
        empty.textContent = 'Активных счетов пока нет.';
        list.appendChild(empty);
      }
      list.parentElement.scrollTop = previousScroll;
    }

    function renderManageAccounts() {
      const tbody = document.getElementById('manageAccountsBody');
      tbody.replaceChildren();
      tbody.closest('table').classList.add('manage-accounts-table');
      overviewData.accounts.forEach(a => {
        const tr = document.createElement('tr');
        const currency = /^[A-Z]{3}$/.test(a.currency || '') ? a.currency : 'RUB';
        const formatAmount = value => {
          const [whole, fraction = '00'] = String(value ?? '0.00').split('.');
          return whole.replace(/\\B(?=(\\d{3})+(?!\\d))/g, '\u00a0') + ',' + fraction + '\u00a0' + currency;
        };
        const fields = [
          ['Код', a.code], ['Название', a.name], ['Тип', a.subtype], ['Принадлежность', a.scope],
          ['Баланс', formatAmount(a.balance_rub)],
          ['Кредитный лимит', a.credit_limit_cents > 0 ? formatAmount(a.credit_limit_rub) : '—']
        ];
        fields.forEach(([label, value]) => {
          const cell = document.createElement('td');
          cell.dataset.label = label;
          cell.textContent = value;
          tr.appendChild(cell);
        });
        const actions = document.createElement('td');
        actions.dataset.label = 'Действия';
        const archive = document.createElement('button');
        archive.className = 'btn btn-secondary';
        archive.type = 'button';
        archive.textContent = 'Архив';
        archive.setAttribute('aria-label', 'Архивировать счёт ' + a.name);
        archive.addEventListener('click', () => archiveAccount(a.id));
        actions.appendChild(archive);
        tr.appendChild(actions);
        tbody.appendChild(tr);
      });
    }

    function populateSelects() {

      const assetLiabAccounts = overviewData.accounts.filter(a => a.type === 'ASSET' || a.type === 'LIABILITY');

      // 1. Transaction Account
      const txAcc = document.getElementById('txAccount');
      const txInputAcc = document.getElementById('txInputAccount');
      if (txAcc) txAcc.innerHTML = '';
      if (txInputAcc) txInputAcc.innerHTML = '';

      assetLiabAccounts.forEach(a => {
        const opt = document.createElement('option');
        opt.value = a.id;
        opt.dataset.scope = a.scope;
        opt.innerText = `${a.name} (${a.scope}, ${a.balance_rub} ₽)`;
        if (txAcc) txAcc.appendChild(opt);
        if (txInputAcc) txInputAcc.appendChild(opt.cloneNode(true));
      });

      // 2. Transfer Accounts

      const trFrom = document.getElementById('trFromAccount');

      const trTo = document.getElementById('trToAccount');

      trFrom.innerHTML = '';

      trTo.innerHTML = '';

      assetLiabAccounts.forEach(a => {

        const o1 = document.createElement('option');

        o1.value = a.id; o1.innerText = `${a.name} (${a.balance_rub} ₽)`;

        trFrom.appendChild(o1);

        const o2 = document.createElement('option');

        o2.value = a.id; o2.innerText = `${a.name} (${a.balance_rub} ₽)`;

        trTo.appendChild(o2);

      });

      if (trTo.options.length > 1) trTo.selectedIndex = 1;

      // 3. Obligation payment account

      const oblAcc = document.getElementById('newOblAccount');

      if (oblAcc) {

        oblAcc.innerHTML = '<option value="">Не назначен (по выбору)</option>';

        assetLiabAccounts.forEach(a => {

          const opt = document.createElement('option');

          opt.value = a.id; opt.innerText = a.name;

          oblAcc.appendChild(opt);

        });

      }

      checkPersonalCardExpense();

    }

    let activeCatFilter = { txCatMenu: 'ALL', dashCatMenu: 'ALL' };

    let selectedCategoryId = null;

    async function loadCategories() {

      try {

        const res = await fetch('/api/categories', { headers: authHeaders() });

        if (!res.ok) return;

        categoryData = await res.json();

        renderCategorySelects();

        renderCategoryCustomDropdowns();

        renderCategoryTree();

      } catch (e) {

        console.error('loadCategories error:', e);

      }

    }

    function onTxTypeChange() {

      const txType = document.getElementById('txType').value;

      setCatMenuFilter('txCatMenu', txType);

      renderCategorySelects();

      checkPersonalCardExpense();

    }

    function toggleCategoryDropdown(menuId) {

      const menu = document.getElementById(menuId);

      if (!menu) return;

      const isHidden = menu.classList.contains('hidden');

      document.querySelectorAll('.category-dropdown-menu').forEach(m => m.classList.add('hidden'));

      if (isHidden) {

        menu.classList.remove('hidden');

        const searchInput = menu.querySelector('input[type="text"]');

        if (searchInput) {

          searchInput.value = '';

          searchInput.focus();

        }

        filterCategoryDropdown(menuId, '');

      }

    }

    function setCatMenuFilter(menuId, filterType, btn) {

      activeCatFilter[menuId] = filterType;

      const menu = document.getElementById(menuId);

      if (menu) {

        menu.querySelectorAll('.cat-filter-btn').forEach(b => b.classList.remove('active'));

        if (btn) btn.classList.add('active');

        const searchInput = menu.querySelector('input[type="text"]');

        filterCategoryDropdown(menuId, searchInput ? searchInput.value : '');

      }

    }

    function filterCategoryDropdown(menuId, query) {

      query = (query || '').toLowerCase().trim();

      let listContainer = null;
      if (menuId === 'txCatMenu') listContainer = document.getElementById('txCatList');
      else if (menuId === 'modalTxCatMenu') listContainer = document.getElementById('modalTxCatList');
      else listContainer = document.getElementById('dashCatList');

      if (!listContainer || !categoryData || !categoryData.tree) return;

      const currentFilter = activeCatFilter[menuId] || 'ALL';

      let html = '';

      categoryData.tree.forEach(root => {

        if (currentFilter !== 'ALL' && root.type !== currentFilter) return;

        const rootMatch = root.name.toLowerCase().includes(query);

        const matchedSubs = (root.subcategories || []).filter(sub => {

          if (currentFilter !== 'ALL' && sub.type && sub.type !== currentFilter) return;

          return !query || sub.name.toLowerCase().includes(query) || rootMatch;

        });

        if (query && !rootMatch && matchedSubs.length === 0) return;

        html += `<div class="cat-group-header"><span>${root.icon || '📁'}</span> <span>${root.name}</span></div>`;

        // Root category item

        const isRootActive = (selectedCategoryId === root.id);

        html += `

          <div class="cat-dropdown-item ${isRootActive ? 'active' : ''}" onclick="onSelectCategory('${root.id}', '${menuId}')">

            <span>${root.icon || '📁'} ${root.name} <small style="color:var(--text-muted); font-size:11px;">(Основная)</small></span>

            <span class="badge" style="font-size:10px; padding:2px 5px;">${root.type === 'INCOME' ? '🟢 Доход' : '🔴 Расход'}</span>

          </div>

        `;

        // Subcategories

        matchedSubs.forEach(sub => {

          const isSubActive = (selectedCategoryId === sub.id);

          html += `

            <div class="cat-dropdown-item ${isSubActive ? 'active' : ''}" style="padding-left: 28px;" onclick="onSelectCategory('${sub.id}', '${menuId}')">

              <span>${sub.icon || '↳'} ${sub.name}</span>

              ${isSubActive ? '<span style="color:#60a5fa; font-size:12px;">✓</span>' : ''}

            </div>

          `;

        });

      });

      if (!html) {

        html = '<div style="color: var(--text-muted); font-size: 13px; text-align: center; padding: 14px;">Категории не найдены</div>';

      }

      listContainer.innerHTML = html;

    }

    function onSelectCategory(catId, menuId, maybeType) {

      if (!categoryData || !categoryData.flat) return;

      let targetMenuId = menuId;
      if (menuId !== 'txCatMenu' && menuId !== 'modalTxCatMenu' && menuId !== 'dashCatMenu') {
        targetMenuId = 'txCatMenu';
      }

      let cat = categoryData.flat.find(c => c.id === catId);
      if (!cat && typeof menuId === 'string' && menuId !== 'txCatMenu' && menuId !== 'modalTxCatMenu' && menuId !== 'dashCatMenu') {
        cat = categoryData.flat.find(c => c.name.toLowerCase() === menuId.toLowerCase());
      }
      if (!cat && catId) {
        cat = categoryData.flat.find(c => c.name.toLowerCase() === String(catId).toLowerCase());
      }
      if (!cat) return;

      selectedCategoryId = cat.id;

      const menu = document.getElementById(targetMenuId);
      if (menu) menu.classList.add('hidden');
      const mMenu = document.getElementById('modalTxCatMenu');
      if (mMenu) mMenu.classList.add('hidden');

      if (targetMenuId === 'txCatMenu' || targetMenuId === 'modalTxCatMenu') {

        const iconEl = document.getElementById('txCatSelectedIcon');
        const nameEl = document.getElementById('txCatSelectedName');
        const parentEl = document.getElementById('txCatSelectedParent');
        const badgeEl = document.getElementById('txCatBadge');
        const selectEl = document.getElementById('txCategorySelect');

        const mIconEl = document.getElementById('modalTxCatSelectedIcon');
        const mNameEl = document.getElementById('modalTxCatSelectedName');
        const mParentEl = document.getElementById('modalTxCatSelectedParent');
        const mBadgeEl = document.getElementById('modalTxCatBadge');
        const mSelectEl = document.getElementById('txInputCategory');

        const iconVal = cat.icon || '🏷️';
        const nameVal = cat.name;
        const parentVal = cat.parent_name ? `${cat.parent_name}` : (cat.type === 'INCOME' ? 'Доход семьи' : 'Расход семьи');
        const badgeText = cat.type === 'INCOME' ? 'Доход' : 'Расход';
        const badgeBg = cat.type === 'INCOME' ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)';
        const badgeColor = cat.type === 'INCOME' ? '#6ee7b7' : '#fca5a5';

        if (iconEl) iconEl.innerText = iconVal;
        if (nameEl) nameEl.innerText = nameVal;
        if (parentEl) parentEl.innerText = parentVal;
        if (badgeEl) {
          badgeEl.innerText = badgeText;
          badgeEl.style.background = badgeBg;
          badgeEl.style.color = badgeColor;
        }
        if (selectEl) {
          selectEl.value = cat.id;
        }

        if (mIconEl) mIconEl.innerText = iconVal;
        if (mNameEl) mNameEl.innerText = nameVal;
        if (mParentEl) mParentEl.innerText = parentVal;
        if (mBadgeEl) {
          mBadgeEl.innerText = badgeText;
          mBadgeEl.style.background = badgeBg;
          mBadgeEl.style.color = badgeColor;
        }
        if (mSelectEl) {
          mSelectEl.value = cat.id;
        }

        const txTypeEl = document.getElementById('txType');

        if (txTypeEl && txTypeEl.value !== cat.type) {

          txTypeEl.value = cat.type;

        }

      } else if (menuId === 'dashCatMenu') {

        const dashIcon = document.getElementById('dashCatSelectedIcon');

        const dashName = document.getElementById('dashCatSelectedName');

        if (dashIcon) dashIcon.innerText = cat.icon || '🏷️';

        if (dashName) dashName.innerText = cat.name;

        const input = document.getElementById('dashQuickInput');

        if (input) {

          const val = input.value.trim();

          const numMatch = val.match(/^\\d+(\\.\\d+)?$/);

          if (numMatch) {

            input.value = `${numMatch[0]} ${cat.name}`;

          } else if (!val) {

            input.value = `${cat.name} `;

          }

          input.focus();

          onQuickInputLive(input.value, 'dashQuickPreview');

        }

      }

    }

    function renderCategoryCustomDropdowns() {

      filterCategoryDropdown('txCatMenu', '');
      filterCategoryDropdown('modalTxCatMenu', '');
      filterCategoryDropdown('dashCatMenu', '');

      if (!selectedCategoryId && categoryData && categoryData.flat) {

        const firstExp = categoryData.flat.find(c => c.type === 'EXPENSE');

        if (firstExp) {

          onSelectCategory(firstExp.id, 'txCatMenu');

        }

      }

    }

    function renderCategorySelects() {

      if (!categoryData || !categoryData.tree) return;

      const txType = document.getElementById('txType') ? document.getElementById('txType').value : (modalTxActiveType || 'EXPENSE');

      const select = document.getElementById('txCategorySelect');
      const selectModal = document.getElementById('txInputCategory');

      if (select) select.innerHTML = '';
      if (selectModal) selectModal.innerHTML = '';

      categoryData.tree.filter(root => root.type === txType).forEach(root => {

        if (root.subcategories && root.subcategories.length > 0) {

          const grp = document.createElement('optgroup');
          grp.label = `${root.icon || ''} ${root.name}`;

          const rootOpt = document.createElement('option');
          rootOpt.value = root.id;
          rootOpt.innerText = `${root.icon || ''} ${root.name} (Основная)`;
          grp.appendChild(rootOpt);

          root.subcategories.forEach(sub => {
            const opt = document.createElement('option');
            opt.value = sub.id;
            opt.innerText = `${sub.icon || ''} ${sub.name}`;
            grp.appendChild(opt);
          });

          if (select) select.appendChild(grp);
          if (selectModal) selectModal.appendChild(grp.cloneNode(true));

        } else {

          const opt = document.createElement('option');
          opt.value = root.id;
          opt.innerText = `${root.icon || ''} ${root.name}`;

          if (select) select.appendChild(opt);
          if (selectModal) selectModal.appendChild(opt.cloneNode(true));

        }

      });

      if (selectedCategoryId) {
        if (select) select.value = selectedCategoryId;
        if (selectModal) selectModal.value = selectedCategoryId;
      }

      const oblCatSelect = document.getElementById('newOblCategory');

      if (oblCatSelect) {

        oblCatSelect.innerHTML = '<option value="">Без категории</option>';

        categoryData.tree.filter(root => root.type === 'EXPENSE').forEach(root => {

          if (root.subcategories && root.subcategories.length > 0) {

            const grp = document.createElement('optgroup');

            grp.label = `${root.icon || ''} ${root.name}`;

            const rootOpt = document.createElement('option');

            rootOpt.value = root.id;

            rootOpt.innerText = `${root.icon || ''} ${root.name}`;

            grp.appendChild(rootOpt);

            root.subcategories.forEach(sub => {

              const opt = document.createElement('option');

              opt.value = sub.id;

              opt.innerText = `${sub.icon || ''} ${sub.name}`;

              grp.appendChild(opt);

            });

            oblCatSelect.appendChild(grp);

          } else {

            const opt = document.createElement('option');

            opt.value = root.id;

            opt.innerText = `${root.icon || ''} ${root.name}`;

            oblCatSelect.appendChild(opt);

          }

        });

      }

      const newCatParent = document.getElementById('newCatParent');

      if (newCatParent) {

        newCatParent.innerHTML = '<option value="">Нет (Корневая категория)</option>';

        categoryData.tree.forEach(root => {

          const opt = document.createElement('option');

          opt.value = root.id;

          opt.innerText = `${root.icon} ${root.name} (${root.type})`;

          newCatParent.appendChild(opt);

        });

      }

    }

    // Global outside click listener to close category dropdowns

    document.addEventListener('click', function(e) {

      if (!e.target.closest('.category-dropdown-trigger') && 

          !e.target.closest('.category-dropdown-menu') && 

          !e.target.closest('#dashCatDropdownBtn')) {

        document.querySelectorAll('.category-dropdown-menu').forEach(m => m.classList.add('hidden'));

      }

    });

    function renderCategoryTree() {

      const container = document.getElementById('categoryTreeContainer');

      if (!container || !categoryData) return;

      container.innerHTML = '';

      categoryData.tree.forEach(root => {

        const div = document.createElement('div');

        div.className = 'tree-node';

        div.innerHTML = `

          <div class="tree-parent">

            <span>${root.icon} <strong>${root.name}</strong> <span class="badge" style="font-size:10px; margin-left:6px;">${root.type === 'EXPENSE' ? 'Расход' : 'Доход'}</span></span>

            <button class="btn btn-secondary" style="font-size:11px; padding:3px 8px;" onclick="archiveCategory('${root.id}')">Архив</button>

          </div>

          <div class="tree-children">

            ${root.subcategories.map(sub => `

              <div class="tree-child">

                <span>${sub.icon} ${sub.name}</span>

                <button class="btn btn-secondary" style="font-size:10px; padding:2px 6px;" onclick="archiveCategory('${sub.id}')">×</button>

              </div>

            `).join('')}

          </div>

        `;

        container.appendChild(div);

      });

    }

    async function loadObligations() {

      try {

        const res = await fetch('/api/obligations?month=' + encodeURIComponent(currentSelectedMonth), { headers: authHeaders() });

        if (!res.ok) return;

        const data = await res.json();

        const container = document.getElementById('obligationsListContainer');

        if (!container) return;

        if (!data.obligations || data.obligations.length === 0) {

          container.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 20px;">Обязательные платежи пока не добавлены. Добавьте аренду, ЖКУ или кредиты.</div>';

          return;

        }

        let html = `

          <div style="background: rgba(139,92,246,0.1); border: 1px solid var(--purple); border-radius: 8px; padding: 12px 16px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">

            <div>

              <span style="font-size: 13px; color: #c084fc;">Всего в этом месяце: <strong>${data.total_rub} ₽</strong></span> | 

              <span style="font-size: 13px; color: #34d399;">Оплачено: <strong>${data.paid_rub} ₽</strong></span> | 

              <span style="font-size: 13px; color: #f87171;">К оплате: <strong>${data.unpaid_rub} ₽</strong></span>

            </div>

            <span class="badge" style="background: #5b21b6; color: #ddd6fe;">${formatMonthRu(data.selected_month || currentSelectedMonth)}</span>

          </div>

          <table class="obligations-table">

            <thead>

              <tr>

                <th>Срок (число)</th>

                <th>Платеж</th>

                <th>Сумма</th>

                <th>Категория</th>

                <th>Статус</th>

                <th>Действие</th>

              </tr>

            </thead>

            <tbody>

        `;

        data.obligations.forEach(o => {

          const statusBadge = o.is_paid_this_month

            ? '<span class="badge" style="background: #065f46; color: #6ee7b7;">✓ Оплачено</span>'

            : '<span class="badge" style="background: #991b1b; color: #fca5a5;">К оплате</span>';

          const actionBtn = o.is_paid_this_month

            ? `<button class="btn btn-secondary" style="padding: 4px 8px; font-size: 12px;" onclick="unpayObligation('${o.id}')">Отменить</button>`

            : `<button class="btn btn-success" style="padding: 4px 8px; font-size: 12px;" onclick="payObligation('${o.id}')">Оплатить</button>`;

          html += `

            <tr>

              <td data-label="Срок"><strong>до ${o.due_day}-го</strong></td>

              <td data-label="Платеж"><strong>${escapeHtml(o.name)}</strong>${o.note ? `<br><small style="color:var(--text-muted);">${escapeHtml(o.note)}</small>` : ''}</td>

              <td data-label="Сумма" style="font-weight: 700; font-size: 15px;">${o.amount_rub} ₽</td>

              <td data-label="Категория">${o.category_icon} ${escapeHtml(o.category_name)}</td>

              <td data-label="Статус">${statusBadge}</td>

              <td data-label="Действия">

                <div style="display:flex; gap:6px;">

                  ${actionBtn}

                  <button class="btn btn-secondary" style="padding:4px 8px; font-size:12px;" onclick="archiveObligation('${o.id}')">×</button>

                </div>

              </td>

            </tr>

          `;

        });

        html += '</tbody></table>';

        container.innerHTML = html;

      } catch (e) {

        console.error('loadObligations error:', e);

      }

    }

    async function submitCreateObligation() {

      const name = document.getElementById('newOblName').value.trim();

      const amount_rub = document.getElementById('newOblAmount').value;

      const due_day = document.getElementById('newOblDueDay').value;

      const category_id = document.getElementById('newOblCategory').value;

      const payment_account_id = document.getElementById('newOblAccount').value;

      const note = document.getElementById('newOblNote').value.trim();

      if (!name || !amount_rub) { alert('Укажите название и сумму платежа'); return; }

      const res = await fetch('/api/obligations/create', {

        method: 'POST',

        headers: authHeaders(),

        body: JSON.stringify({ name, amount_rub, due_day, category_id, payment_account_id, note })

      });

      const data = await res.json();

      if (data.status === 'success') {

        document.getElementById('newOblName').value = '';

        document.getElementById('newOblAmount').value = '';

        toggleNewObligationForm();

        await loadObligations();

        await loadDashboard();

      } else {

        alert(data.message);

      }

    }

    async function payObligation(obligationId) {

      const res = await fetch('/api/obligations/pay', {

        method: 'POST',

        headers: authHeaders(),

        body: JSON.stringify({ obligation_id: obligationId, month_year: currentSelectedMonth })

      });

      await loadObligations();

      await loadDashboard();

    }

    async function unpayObligation(obligationId) {

      const res = await fetch('/api/obligations/unpay', {

        method: 'POST',

        headers: authHeaders(),

        body: JSON.stringify({ obligation_id: obligationId, month_year: currentSelectedMonth })

      });

      await loadObligations();

      await loadDashboard();

    }

    async function archiveObligation(obligationId) {

      if (!confirm('Архивировать это обязательство?')) return;

      await fetch('/api/obligations/archive', {

        method: 'POST',

        headers: authHeaders(),

        body: JSON.stringify({ obligation_id: obligationId, month_year: currentSelectedMonth })

      });

      await loadObligations();

      await loadDashboard();

    }

    async function submitCreateCategory() {

      const name = document.getElementById('newCatName').value.trim();

      const category_type = document.getElementById('newCatType').value;

      const icon = document.getElementById('newCatIcon').value.trim() || '🏷️';

      const parent_id = document.getElementById('newCatParent').value || null;

      if (!name) { alert('Введите название категории'); return; }

      const res = await fetch('/api/categories/create', {

        method: 'POST',

        headers: authHeaders(),

        body: JSON.stringify({ name, category_type, icon, parent_id })

      });

      const data = await res.json();

      if (data.status === 'success') {

        document.getElementById('newCatName').value = '';

        toggleNewCategoryForm();

        await loadCategories();

        LocalDatabaseVault.syncAfterMutation();

      } else {

        alert(data.message);

      }

    }

    async function archiveCategory(categoryId) {

      if (!confirm('Архивировать эту категорию и её подкатегории?')) return;

      await fetch('/api/categories/archive', {

        method: 'POST',

        headers: authHeaders(),

        body: JSON.stringify({ category_id: categoryId })

      });

      await loadCategories();

      LocalDatabaseVault.syncAfterMutation();

    }

    function checkPersonalCardExpense() {

      const txType = document.getElementById('txType').value;

      const accSelect = document.getElementById('txAccount');

      const selectedOpt = accSelect.options[accSelect.selectedIndex];

      const scope = selectedOpt ? selectedOpt.dataset.scope : 'COMMON';

      const div = document.getElementById('personalExpenseOption');

      if (txType === 'EXPENSE' && (scope === 'PERSONAL_HUSBAND' || scope === 'PERSONAL_WIFE')) {

        div.style.display = 'block';

      } else {

        div.style.display = 'none';

        document.getElementById('chkPersonalForCommon').checked = false;

      }

    }

    async function submitCreateAccount() {

      const name = document.getElementById('newAccName').value.trim();

      const subtype = document.getElementById('newAccSubtype').value;

      const scope = document.getElementById('newAccScope').value;

      const initBal = document.getElementById('newAccInitBal').value || '0';

      const creditLimit = document.getElementById('newAccCreditLimit').value || '0';

      const desc = document.getElementById('newAccDesc').value.trim();

      if (!name) { alert('Введите название счета'); return; }

      const account_type = subtype === 'CREDIT_CARD' ? 'LIABILITY' : 'ASSET';

      const btn = document.getElementById('btnCreateAcc');

      btn.disabled = true;

      try {

        const res = await fetch('/api/accounts/create', {

          method: 'POST',

          headers: authHeaders(),

          body: JSON.stringify({

            name,

            account_type,

            subtype,

            ownership_scope: scope,

            initial_balance_rub: initBal,

            credit_limit_rub: creditLimit,

            description: desc

          })

        });

        const data = await res.json();

        if (data.status === 'success') {

          document.getElementById('newAccName').value = '';

          document.getElementById('newAccInitBal').value = '';

          document.getElementById('newAccCreditLimit').value = '';

          document.getElementById('newAccDesc').value = '';

          document.getElementById('accMsg').innerHTML = `<div class="alert alert-success">Счет '${name}' успешно создан!</div>`;

          setTimeout(() => { document.getElementById('accMsg').innerHTML = ''; }, 3000);

          await loadDashboard();

        } else {

          document.getElementById('accMsg').innerHTML = `<div class="alert alert-error">${data.message}</div>`;

        }

      } finally {

        btn.disabled = false;

      }

    }

    async function archiveAccount(accountId) {

      if (!confirm('Архивировать этот счет? История операций будет сохранена.')) return;

      await fetch('/api/accounts/archive', {

        method: 'POST',

        headers: authHeaders(),

        body: JSON.stringify({ account_id: accountId })

      });

      await loadDashboard();

    }

    async function submitTransfer() {

      const fromAcc = document.getElementById('trFromAccount').value;

      const toAcc = document.getElementById('trToAccount').value;

      const amount = document.getElementById('trAmount').value;

      const desc = document.getElementById('trDesc').value.trim() || 'Внутренний перевод';

      if (!amount || parseFloat(amount) <= 0) { alert('Введите корректную сумму перевода'); return; }

      if (fromAcc === toAcc) { alert('Счета списания и зачисления должны различаться'); return; }

      const btn = document.getElementById('btnSubmitTransfer');

      btn.disabled = true;

      try {

        const res = await fetch('/api/transfer/create', {

          method: 'POST',

          headers: authHeaders(),

          body: JSON.stringify({

            from_account_id: fromAcc,

            to_account_id: toAcc,

            amount_rub: amount,

            description: desc,

            idempotency_key: activeTrIdempotencyKey

          })

        });

        const data = await res.json();

        if (data.status === 'success') {

          activeTrIdempotencyKey = generateFormKey('tr');

          document.getElementById('trAmount').value = '';

          document.getElementById('trMsg').innerHTML = `<div class="alert alert-success">Перевод успешно выполнен!</div>`;

          setTimeout(() => { document.getElementById('trMsg').innerHTML = ''; }, 3000);

          await loadDashboard();

        } else {

          document.getElementById('trMsg').innerHTML = `<div class="alert alert-error">${data.message}</div>`;

        }

      } finally {

        btn.disabled = false;

      }

    }

    let currentSelectedMonth = new Date().toISOString().slice(0, 7);
    let cachedTransactions = [];
    const RU_MONTH_NAMES = ['Январь', 'Февраль', 'Март', 'Апрель', 'Май', 'Июнь', 'Июль', 'Август', 'Сентябрь', 'Октябрь', 'Ноябрь', 'Декабрь'];

    function formatMonthRu(ym) {
      if (!ym || typeof ym !== 'string' || !ym.includes('-')) return ym || '';
      const parts = ym.split('-');
      const y = parts[0];
      const m = parseInt(parts[1], 10);
      const name = RU_MONTH_NAMES[m - 1] || parts[1];
      return `${name} ${y}`;
    }

    function renderMonthSelector(availableMonths, selectedMonth) {
      const select = document.getElementById('globalMonthSelect');
      if (!select) return;
      const curRealMonth = new Date().toISOString().slice(0, 7);
      const targetMonth = selectedMonth || currentSelectedMonth || curRealMonth;

      const monthsSet = new Set(availableMonths || []);
      monthsSet.add(curRealMonth);
      monthsSet.add(targetMonth);

      const now = new Date();
      for (let i = 0; i < 12; i++) {
        const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
        const ym = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
        monthsSet.add(ym);
      }

      const sortedMonths = Array.from(monthsSet).sort().reverse();
      select.innerHTML = '';
      sortedMonths.forEach(ym => {
        const opt = document.createElement('option');
        opt.value = ym;
        const isCur = (ym === curRealMonth);
        opt.innerText = formatMonthRu(ym) + (isCur ? ' (Текущий)' : '');
        if (ym === targetMonth) opt.selected = true;
        select.appendChild(opt);
      });

      const resetBtn = document.getElementById('btnCurrentMonthReset');
      const notice = document.getElementById('pastMonthNotice');
      const noticeLbl = document.getElementById('pastMonthNoticeLabel');
      if (resetBtn) resetBtn.style.display = (targetMonth === curRealMonth ? 'none' : 'inline-block');
      if (notice) {
        notice.style.display = (targetMonth === curRealMonth ? 'none' : 'flex');
        if (noticeLbl) noticeLbl.innerText = formatMonthRu(targetMonth);
      }
    }

    function shiftSelectedMonth(delta) {
      const parts = currentSelectedMonth.split('-').map(Number);
      const d = new Date(parts[0], parts[1] - 1 + delta, 1);
      const ym = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
      onGlobalMonthSelectChange(ym);
    }

    function onGlobalMonthSelectChange(ym) {
      currentSelectedMonth = ym;
      const curRealMonth = new Date().toISOString().slice(0, 7);
      const select = document.getElementById('globalMonthSelect');
      if (select && select.value !== ym) select.value = ym;

      const resetBtn = document.getElementById('btnCurrentMonthReset');
      const notice = document.getElementById('pastMonthNotice');
      const noticeLbl = document.getElementById('pastMonthNoticeLabel');
      if (resetBtn) resetBtn.style.display = (ym === curRealMonth ? 'none' : 'inline-block');
      if (notice) {
        notice.style.display = (ym === curRealMonth ? 'none' : 'flex');
        if (noticeLbl) noticeLbl.innerText = formatMonthRu(ym);
      }

      const txDateInput = document.getElementById('txDate');
      if (txDateInput) {
        if (ym === curRealMonth) {
          txDateInput.value = new Date().toISOString().slice(0, 10);
        } else {
          txDateInput.value = ym + '-01';
        }
      }

      loadTransactions(ym);
      loadAnalytics(ym);
      loadObligations(ym);
    }

    function resetToCurrentMonth() {
      const cur = new Date().toISOString().slice(0, 7);
      onGlobalMonthSelectChange(cur);
    }

    function setTxDateToday() {
      const el = document.getElementById('txDate');
      if (el) el.value = new Date().toISOString().slice(0, 10);
    }

    function setTxDateYesterday() {
      const el = document.getElementById('txDate');
      if (el) {
        const d = new Date();
        d.setDate(d.getDate() - 1);
        el.value = d.toISOString().slice(0, 10);
      }
    }

    async function submitModalTransaction() {
      await submitTransaction(true);
    }

    async function submitTransaction(isModal = false) {
      const txType = (isModal ? modalTxActiveType : null) || document.getElementById('txType')?.value || modalTxActiveType || 'EXPENSE';
      const account_id = (isModal ? document.getElementById('txInputAccount')?.value : null) || document.getElementById('txAccount')?.value || document.getElementById('txInputAccount')?.value;
      const category_id = (isModal ? document.getElementById('txInputCategory')?.value : null) || document.getElementById('txCategorySelect')?.value || document.getElementById('txInputCategory')?.value || selectedChipCategoryId || selectedCategoryId || null;
      const defaultChartAcc = (overviewData && overviewData.accounts) ? (overviewData.accounts.find(a => a.type === txType) || overviewData.accounts[0]) : null;
      const category_account_id = defaultChartAcc ? defaultChartAcc.id : account_id;

      const description = ((isModal ? document.getElementById('txInputDesc')?.value : null) || document.getElementById('txDescription')?.value || document.getElementById('txInputDesc')?.value || '').trim() || 'Операция';
      const amount_rub = (isModal ? document.getElementById('txInputAmount')?.value : null) || document.getElementById('txAmount')?.value || document.getElementById('txInputAmount')?.value;
      const isPersonalCommon = document.getElementById('chkPersonalForCommon')?.checked || false;
      const tx_date = (isModal ? document.getElementById('txInputDate')?.value : null) || document.getElementById('txDate')?.value || document.getElementById('txInputDate')?.value || undefined;

      const msgEl = isModal ? document.getElementById('modalTxMsg') : document.getElementById('txMsg');

      if (!amount_rub || parseFloat(amount_rub) <= 0) {
        if (msgEl) {
          msgEl.innerHTML = '<div class="alert alert-error">Введите корректную сумму</div>';
        } else {
          alert('Введите корректную сумму');
        }
        return;
      }

      const btn = isModal ? document.getElementById('modalBtnSubmitTx') : document.getElementById('btnSubmitTx');
      if (btn) btn.disabled = true;

      try {
        const res = await fetch('/api/transaction/create', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({
            tx_type: txType,
            account_id,
            category_account_id,
            category_id,
            description,
            amount_rub,
            is_personal_for_common: isPersonalCommon,
            tx_date: tx_date || undefined,
            idempotency_key: activeTxIdempotencyKey
          })
        });
        const data = await res.json();
        if (data.status === 'success') {
          activeTxIdempotencyKey = generateFormKey('tx');
          if (document.getElementById('txAmount')) document.getElementById('txAmount').value = '';
          if (document.getElementById('txInputAmount')) document.getElementById('txInputAmount').value = '';
          if (document.getElementById('txDescription')) document.getElementById('txDescription').value = '';
          if (document.getElementById('txInputDesc')) document.getElementById('txInputDesc').value = '';
          if (document.getElementById('chkPersonalForCommon')) document.getElementById('chkPersonalForCommon').checked = false;

          if (msgEl) msgEl.innerHTML = `<div class="alert alert-success">Операция записана!</div>`;
          setTimeout(() => {
            if (msgEl) msgEl.innerHTML = '';
            if (isModal) closeNewTxModal();
          }, isModal ? 600 : 3000);

          await loadDashboard();
          await loadTransactions(currentSelectedMonth);
          await loadAnalytics(currentSelectedMonth);
        } else {
          if (msgEl) msgEl.innerHTML = `<div class="alert alert-error">${data.message}</div>`;
        }
      } catch (err) {
        if (msgEl) msgEl.innerHTML = `<div class="alert alert-error">Ошибка: ${err.message}</div>`;
      } finally {
        if (btn) btn.disabled = false;
      }
    }

    async function loadTransactions(month) {
      const targetMonth = month || currentSelectedMonth || new Date().toISOString().slice(0, 7);
      const res = await fetch('/api/transactions?month=' + targetMonth, { headers: authHeaders() });
      if (res.status === 401 || res.status === 423) return;
      const data = await res.json();
      let txs = [];
      if (Array.isArray(data)) {
        txs = data;
      } else if (data && data.transactions) {
        txs = data.transactions;
        if (data.available_months) {
          renderMonthSelector(data.available_months, data.selected_month || targetMonth);
        }
      }
      cachedTransactions = txs;
      const tbody = document.getElementById('txTableBody');
      if (tbody) {
        if (!txs || txs.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 24px;">В периоде ' + formatMonthRu(targetMonth) + ' операций не найдено</td></tr>';
        } else {
          tbody.innerHTML = '';
          txs.forEach(t => {
            const tr = document.createElement('tr');
            const postingSummary = t.postings.map(p => `${p.type === 'DEBIT' ? 'Дт' : 'Кт'} ${escapeHtml(p.account_name)} (${p.amount_rub} ₽)`).join('<br>');
            const mainAmount = t.postings[0] ? t.postings[0].amount_rub + ' ₽' : '0.00 ₽';
            const safeDesc = encodeURIComponent(t.description || '').split(String.fromCharCode(39)).join('%27');
            const isExpense = (t.tx_type === 'EXPENSE');
            tr.innerHTML = `
              <td><strong>${t.tx_date}</strong></td>
              <td><span class="badge ${isExpense ? 'badge-expense' : 'badge-income'}">${t.category_icon || '🏷️'} ${escapeHtml(t.category_name)}</span></td>
              <td>${escapeHtml(t.description || '')}</td>
              <td style="font-size: 13px;">${postingSummary}</td>
              <td class="amount-val ${isExpense ? 'amount-expense' : 'amount-income'}" style="text-align: right; white-space: nowrap;">${isExpense ? '-' : '+'}${mainAmount}</td>
              <td style="text-align: right; white-space: nowrap;">
                <button class="btn btn-secondary" style="padding: 4px 8px; font-size: 12px; margin-right: 4px;" onclick="openEditTxModal('${t.id}')" title="Редактировать операцию">✏️</button>
                <button class="btn btn-secondary" style="padding: 4px 8px; font-size: 12px; color: #f87171;" onclick="deleteTransaction('${t.id}', '${safeDesc}', '${mainAmount}')" title="Удалить операцию">🗑️</button>
              </td>
            `;
            tbody.appendChild(tr);
          });
        }
      }

      const dashTbody = document.getElementById('dashTxTableBody');
      if (dashTbody) {
        if (!txs || txs.length === 0) {
          dashTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 24px;">В периоде ' + formatMonthRu(targetMonth) + ' операций не найдено</td></tr>';
        } else {
          dashTbody.innerHTML = '';
          const recentTxs = txs.slice(0, 10);
          recentTxs.forEach(t => {
            const tr = document.createElement('tr');
            const mainAmount = t.postings[0] ? t.postings[0].amount_rub + ' ₽' : '0.00 ₽';
            const safeDesc = encodeURIComponent(t.description || '').split(String.fromCharCode(39)).join('%27');
            const isExpense = (t.tx_type === 'EXPENSE');
            tr.innerHTML = `
              <td style="white-space: nowrap; font-size: 13px; color: var(--text-muted);">${t.tx_date}</td>
              <td><span class="badge ${isExpense ? 'badge-expense' : 'badge-income'}" style="font-size: 12px;">${t.category_icon || '🏷️'} ${escapeHtml(t.category_name)}</span></td>
              <td style="font-weight: 500; font-size: 14px; max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(t.description || '')}</td>
              <td class="amount-val ${isExpense ? 'amount-expense' : 'amount-income'}" style="text-align: right; white-space: nowrap;">${isExpense ? '-' : '+'}${mainAmount}</td>
              <td style="text-align: right; white-space: nowrap;">
                <button class="btn btn-secondary" style="padding: 3px 6px; font-size: 11px;" onclick="openEditTxModal('${t.id}')" title="Редактировать">✏️</button>
              </td>
            `;
            dashTbody.appendChild(tr);
          });
        }
      }
    }

    function openEditTxModal(txId) {
      const t = cachedTransactions.find(x => x.id === txId);
      if (!t) {
        alert('Операция не найдена в текущем списке.');
        return;
      }
      document.getElementById('editTxId').value = t.id;
      document.getElementById('editTxDate').value = t.tx_date;
      document.getElementById('editTxAmount').value = t.postings[0] ? t.postings[0].amount_rub : 0;
      document.getElementById('editTxType').value = t.tx_type || 'EXPENSE';
      document.getElementById('editTxDescription').value = t.description || '';
      document.getElementById('editTxMsg').innerHTML = '';

      const accSelect = document.getElementById('editTxAccount');
      accSelect.innerHTML = '';
      const assetLiab = (overviewData && overviewData.accounts) 
        ? overviewData.accounts.filter(a => a.type === 'ASSET' || a.type === 'LIABILITY')
        : [];
      const currentAccId = (t.postings && t.postings[0]) ? t.postings[0].account_id : '';
      assetLiab.forEach(a => {
        const opt = document.createElement('option');
        opt.value = a.id;
        opt.innerText = `${a.name} (${a.balance_rub} ₽)`;
        if (a.id === currentAccId) opt.selected = true;
        accSelect.appendChild(opt);
      });

      populateEditTxCategories(t.tx_type || 'EXPENSE', t.category_id);
      document.getElementById('modalEditTx').classList.remove('hidden');
    }

    function populateEditTxCategories(txType, selectedCatId) {
      const catSelect = document.getElementById('editTxCategory');
      if (!catSelect) return;
      catSelect.innerHTML = '';
      if (!categoryData || !categoryData.tree) return;
      const targetRoots = categoryData.tree.filter(root => !txType || root.type === txType);

      targetRoots.forEach(root => {
        if (root.subcategories && root.subcategories.length > 0) {
          const grp = document.createElement('optgroup');
          grp.label = `${root.icon || ''} ${root.name}`;
          const rootOpt = document.createElement('option');
          rootOpt.value = root.id;
          rootOpt.innerText = `${root.icon || ''} ${root.name} (Основная)`;
          if (root.id === selectedCatId) rootOpt.selected = true;
          grp.appendChild(rootOpt);
          root.subcategories.forEach(sub => {
            const opt = document.createElement('option');
            opt.value = sub.id;
            opt.innerText = `${sub.icon || ''} ${sub.name}`;
            if (sub.id === selectedCatId) opt.selected = true;
            grp.appendChild(opt);
          });
          catSelect.appendChild(grp);
        } else {
          const opt = document.createElement('option');
          opt.value = root.id;
          opt.innerText = `${root.icon || ''} ${root.name}`;
          if (root.id === selectedCatId) opt.selected = true;
          catSelect.appendChild(opt);
        }
      });
    }

    function onEditTxTypeChange() {
      const txType = document.getElementById('editTxType').value;
      populateEditTxCategories(txType, null);
    }

    function closeEditTxModal() {
      document.getElementById('modalEditTx').classList.add('hidden');
    }

    async function submitEditTransaction() {
      const tx_id = document.getElementById('editTxId').value;
      const tx_date = document.getElementById('editTxDate').value;
      const amount_rub = parseFloat(document.getElementById('editTxAmount').value);
      const tx_type = document.getElementById('editTxType').value;
      const category_id = document.getElementById('editTxCategory').value;
      const account_id = document.getElementById('editTxAccount').value;
      const description = document.getElementById('editTxDescription').value.trim() || 'Операция';
      const msgEl = document.getElementById('editTxMsg');

      if (!amount_rub || amount_rub <= 0) {
        msgEl.innerHTML = '<div class="alert alert-error">Укажите сумму больше нуля</div>';
        return;
      }
      if (!tx_date) {
        msgEl.innerHTML = '<div class="alert alert-error">Укажите дату операции</div>';
        return;
      }

      const btn = document.getElementById('btnSaveEditTx');
      btn.disabled = true;
      try {
        const res = await fetch('/api/transactions/update', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({
            transaction_id: tx_id,
            tx_date: tx_date,
            amount_rub: amount_rub,
            description: description,
            category_id: category_id || null,
            account_id: account_id || null,
            tx_type: tx_type
          })
        });
        const data = await res.json();
        if (data.status === 'success') {
          closeEditTxModal();
          await loadDashboard();
          await loadTransactions(currentSelectedMonth);
          await loadAnalytics(currentSelectedMonth);
        } else {
          msgEl.innerHTML = `<div class="alert alert-error">${data.message || 'Ошибка обновления'}</div>`;
        }
      } catch (e) {
        msgEl.innerHTML = `<div class="alert alert-error">Ошибка сети: ${e.message}</div>`;
      } finally {
        btn.disabled = false;
      }
    }

    async function submitEditTx() {
      return await submitEditTransaction();
    }

    async function deleteTransaction(txId, encodedDesc, amount) {
      const desc = decodeURIComponent(encodedDesc || '');
      if (!confirm(`Удалить операцию "${desc || 'Операция'}" на сумму ${amount || ''}?`)) {
        return;
      }
      try {
        const res = await fetch('/api/transactions/delete', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({
            transaction_id: txId,
            reason: 'Удалено пользователем'
          })
        });
        const data = await res.json();
        if (data.status === 'success') {
          await loadDashboard();
          await loadTransactions(currentSelectedMonth);
          await loadAnalytics(currentSelectedMonth);
        } else {
          alert('Ошибка удаления: ' + (data.message || 'Неизвестная ошибка'));
        }
      } catch (e) {
        alert('Ошибка связи: ' + e.message);
      }
    }

    function deleteTransactionFromModal() {
      const txId = document.getElementById('editTxId').value;
      const desc = encodeURIComponent(document.getElementById('editTxDescription').value || '');
      const amount = document.getElementById('editTxAmount').value + ' ₽';
      closeEditTxModal();
      deleteTransaction(txId, desc, amount);
    }

    async function updateSyncStatus() {

      if (!sessionToken) return;

      try {

        const res = await fetch('/api/sync/status', { headers: authHeaders() });

        if (res.ok) {

          const data = await res.json();

          const badge = document.getElementById('syncBadge');

          const count = data.active_peers ? data.active_peers.length : 0;

          if (count > 0) {

            badge.innerText = `📡 P2P: ${count} пир(а)`;

            badge.style.background = '#059669';

          } else {

            badge.innerText = '📡 Автономно';

            badge.style.background = '#475569';

          }

        }

      } catch (e) {}

    }

    // Sync polling disabled for local home mode

    async function triggerLanSync() {

      try {

        const res = await fetch('/api/sync/status', { headers: authHeaders() });

        const data = await res.json();

        if (!data.active_peers || data.active_peers.length === 0) {

          alert(`В домашней локальной сети не обнаружено активных устройств Family Finances OS.\nУбедитесь, что второе устройство подключено к тому же Wi-Fi роутеру.`);

          return;

        }

        for (const peer of data.active_peers) {

          const syncRes = await fetch('/api/sync/trigger', {

            method: 'POST',

            headers: authHeaders(),

            body: JSON.stringify({ peer_ip: peer.ip, peer_port: peer.http_port })

          });

          const result = await syncRes.json();

          if (result.status === 'success') {

            alert(`Синхронизация с устройством '${peer.device_name}' (${peer.ip}) успешно завершена!`);

            await loadDashboard();

          } else {

            alert(`Ошибка синхронизации: ${result.message}`);

          }

        }

      } catch (err) {

        alert('Ошибка при выполнении синхронизации: ' + err.message);

      }

    }

    async function submitOnboarding() {

      const mainCard = document.getElementById('obMainCard').value || 0;

      const wifeCard = document.getElementById('obWifeCard').value || 0;

      const cash = document.getElementById('obCash').value || 0;

      const credLimit = document.getElementById('obCreditLimit').value || 0;

      const credDebt = document.getElementById('obCreditDebt').value || 0;

      const oblName = document.getElementById('obOblName').value.trim();

      const oblAmount = document.getElementById('obOblAmount').value || 0;

      const oblDay = parseInt(document.getElementById('obOblDay').value) || 15;

      const mainAcc = overviewData.accounts.find(a => a.code === '1010');

      const wifeAcc = overviewData.accounts.find(a => a.code === '1012') || overviewData.accounts.find(a => a.code === '1011');

      const cashAcc = overviewData.accounts.find(a => a.code === '1020');

      const credAcc = overviewData.accounts.find(a => a.code === '2020');

      const balances = [];

      if (mainAcc && parseFloat(mainCard) > 0) {

        balances.push({ account_id: mainAcc.id, balance_rub: String(mainCard) });

      }

      if (wifeAcc && parseFloat(wifeCard) > 0) {

        balances.push({ account_id: wifeAcc.id, balance_rub: String(wifeCard) });

      }

      if (cashAcc && parseFloat(cash) > 0) {

        balances.push({ account_id: cashAcc.id, balance_rub: String(cash) });

      }

      if (credAcc) {

        balances.push({

          account_id: credAcc.id,

          balance_rub: String(credDebt),

          credit_limit_rub: String(credLimit)

        });

      }

      const obligations = [];

      if (oblName && parseFloat(oblAmount) > 0) {

        obligations.push({

          name: oblName,

          amount_rub: String(oblAmount),

          due_day: oblDay,

          payment_account_id: mainAcc ? mainAcc.id : null

        });

      }

      try {

        const res = await fetch('/api/onboarding/setup', {

          method: 'POST',

          headers: authHeaders(),

          body: JSON.stringify({ balances, obligations })

        });

        const data = await res.json();

        if (data.status === 'success') {

          sessionStorage.setItem('ffos_onboarding_dismissed', 'true');

          document.getElementById('onboardingBanner').classList.add('hidden');

          await loadDashboard();

          alert('Стартовый баланс семьи успешно зафиксирован! Теперь система точно считает Safe-to-Spend.');

        } else {

          alert('Ошибка сохранения: ' + data.message);

        }

      } catch (err) {

        alert('Ошибка связи с сервером: ' + err.message);

      }

    }

    const financialFetch = window.fetch.bind(window);
    const commandRoutes = new Set(['/api/goals/contribute','/api/debts/pay','/api/envelopes/deposit','/api/envelopes/withdraw','/api/envelopes/transfer']);
    window.fetch = async function financialCommandFetch(resource, options) {
      const route = typeof resource === 'string' ? resource.split('?')[0] : '';
      let key = null;
      if (commandRoutes.has(route) && options?.method === 'POST' && typeof options.body === 'string') {
        const payload = JSON.parse(options.body);
        if (!payload.idempotency_key) {
          const fingerprint = route + ':' + options.body;
          const previous = JSON.parse(sessionStorage.getItem('ffos_pending_command') || 'null');
          key = previous?.fingerprint === fingerprint ? previous.key : crypto.randomUUID();
          sessionStorage.setItem('ffos_pending_command', JSON.stringify({ fingerprint, key }));
          options = { ...options, body: JSON.stringify({ ...payload, idempotency_key: key }) };
        }
      }
      const response = await financialFetch(resource, options);
      if (key && response.ok) {
        const result = await response.clone().json();
        if (result.status === 'success') {
          const pending = JSON.parse(sessionStorage.getItem('ffos_pending_command') || 'null');
          if (pending?.key === key) sessionStorage.removeItem('ffos_pending_command');
        }
      }
      return response;
    };

    let currentPreviewItems = [];

    function populateImportAccounts() {

      const sel = document.getElementById('importAccountSelect');

      if (!sel || !overviewData) return;

      sel.innerHTML = '';

      overviewData.accounts.filter(a => a.type === 'ASSET' || a.type === 'LIABILITY').forEach(a => {

        const opt = document.createElement('option');

        opt.value = a.id;

        opt.innerText = `${a.code} - ${a.name} (${a.subtype})`;

        sel.appendChild(opt);

      });

    }

    function handleFileSelect(evt) {

      const file = evt.target.files[0];

      if (!file) return;

      const reader = new FileReader();

      reader.onload = function(e) {

        document.getElementById('importRawText').value = e.target.result;

      };

      reader.readAsText(file, 'utf-8');

    }

    async function runImportPreview() {

      const csvText = document.getElementById('importRawText').value.trim();

      if (!csvText) {

        alert('Пожалуйста, выберите файл выписки или вставьте текст в поле ввода.');

        return;

      }

      try {

        const res = await fetch('/api/import/preview', {

          method: 'POST',

          headers: authHeaders(),

          body: JSON.stringify({ csv_text: csvText })

        });

        const data = await res.json();

        if (data.status === 'success') {

          currentPreviewItems = data.items;

          renderImportPreview();

        } else {

          alert('Ошибка распознавания: ' + data.message);

        }

      } catch (err) {

        alert('Ошибка связи с сервером: ' + err.message);

      }

    }

    function renderImportPreview() {

      const container = document.getElementById('importPreviewContainer');

      const countLabel = document.getElementById('importPreviewCount');

      const tbody = document.getElementById('importPreviewBody');

      countLabel.innerText = `Распознано операций: ${currentPreviewItems.length}`;

      tbody.innerHTML = '';

      currentPreviewItems.forEach((item, idx) => {

        const tr = document.createElement('tr');

        const dirBadge = item.direction === 'INCOME' ?

          '<span class="badge" style="background:#065f46; color:#6ee7b7;">+ Доход</span>' :

          '<span class="badge" style="background:#991b1b; color:#fca5a5;">- Расход</span>';

        tr.innerHTML = `

          <td>${escapeHtml(item.date)}</td>

          <td>${dirBadge}</td>

          <td>${escapeHtml(item.description)}</td>

          <td>

            <select id="importCatSelect_${idx}" style="padding:4px; font-size:12px; background:var(--card-bg); color:var(--text); border:1px solid var(--border); border-radius:4px;" onchange="currentPreviewItems[${idx}].category_id = this.value">

              <option value="">Без категории</option>

              ${categoryData ? (categoryData.flat || []).map(c => `<option value="${c.id}" ${c.id === item.category_id ? 'selected' : ''}>${escapeHtml(c.name)}</option>`).join('') : ''}

            </select>

          </td>

          <td style="font-weight:600; color:${item.direction === 'INCOME' ? '#34d399' : '#f87171'};">

            ${item.direction === 'INCOME' ? '+' : '-'}${item.amount_rub} ₽

          </td>

        `;

        tbody.appendChild(tr);

      });

      container.classList.remove('hidden');

    }

    async function confirmImport() {

      const targetAccId = document.getElementById('importAccountSelect').value;

      if (!targetAccId) {

        alert('Выберите целевой счет для импорта');

        return;

      }

      if (!currentPreviewItems || !currentPreviewItems.length) {

        alert('Нет операций для импорта');

        return;

      }

      const btn = document.getElementById('btnConfirmImport');

      btn.disabled = true;

      try {

        const res = await fetch('/api/import/confirm', {

          method: 'POST',

          headers: authHeaders(),

          body: JSON.stringify({ account_id: targetAccId, items: currentPreviewItems })

        });

        const data = await res.json();

        if (res.ok && ['success', 'partial'].includes(data.status)) {

          alert(`Импортировано: ${data.imported_count}; дубликатов: ${data.skipped_count}; ошибок: ${data.error_count || 0}.` +
            ((data.errors || []).length ? String.fromCharCode(10) + data.errors.map(e => `Строка ${e.line_num ?? '?'}: ${e.message}`).join(String.fromCharCode(10)) : '') +
            (data.identity_warning ? String.fromCharCode(10) + data.identity_warning : ''));

          currentPreviewItems = [];

          document.getElementById('importPreviewContainer').classList.add('hidden');

          document.getElementById('importRawText').value = '';

          await loadDashboard();

          switchTab('tab-overview');

        } else {

          alert('Ошибка импорта: ' + data.message);

        }

      } catch (err) {

        alert('Ошибка связи с сервером: ' + err.message);

      } finally {

        btn.disabled = false;

      }

    }

    // =========================================================================

    // Stage 9: Smart Quick Input, Financial Goals & Debt Repayment Functions

    // =========================================================================

    // --- Smart Quick Input ---

    let quickInputDebounceTimer = null;

    async function onQuickInputLive(val, previewId) {

      const previewEl = document.getElementById(previewId);

      if (!previewEl) return;

      val = (val || '').trim();

      if (!val) {

        previewEl.classList.add('hidden');

        previewEl.innerText = '';

        return;

      }

      clearTimeout(quickInputDebounceTimer);

      quickInputDebounceTimer = setTimeout(async () => {

        try {

          const res = await fetch('/api/quick-tx/parse', {

            method: 'POST',

            headers: authHeaders(),

            body: JSON.stringify({ text: val })

          });

          if (res.status === 401 || res.status === 423) return;

          const data = await res.json();

          if (data.status === 'success' && data.parsed) {

            const p = data.parsed;

            const dirLabel = p.direction === 'INCOME' ? '🟢 Доход' : '🔴 Расход';

            const catLabel = p.category_name ? ` · 🏷️ ${p.category_name}` : '';

            const accLabel = p.account_name ? ` · 💳 ${escapeHtml(p.account_name)}` : '';

            previewEl.innerHTML = `⚡ <strong>Распознано:</strong> ${p.amount_rub} ₽ (${dirLabel}${catLabel}${accLabel}) — <em>"${p.description}"</em>`;

            previewEl.classList.remove('hidden');

          } else {

            previewEl.classList.add('hidden');

          }

        } catch (e) {

          previewEl.classList.add('hidden');

        }

      }, 250);

    }

    async function submitQuickInput(inputId, msgId) {

      const inputEl = document.getElementById(inputId);

      const msgEl = document.getElementById(msgId);

      if (!inputEl) return;

      const text = inputEl.value.trim();

      if (!text) {

        if (msgEl) msgEl.innerHTML = '<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Введите текст операции (например: 500 кофе)</div>';

        return;

      }

      try {

        const res = await fetch('/api/quick-tx/create', {

          method: 'POST',

          headers: authHeaders(),

          body: JSON.stringify({ text })

        });

        const data = await res.json();

        if (data.status === 'success') {

          inputEl.value = '';

          const previewId = inputId === 'dashQuickInput' ? 'dashQuickPreview' : 'txQuickPreview';

          const prevEl = document.getElementById(previewId);

          if (prevEl) prevEl.classList.add('hidden');

          if (msgEl) {

            msgEl.innerHTML = `<div class="alert alert-success" style="padding:6px 10px; font-size:12px;">✅ Записано: <strong>${data.parsed.amount_rub} ₽</strong> (${data.parsed.description} · ${data.parsed.category_name || 'Без категории'})</div>`;

            setTimeout(() => { if (msgEl) msgEl.innerHTML = ''; }, 4000);

          }

          await loadDashboard();

          await loadGoalsWidget();

        } else {

          if (msgEl) {

            msgEl.innerHTML = `<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">❌ Ошибка: ${data.message}</div>`;

          }

        }

      } catch (e) {

        if (msgEl) {

          msgEl.innerHTML = `<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Ошибка сети: ${e.message}</div>`;

        }

      }

    }

    async function submitSmartTx(inputId = 'txQuickInput', msgId = 'txQuickMsg') {

      return await submitQuickInput(inputId, msgId);

    }

    function applyQuickPreset(text) {

      const inputEl = document.getElementById('dashQuickInput') || document.getElementById('txQuickInput');

      if (inputEl) {

        inputEl.value = text;

        const previewId = inputEl.id === 'dashQuickInput' ? 'dashQuickPreview' : 'txQuickPreview';

        onQuickInputLive(text, previewId);

        inputEl.focus();

      }

    }

    function addTxAmount(rub) {

      const el = document.getElementById('txAmount');

      if (!el) return;

      const current = parseFloat(el.value) || 0;

      el.value = (current + rub).toFixed(2);

    }

    function autoSelectCategoryByDesc(text) {

      if (!text || !categoryData || !categoryData.flat) return;

      const lower = text.toLowerCase();

      const match = categoryData.flat.find(c => {

        const cLower = c.name.toLowerCase();

        if (cLower.includes(lower) || lower.includes(cLower)) return true;

        if (lower.includes('кофе') && cLower.includes('кафе')) return true;

        if ((lower.includes('еда') || lower.includes('продукт') || lower.includes('магаз')) && (cLower.includes('продукт') || cLower.includes('супермаркет'))) return true;

        if ((lower.includes('такси') || lower.includes('бензин') || lower.includes('проезд')) && (cLower.includes('транспорт') || cLower.includes('авто'))) return true;

        if ((lower.includes('аптек') || lower.includes('лекарств')) && (cLower.includes('здоров') || cLower.includes('медиц') || cLower.includes('аптек'))) return true;

        if ((lower.includes('зарплат') || lower.includes('аванс')) && cLower.includes('зарплат')) return true;

        return false;

      });

      if (match) {
        const select = document.getElementById('txCategorySelect');
        const selectModal = document.getElementById('txInputCategory');
        if (select) select.value = match.id;
        if (selectModal) selectModal.value = match.id;
        selectedCategoryId = match.id;
        onSelectCategory(match.id, 'txCatMenu');
        onSelectCategory(match.id, 'modalTxCatMenu');
      }

    }

    // --- Financial Goals Management ---

    let allGoalsData = [];

    let activeContribGoal = null;

    async function loadGoals() {

      const container = document.getElementById('goalsListContainer');

      if (!container) return;

      try {

        const res = await fetch('/api/goals', { headers: authHeaders() });

        if (res.status === 401 || res.status === 423) return;

        const rawGoals = await res.json();
        allGoalsData = Array.isArray(rawGoals) ? rawGoals : (rawGoals.goals || []);

        if (!allGoalsData || allGoalsData.length === 0) {

          container.innerHTML = `

            <div style="grid-column: 1 / -1; text-align: center; padding: 32px 16px; background: rgba(255,255,255,0.02); border-radius: 12px; border: 1px dashed var(--border);">

              <div style="font-size: 36px; margin-bottom: 8px;">🎯</div>

              <div style="font-size: 16px; font-weight: 600; color: var(--text); margin-bottom: 4px;">У вас пока нет активных финансовых целей</div>

              <div style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">

                Поставьте первую цель (подушка безопасности, отпуск, ремонт), чтобы система помогала копить и рассчитывала темп.

              </div>

              <button class="btn btn-success" onclick="openNewGoalModal()">➕ Создать первую цель</button>

            </div>

          `;

          return;

        }

        container.innerHTML = allGoalsData.map(g => {

          const isDone = g.is_completed || g.progress_percent >= 100;

          const barColor = isDone ? '#10b981' : (g.progress_percent >= 50 ? '#3b82f6' : '#f59e0b');

          const statusBadge = isDone 

            ? '<span class="badge" style="background: rgba(16,185,129,0.2); color: #34d399; border: 1px solid #10b981;">🎉 Достигнута!</span>'

            : `<span class="badge" style="background: rgba(59,130,246,0.2); color: #60a5fa; border: 1px solid #3b82f6;">В процессе (${g.progress_percent}%)</span>`;

          const paceText = g.recommended_monthly_rub 

            ? `<div style="font-size: 12px; color: #38bdf8; margin-top: 6px;">🎯 Рекомендуемый темп: <strong>${g.recommended_monthly_rub} ₽/мес</strong></div>`

            : '';

          const dateText = g.target_date 

            ? `<span style="font-size: 11px; color: var(--text-muted);">Срок: ${g.target_date}</span>`

            : '<span style="font-size: 11px; color: var(--text-muted);">Бессрочно</span>';

          const accText = g.account_name 

            ? `<div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">🏦 Счет: ${escapeHtml(g.account_name)}</div>`

            : '';

          return `

            <div class="card" style="margin-bottom: 0; display: flex; flex-direction: column; justify-content: space-between; border-color: ${isDone ? '#059669' : 'var(--border)'}; background: ${isDone ? 'rgba(5, 150, 105, 0.05)' : 'var(--card-bg)'};">

              <div>

                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">

                  <div style="display: flex; align-items: center; gap: 8px;">

                    <span style="font-size: 26px;">${g.icon || '🎯'}</span>

                    <div>

                      <div style="font-weight: 700; font-size: 16px; color: var(--text);">${escapeHtml(g.name)}</div>

                      ${dateText}

                    </div>

                  </div>

                  ${statusBadge}

                </div>

                <div style="margin: 12px 0 8px 0;">

                  <div style="display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 6px;">

                    <span style="color: var(--text-muted);">Накоплено: <strong style="color: var(--text);">${g.current_amount_rub} ₽</strong></span>

                    <span style="color: var(--text-muted);">Цель: <strong style="color: var(--text);">${g.target_amount_rub} ₽</strong></span>

                  </div>

                  <div class="progress-bar-bg" style="height: 10px; border-radius: 5px;">

                    <div class="progress-bar-fill" style="width: ${g.progress_percent}%; background: ${barColor}; height: 100%; border-radius: 5px;"></div>

                  </div>

                  <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 6px;">

                    <span style="font-size: 12px; color: ${isDone ? '#34d399' : 'var(--text-muted)'};">

                      ${isDone ? 'Цель полностью профинансирована!' : `Осталось: <strong style="color: #f87171;">${g.remaining_rub} ₽</strong>`}

                    </span>

                    <span style="font-size: 12px; font-weight: 700; color: ${barColor};">${g.progress_percent}%</span>

                  </div>

                  ${paceText}

                  ${accText}

                  ${g.note ? `<div style="font-size: 11px; color: var(--text-muted); font-style: italic; margin-top: 6px;">💬 ${escapeHtml(g.note)}</div>` : ''}

                </div>

              </div>

              <div style="display: flex; gap: 6px; margin-top: 14px; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 10px;">

                ${!isDone ? `<button class="btn btn-success" style="flex: 1; padding: 6px 10px; font-size: 12px;" onclick="openContributeGoalModal('${g.id}')">💰 Пополнить</button>` : ''}

                <button class="btn btn-secondary" style="padding: 6px 10px; font-size: 12px;" onclick="openEditGoalModal('${g.id}')" title="Редактировать">✏️</button>

                <button class="btn btn-secondary" style="padding: 6px 10px; font-size: 12px;" onclick="archiveGoal('${g.id}')" title="Архивировать">📦</button>

              </div>

            </div>

          `;

        }).join('');

      } catch (e) {

        console.error('loadGoals error:', e);

      }

    }

    async function loadGoalsWidget() {

      const container = document.getElementById('dashGoalsContainer');

      if (!container) return;

      try {

        const res = await fetch('/api/goals', { headers: authHeaders() });

        if (res.status === 401 || res.status === 423) return;

        const rawWidget = await res.json();
        const goals = Array.isArray(rawWidget) ? rawWidget : (rawWidget.goals || []);
        allGoalsData = goals;

        if (!goals || goals.length === 0) {

          container.innerHTML = `

            <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; background: rgba(255,255,255,0.02); border-radius: 8px;">

              <span style="color: var(--text-muted); font-size: 13px;">Целей пока нет. Начните копить на мечту или подушку безопасности!</span>

              <button class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="openNewGoalModal()">+ Поставить цель</button>

            </div>

          `;

          return;

        }

        const activeGoals = goals.filter(g => !g.is_completed).slice(0, 3);

        if (activeGoals.length === 0) {

          container.innerHTML = `

            <div style="padding: 8px 12px; background: rgba(16,185,129,0.05); border-radius: 8px; font-size: 13px; color: #34d399;">

              🎉 Все установленные цели накоплений успешно достигнуты!

            </div>

          `;

          return;

        }

        container.innerHTML = activeGoals.map(g => `

          <div style="padding: 8px 10px; background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); border-radius: 8px;">

            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">

              <span style="font-size: 13px; font-weight: 600; color: var(--text);">${g.icon || '🎯'} ${escapeHtml(g.name)}</span>

              <div style="display: flex; align-items: center; gap: 8px;">

                <span style="font-size: 12px; font-weight: 600; color: #34d399;">${g.current_amount_rub} / ${g.target_amount_rub} ₽</span>

                <button class="btn btn-secondary" style="padding: 2px 7px; font-size: 11px;" onclick="openContributeGoalModal('${g.id}')">+ Внести</button>

              </div>

            </div>

            <div class="progress-bar-bg" style="height: 6px;">

              <div class="progress-bar-fill" style="width: ${g.progress_percent}%; background: #3b82f6; height: 100%;"></div>

            </div>

          </div>

        `).join('');

      } catch (e) {

        console.error('loadGoalsWidget error:', e);

      }

    }

    function populateGoalAccountSelect(selectedId) {

      const sel = document.getElementById('goalInputAccount');

      if (!sel) return;

      sel.innerHTML = '<option value="">(Не привязывать к отдельному счёту)</option>';

      if (overviewData && overviewData.accounts) {

        overviewData.accounts.filter(a => a.type === 'ASSET').forEach(a => {

          const opt = document.createElement('option');

          opt.value = a.id;

          opt.innerText = `${a.name} (${a.subtype}, ${a.balance_rub} ₽)`;

          if (selectedId && a.id === selectedId) opt.selected = true;

          sel.appendChild(opt);

        });

      }

    }

    function openNewGoalModal() {

      document.getElementById('goalEditId').value = '';

      document.getElementById('goalModalTitle').innerHTML = '<span>🎯</span> <span>Новая цель накоплений</span>';

      document.getElementById('goalInputName').value = '';

      document.getElementById('goalInputTarget').value = '';

      document.getElementById('goalInputIcon').value = '🎯';

      document.getElementById('goalInputDate').value = '';

      document.getElementById('goalInputInitial').value = '0';

      document.getElementById('goalInputNote').value = '';

      document.getElementById('goalModalMsg').innerHTML = '';

      populateGoalAccountSelect(null);

      document.getElementById('modalGoal').classList.remove('hidden');

    }

    function openEditGoalModal(goalId) {

      const goal = allGoalsData.find(g => g.id === goalId);

      if (!goal) return;

      document.getElementById('goalEditId').value = goal.id;

      document.getElementById('goalModalTitle').innerHTML = '<span>✏️</span> <span>Редактировать цель</span>';

      document.getElementById('goalInputName').value = goal.name;

      document.getElementById('goalInputTarget').value = goal.target_amount_rub;

      document.getElementById('goalInputIcon').value = goal.icon || '🎯';

      document.getElementById('goalInputDate').value = goal.target_date || '';

      document.getElementById('goalInputInitial').value = goal.current_amount_rub;

      document.getElementById('goalInputNote').value = goal.note || '';

      document.getElementById('goalModalMsg').innerHTML = '';

      populateGoalAccountSelect(goal.account_id);

      document.getElementById('modalGoal').classList.remove('hidden');

    }

    function closeGoalModal() {

      document.getElementById('modalGoal').classList.add('hidden');

    }

    async function submitSaveGoal() {

      const goalId = document.getElementById('goalEditId').value;

      const name = document.getElementById('goalInputName').value.trim();

      const target_amount_rub = document.getElementById('goalInputTarget').value;

      const icon = document.getElementById('goalInputIcon').value;

      const target_date = document.getElementById('goalInputDate').value || null;

      const initial_saved_rub = document.getElementById('goalInputInitial').value || '0';

      const account_id = document.getElementById('goalInputAccount').value || null;

      const note = document.getElementById('goalInputNote').value.trim() || null;

      const msgEl = document.getElementById('goalModalMsg');

      if (!name) {

        msgEl.innerHTML = '<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Укажите название цели</div>';

        return;

      }

      if (!target_amount_rub || parseFloat(target_amount_rub) <= 0) {

        msgEl.innerHTML = '<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Укажите целевую сумму больше нуля</div>';

        return;

      }

      const endpoint = goalId ? '/api/goals/update' : '/api/goals/create';

      const payload = goalId 

        ? { goal_id: goalId, name, target_amount_rub, icon, target_date, account_id, note }

        : { name, target_amount_rub, icon, target_date, initial_saved_rub, account_id, note };

      try {

        const res = await fetch(endpoint, {

          method: 'POST',

          headers: authHeaders(),

          body: JSON.stringify(payload)

        });

        const data = await res.json();

        if (data.status === 'success') {

          closeGoalModal();

          await loadGoals();

          await loadGoalsWidget();

          LocalDatabaseVault.syncAfterMutation();

        } else {

          msgEl.innerHTML = `<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Ошибка: ${data.message}</div>`;

        }

      } catch (e) {

        msgEl.innerHTML = `<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Ошибка сети: ${e.message}</div>`;

      }

    }

    async function archiveGoal(goalId) {

      if (!confirm('Архивировать эту цель накоплений?')) return;

      try {

        const res = await fetch('/api/goals/archive', {

          method: 'POST',

          headers: authHeaders(),

          body: JSON.stringify({ goal_id: goalId })

        });

        const data = await res.json();

        if (data.status === 'success') {

          await loadGoals();

          await loadGoalsWidget();

          LocalDatabaseVault.syncAfterMutation();

        } else {

          alert('Ошибка: ' + data.message);

        }

      } catch (e) {

        alert('Ошибка связи с сервером: ' + e.message);

      }

    }

    function openContributeGoalModal(goalId) {

      activeContribGoal = allGoalsData.find(g => g.id === goalId);

      if (!activeContribGoal) return;

      document.getElementById('contribGoalId').value = activeContribGoal.id;

      document.getElementById('contribGoalTitle').innerText = `Пополнить: ${activeContribGoal.icon || '🎯'} ${activeContribGoal.name}`;

      document.getElementById('contribGoalRemaining').innerText = `Осталось накопить: ${activeContribGoal.remaining_rub} ₽ из ${activeContribGoal.target_amount_rub} ₽`;

      document.getElementById('contribGoalAmount').value = '';

      document.getElementById('contribGoalNote').value = `Пополнение цели "${activeContribGoal.name}"`;

      document.getElementById('contribGoalMsg').innerHTML = '';

      // Populate source accounts select with liquid asset accounts

      const sel = document.getElementById('contribSourceAccount');

      sel.innerHTML = '';

      if (overviewData && overviewData.accounts) {

        overviewData.accounts.filter(a => a.type === 'ASSET' && (a.subtype === 'CHECKING' || a.subtype === 'CASH' || a.subtype === 'SAVINGS')).forEach(a => {

          const opt = document.createElement('option');

          opt.value = a.id;

          opt.innerText = `${a.name} (${a.scope}, ${a.balance_rub} ₽)`;

          sel.appendChild(opt);

        });

      }

      document.getElementById('modalContributeGoal').classList.remove('hidden');

    }

    function closeContributeGoalModal() {

      document.getElementById('modalContributeGoal').classList.add('hidden');

    }

    function addContribAmount(amt) {

      const el = document.getElementById('contribGoalAmount');

      const cur = parseFloat(el.value) || 0;

      el.value = (cur + amt).toFixed(2);

    }

    function setContribAllRemaining() {

      if (!activeContribGoal) return;

      document.getElementById('contribGoalAmount').value = activeContribGoal.remaining_rub;

    }

    async function submitContributeGoal() {

      const goal_id = document.getElementById('contribGoalId').value;

      const amount_rub = document.getElementById('contribGoalAmount').value;

      const source_account_id = document.getElementById('contribSourceAccount').value || null;

      const note = document.getElementById('contribGoalNote').value.trim() || null;

      const msgEl = document.getElementById('contribGoalMsg');

      if (!amount_rub || parseFloat(amount_rub) <= 0) {

        msgEl.innerHTML = '<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Укажите сумму пополнения больше нуля</div>';

        return;

      }

      try {

        const res = await fetch('/api/goals/contribute', {

          method: 'POST',

          headers: authHeaders(),

          body: JSON.stringify({ goal_id, amount_rub, source_account_id, note })

        });

        const data = await res.json();

        if (data.status === 'success') {

          closeContributeGoalModal();

          await loadGoals();

          await loadGoalsWidget();

          await loadDashboard();

        } else {

          msgEl.innerHTML = `<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Ошибка: ${data.message}</div>`;

        }

      } catch (e) {

        msgEl.innerHTML = `<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Ошибка связи: ${e.message}</div>`;

      }

    }

    // --- Debts & Liabilities Management ---

    let allDebtsData = null;

    const DEBT_SUBTYPE_CONFIG = {
      CREDIT_CARD: { icon: '💳', name: 'Кредитная карта', badgeBg: '#be185d', badgeColor: '#fbcfe8' },
      MORTGAGE: { icon: '🏠', name: 'Ипотека', badgeBg: '#4338ca', badgeColor: '#c7d2fe' },
      CONSUMER_LOAN: { icon: '💰', name: 'Потребкредит', badgeBg: '#b45309', badgeColor: '#fde68a' },
      AUTO_LOAN: { icon: '🚗', name: 'Автокредит', badgeBg: '#047857', badgeColor: '#a7f3d0' },
      PERSONAL_DEBT: { icon: '🤝', name: 'Долг человеку', badgeBg: '#6d28d9', badgeColor: '#ddd6fe' },
      INSTALLMENT_BNPL: { icon: '🛍️', name: 'Рассрочка / Сплит', badgeBg: '#0e7490', badgeColor: '#a5f3fc' },
      LOAN: { icon: '📋', name: 'Кредит / Займ', badgeBg: '#b45309', badgeColor: '#fde68a' }
    };

    async function loadDebts() {
      const container = document.getElementById('debtsListContainer');
      if (!container) return;
      try {
        const res = await fetch('/api/debts', { headers: authHeaders() });
        if (res.status === 401) {
          container.innerHTML = '<div class="alert alert-error" style="padding:16px; text-align:center;">🔒 Сессия истекла. Пожалуйста, выполните вход заново.</div>';
          return;
        }
        if (res.status === 423) {
          container.innerHTML = '<div class="alert alert-warning" style="padding:16px; text-align:center;">🔒 База данных заблокирована мастер-паролем.</div>';
          return;
        }
        if (!res.ok) {
          container.innerHTML = `<div class="alert alert-error" style="padding:16px; text-align:center;">⚠️ Ошибка связи с сервером (${res.status}). Не удалось загрузить долги.</div>`;
          return;
        }
        allDebtsData = await res.json();
        
        // Update KPI summary cards
        const totalEl = document.getElementById('debtsTabTotal');
        if (totalEl) totalEl.innerText = (allDebtsData.total_debt_rub || '0.00') + ' ₽';
        const cardsEl = document.getElementById('debtsTabCards');
        if (cardsEl) cardsEl.innerText = (allDebtsData.credit_cards_debt_rub || '0.00') + ' ₽';
        const loansEl = document.getElementById('debtsTabLoans');
        if (loansEl) loansEl.innerText = (allDebtsData.loans_debt_rub || '0.00') + ' ₽';

        // Urgent Alert Banner
        const urgentBanner = document.getElementById('debtsUrgentBanner');
        const urgentText = document.getElementById('debtsUrgentBannerText');
        if (urgentBanner && urgentText) {
          if (allDebtsData.has_urgent_card_payment) {
            urgentBanner.classList.remove('hidden');
            urgentText.innerHTML = `<strong>Срочное внимание по кредитным картам семьи!</strong> Приближается срок платежа или допущена просрочка (карт с платежом: <strong>${allDebtsData.urgent_cards_count || 1}</strong>). Общий обязательный платеж: <strong>${allDebtsData.total_min_payments_rub || '0.00'} ₽</strong>. Внесите платежи вовремя, чтобы избежать неожиданных начислений по условиям ваших договоров.`;
          } else {
            urgentBanner.classList.add('hidden');
          }
        }

        const debts = Array.isArray(allDebtsData.debts) ? allDebtsData.debts : [];
        if (debts.length === 0) {
          container.innerHTML = `
            <div style="text-align: center; padding: 36px 16px; background: rgba(16,185,129,0.05); border-radius: 12px; border: 1px dashed rgba(16,185,129,0.3);">
              <div style="font-size: 40px; margin-bottom: 8px;">🎉</div>
              <div style="font-size: 18px; font-weight: 700; color: #34d399; margin-bottom: 6px;">У семьи нет открытых долгов!</div>
              <div style="font-size: 13px; color: var(--text-muted); max-width: 480px; margin: 0 auto 16px auto; line-height: 1.4;">
                Кредиты, кредитные карты и займы не зафиксированы. Если у вас есть кредитка, ипотека, рассрочка или долг человеку — добавьте их для точного контроля финансов и расчета Safe-to-Spend.
              </div>
              <button class="btn" onclick="openNewDebtModal()">➕ Добавить долг или кредит</button>
            </div>
          `;
          return;
        }

        container.innerHTML = debts.map(d => {
          const cfg = DEBT_SUBTYPE_CONFIG[d.subtype] || DEBT_SUBTYPE_CONFIG.LOAN;
          const isCard = d.subtype === 'CREDIT_CARD';
          const currency = escapeHtml(d.currency || 'RUB');
          const fullDebtNum = parseFloat(d.debt_rub) || 0;
          const typeBadge = `<span class="badge" style="background:${cfg.badgeBg}; color:${cfg.badgeColor}; display: inline-flex; align-items: center; gap: 4px;">${cfg.icon} ${cfg.name}</span>`;
          const hasDebt = (d.debt_cents || 0) > 0;
          
          let limitInfo = '';
          if (isCard && (d.credit_limit_cents || 0) > 0) {
            const usedPct = Math.min(100, Math.round(((d.debt_cents || 0) / d.credit_limit_cents) * 100));
            limitInfo = `
              <div style="margin-top: 8px;">
                <div style="display: flex; justify-content: space-between; font-size: 12px; color: var(--text-muted); margin-bottom: 4px;">
                  <span>Использовано лимита: <strong>${usedPct}%</strong></span>
                  <span>Лимит: <strong>${d.credit_limit_rub || '0.00'} ${currency}</strong> | Доступно: <strong>${d.available_rub || '0.00'} ${currency}</strong></span>
                </div>
                <div class="progress-bar-bg" style="height: 6px;">
                  <div class="progress-bar-fill" style="width: ${usedPct}%; background: ${usedPct > 80 ? '#ef4444' : (usedPct > 50 ? '#f59e0b' : '#10b981')}; height: 100%;"></div>
                </div>
              </div>
            `;
          }

          let cardBankingBlock = '';
          if (isCard && d.banking) {
            const b = d.banking;
            const statusColor = b.status_color === 'red' ? '#ef4444' : (b.status_color === 'yellow' ? '#f59e0b' : (b.status_color === 'green' ? '#10b981' : '#64748b'));
            const statusBg = b.status_color === 'red' ? 'rgba(239, 68, 68, 0.15)' : (b.status_color === 'yellow' ? 'rgba(245, 158, 11, 0.15)' : (b.status_color === 'green' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(100, 116, 139, 0.15)'));
            const statusBadge = `<span class="badge" style="background:${statusBg}; color:${statusColor}; border:1px solid ${statusColor}; font-weight:700; font-size:11px; padding:3px 8px;">${escapeHtml(b.status_label) || 'Активна'}</span>`;

            cardBankingBlock = `
              <div style="background: var(--card-hover); border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 8px; padding: 12px; margin-top: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 8px;">
                  <div style="display: flex; align-items: center; gap: 8px;">
                    <span style="font-size: 14px; font-weight: 700; color: var(--text);">🏦 Банковский контроль</span>
                    ${statusBadge}
                  </div>
                  <div style="font-size: 12px; color: var(--text-muted);">
                    ${b.grace_due_date ? `Дата платежа: <strong style="color: var(--text);">${b.grace_due_date}</strong>` : '<span style="color:#f59e0b;">Дата платежа не задана</span>'}
                  </div>
                </div>

                <!-- Warning message -->
                <div style="font-size: 12px; color: ${statusColor}; margin-bottom: 10px; line-height: 1.4; padding: 8px 12px; background: ${statusBg}; border-radius: 6px; border: 1px solid ${statusColor};">
                  ${escapeHtml(b.warning_message) || 'Контроль платежей по кредитной карте активен.'}
                </div>

                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; margin-bottom: 10px;">
                  <div style="background: var(--card-hover); padding: 8px 10px; border-radius: 6px;">
                    <div style="font-size: 11px; color: var(--text-muted);">Обязательный мин. платеж:</div>
                    <div style="font-size: 15px; font-weight: 700; color: #fbbf24;">${b.min_payment_formatted ?? b.min_payment_rub ?? '—'} ${currency}</div>
                    <div style="font-size: 10px; color: var(--text-muted);">${b.min_payment_percent ?? '—'}% от суммы долга</div>
                  </div>
                  <div style="background: var(--card-hover); padding: 8px 10px; border-radius: 6px;">
                    <div style="font-size: 11px; color: var(--text-muted);">Ставка банка вне грейса:</div>
                    <div style="font-size: 15px; font-weight: 700; color: #94a3b8;">${b.interest_rate_percent ?? '—'}% <span style="font-size: 11px;">годовых</span></div>
                    <div style="font-size: 10px; color: var(--text-muted);">Грейс действует только по условиям договора</div>
                  </div>
                  <div style="background: var(--card-hover); padding: 8px 10px; border-radius: 6px;">
                    <div style="font-size: 11px; color: var(--text-muted);">Неустойка за просрочку:</div>
                    <div style="font-size: 15px; font-weight: 700; color: #f87171;">${b.late_penalty_rate_percent ?? '—'}% <span style="font-size: 11px;">годовых</span></div>
                    <div style="font-size: 10px; color: var(--text-muted);">по договору Сбербанка</div>
                  </div>
                </div>

                <!-- Overdue Simulation Box -->
                ${hasDebt ? `
                  <div style="background: rgba(239, 68, 68, 0.08); border: 1px dashed rgba(239, 68, 68, 0.4); border-radius: 8px; padding: 10px 12px; margin-bottom: 10px;">
                    <div style="font-size: 12px; font-weight: 700; color: #fca5a5; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 4px; margin-bottom: 6px;">
                      <span>⚠️ Расчет банковских штрафов при просрочке на 30 дней:</span>
                      <span style="font-size: 13px; color: #ef4444; font-weight: 800;">+${b.simulation_30d_extra_rub || '0.00'} ${currency} переплаты</span>
                    </div>
                    <div style="font-size: 11px; color: var(--text-muted); display: grid; grid-template-columns: 1fr 1fr; gap: 6px; line-height: 1.4;">
                      <div>• Проценты по ставке (${b.interest_rate_percent ?? '—'}%): <strong style="color:#f87171;">+${b.simulation_30d_interest_rub || '0.00'} ${currency}</strong></div>
                      <div>• Неустойка банка (${b.late_penalty_rate_percent ?? '—'}%): <strong style="color:#f87171;">+${b.simulation_30d_penalty_rub || '0.00'} ${currency}</strong></div>
                    </div>
                    <div style="margin-top: 6px; padding-top: 6px; border-top: 1px solid rgba(239, 68, 68, 0.2); font-size: 12px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                      <span>Итого к оплате банку при просрочке:</span>
                      <strong style="color: #fca5a5; font-size: 14px;">${b.simulation_30d_total_rub || '0.00'} ${currency}</strong>
                    </div>
                  </div>
                ` : ''}

                <!-- Action buttons for this card -->
                <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                  ${hasDebt && b.min_payment_cents > 0 ? `
                    <button class="btn btn-secondary" style="font-size: 12px; padding: 6px 10px; color: #fbbf24; border-color: rgba(251, 191, 36, 0.4);" onclick="openPayDebtModal('${d.id}', ${b.min_payment_rub || 0})">
                      💳 Внести мин. платеж (${b.min_payment_formatted ?? b.min_payment_rub ?? '—'} ${currency})
                    </button>
                    <button class="btn btn-danger" style="font-size: 12px; padding: 6px 10px;" onclick="openPayDebtModal('${d.id}', ${fullDebtNum})">
                      💰 Закрыть весь долг (${d.debt_rub || '0.00'} ${currency})
                    </button>
                  ` : ''}
                  <button class="btn btn-secondary" style="font-size: 12px; padding: 6px 10px; color: #38bdf8; border-color: rgba(56, 189, 248, 0.4);" onclick="openCardSettingsModal('${d.id}')">
                    ⚙️ Условия карты и дата платежа
                  </button>
                </div>
              </div>
            `;
          }

          const obInfo = d.linked_obligation ? `
            <div style="font-size: 12px; color: #60a5fa; margin-top: 8px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; background: rgba(59,130,246,0.1); padding: 6px 12px; border-radius: 6px;">
              <span>📅 Привязан регулярный платеж: <strong>${d.linked_obligation.amount_rub || '0.00'} ${currency}</strong> (до ${d.linked_obligation.due_day}-го числа)</span>
              ${d.linked_obligation.is_paid ? '<span class="badge" style="background:#065f46; color:#6ee7b7; font-size:10px;">Оплачен в этом месяце</span>' : '<span class="badge" style="background:#991b1b; color:#fca5a5; font-size:10px;">Ожидает оплаты</span>'}
            </div>
          ` : '';

          const descInfo = (typeof d.description === 'string' && d.description.trim() && !d.description.trim().startsWith('{')) ? `
            <div style="font-size: 12px; color: #94a3b8; margin-top: 6px;">
              📝 <em>${escapeHtml(d.description.trim())}</em>
            </div>
          ` : '';

          const scopeBadge = (d.ownership_scope === 'PERSONAL_HUSBAND') 
            ? '<span class="badge" style="background: rgba(59,130,246,0.15); color: #93c5fd; font-size:11px;">Муж</span>' 
            : (d.ownership_scope === 'PERSONAL_WIFE')
              ? '<span class="badge" style="background: rgba(236,72,153,0.15); color: #f472b6; font-size:11px;">Жена</span>'
              : '';

          let payoffAcceleratorsHtml = '';
          if (isCard && d.banking && d.banking.payoff_scenarios && (d.debt_cents || 0) > 0) {
            const sc = d.banking.payoff_scenarios;
            const minSc = sc.minimum_scenario || null;
            const graceSc = sc.grace_scenario || null;
            const accSc = Array.isArray(sc.accelerated_scenarios) ? sc.accelerated_scenarios : [];

            if (minSc || (graceSc && graceSc.is_active) || accSc.length > 0) {
              payoffAcceleratorsHtml = `
                <div style="background: var(--card-hover); border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 8px; padding: 12px; margin-top: 10px;">
                  <div style="font-size: 13px; font-weight: 700; color: #38bdf8; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 6px; margin-bottom: 8px;">
                    <span>🚀 Стратегии: сколько платить, чтобы закрыть долг быстрее</span>
                    <span style="font-size: 11px; color: var(--text-muted);">Расчётная модель (${d.banking.interest_rate_percent ?? 24.8}% APR), без новых покупок и комиссий</span>
                  </div>

                  <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 8px; margin-bottom: 8px;">
                    <!-- Grace Period -->
                    ${graceSc && graceSc.is_active ? `
                      <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.4); border-radius: 6px; padding: 8px 10px; display: flex; flex-direction: column; justify-content: space-between;">
                        <div>
                          <div style="font-size: 11px; font-weight: 700; color: #34d399; margin-bottom: 2px;">💎 До указанной даты грейса</div>
                          <div style="font-size: 11px; color: var(--text-muted); line-height: 1.3;">
                            Срок: <strong style="color: var(--text);">${graceSc.days_left || 0} дн.</strong> (до ${graceSc.due_date || 'конца грейса'})<br>
                            Переплата: <strong style="color: #34d399;">0.00 ${currency}</strong> по условному грейс-сценарию
                          </div>
                        </div>
                        <button class="btn btn-secondary" style="font-size: 11px; padding: 4px 8px; margin-top: 6px; color: #34d399; border-color: rgba(52,211,153,0.4);" onclick="openPayDebtModal('${d.id}', ${fullDebtNum}, 100)">
                          Погасить основной долг (${d.debt_rub || '0.00'} ${currency})
                        </button>
                      </div>
                    ` : ''}

                    <!-- Minimum Payment Warning -->
                    ${minSc ? `
                      <div style="background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 6px; padding: 8px 10px; display: flex; flex-direction: column; justify-content: space-between;">
                        <div>
                          <div style="font-size: 11px; font-weight: 700; color: #fca5a5; margin-bottom: 2px;">⚠️ Мин. платеж (${minSc.payment_percent ?? 3.0}% от долга)</div>
                          <div style="font-size: 11px; color: var(--text-muted); line-height: 1.3;">
                            Платеж: <strong style="color: #fbbf24;">${minSc.first_payment_rub || '0.00'} ${currency}/мес</strong> (${minSc.payment_percent ?? 3.0}%)<br>
                            Срок: <strong style="color: #f87171;">${minSc.paid_off ? minSc.days_to_payoff + ' дн.' : 'Не определён'}</strong> (${minSc.paid_off ? minSc.months_to_payoff + ' мес.' : 'остаток ' + minSc.remaining_rub})<br>
                            Переплата: <strong style="color: #ef4444;">${minSc.total_interest_rub == null ? 'Не определена' : '+' + minSc.total_interest_rub + ' RUB'}</strong>
                          </div>
                        </div>
                        <button class="btn btn-secondary" style="font-size: 11px; padding: 4px 8px; margin-top: 6px; color: #fbbf24; border-color: rgba(251,191,36,0.4);" onclick="openPayDebtModal('${d.id}', ${(minSc.first_payment_cents || 0) / 100}, ${minSc.payment_percent ?? 3.0})">
                          Мин. платеж (${minSc.first_payment_rub || '0.00'} ${currency})
                        </button>
                      </div>
                    ` : ''}

                    <!-- Accelerated Horizons -->
                    ${accSc.filter(Boolean).map(a => `
                      <div style="background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 6px; padding: 8px 10px; display: flex; flex-direction: column; justify-content: space-between;">
                        <div>
                          <div style="font-size: 11px; font-weight: 700; color: #38bdf8; margin-bottom: 2px;">⚡ ${a.label || 'Ускоренное погашение'}</div>
                          <div style="font-size: 11px; color: var(--text-muted); line-height: 1.3;">
                            Платеж: <strong style="color: var(--text);">${a.monthly_payment_rub || '0.00'} ${currency}/мес</strong> (${a.monthly_payment_percent || 0}%)<br>
                            Срок: <strong style="color: #38bdf8;">${a.days || 0} дн.</strong> (${a.months || 0} мес.)<br>
                            Экономия: <strong style="color: #34d399;">${a.interest_savings_rub == null ? 'Не определена' : '+' + a.interest_savings_rub + ' RUB'}</strong>
                          </div>
                        </div>
                        <button class="btn btn-secondary" style="font-size: 11px; padding: 4px 8px; margin-top: 6px; color: #38bdf8; border-color: rgba(56,189,248,0.4);" onclick="openPayDebtModal('${d.id}', ${(a.monthly_payment_cents || 0) / 100}, ${a.monthly_payment_percent || 0})">
                          Платить ${a.monthly_payment_rub || '0.00'} ${currency}/мес
                        </button>
                      </div>
                    `).join('')}
                  </div>
                </div>
              `;
            }
          }

          const safeName = encodeURIComponent(d.name || '').split(String.fromCharCode(39)).join('%27');

          return `
            <div class="card" style="margin-bottom: 0; border-left: 4px solid ${hasDebt ? '#ef4444' : '#10b981'};">
              <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 10px;">
                <div>
                  <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                    <span style="font-size: 18px;">${cfg.icon}</span>
                    <strong style="font-size: 16px; color: var(--text);">${escapeHtml(d.name)}</strong>
                    ${typeBadge}
                    ${scopeBadge}
                    <span style="font-family: monospace; color: var(--text-muted); font-size: 11px;">${d.code}</span>
                  </div>
                  <div style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">
                    Остаток задолженности: <strong style="color: ${hasDebt ? '#f87171' : '#34d399'}; font-size: 17px;">${d.debt_rub || '0.00'} ${currency}</strong>
                  </div>
                  ${descInfo}
                </div>
                <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                  ${hasDebt ? `<button class="btn btn-danger" style="padding: 6px 14px; font-size: 13px;" onclick="openPayDebtModal('${d.id}')">💳 Погасить</button>` : '<span style="font-size: 12px; color: #34d399; font-weight: 600;">✅ Выплачен</span>'}
                  <button class="btn btn-secondary" style="padding: 6px 10px; font-size: 12px; color: var(--text-muted);" onclick="archiveDebt('${d.id}', '${safeName}')" title="Убрать в архив">📦 В архив</button>
                </div>
              </div>
              ${limitInfo}
              ${cardBankingBlock}
              ${payoffAcceleratorsHtml}
              ${obInfo}
            </div>
          `;
        }).join('');
      } catch (e) {
        console.error('loadDebts error:', e);
        if (container) {
          container.innerHTML = `<div class="alert alert-error" style="padding:16px; text-align:center;">⚠️ Не удалось отобразить список задолженностей: ${escapeHtml(e.message || 'Ошибка рендеринга')}. <button class="btn btn-secondary" style="margin-left:8px; padding:4px 10px; font-size:12px;" onclick="loadDebts()">Повторить</button></div>`;
        }
      }
    }

    function parseMobileFloat(val, fallback = 0) {
      if (val === null || val === undefined) return fallback;
      const s = String(val).replace(/[\\s\\u00a0]+/g, '').replace('₽', '').replace(',', '.').trim();
      if (!s) return fallback;
      const n = parseFloat(s);
      return isNaN(n) ? fallback : n;
    }

    function openNewDebtModal() {
      // Dismiss any open dropdowns so they do not cover the modal
      document.querySelectorAll('.category-dropdown-menu').forEach(m => m.classList.add('hidden'));

      document.getElementById('newDebtName').value = '';
      document.getElementById('newDebtCurrentAmount').value = '';
      document.getElementById('newDebtCreditLimit').value = '165000';
      document.getElementById('newDebtMonthlyPayment').value = '';
      document.getElementById('newDebtDueDay').value = '15';
      document.getElementById('newDebtNotes').value = '';
      document.getElementById('newDebtMsg').innerHTML = '';
      
      // Illustrative default rates; the grace due date must come from the user statement.
      const now = new Date();
      const lastDayOfMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0);
      const yyyy = lastDayOfMonth.getFullYear();
      const mm = String(lastDayOfMonth.getMonth() + 1).padStart(2, '0');
      const dd = String(lastDayOfMonth.getDate()).padStart(2, '0');
      const defDueDate = `${yyyy}-${mm}-${dd}`;

      const elDue = document.getElementById('newDebtGraceDueDate');
      if (elDue) elDue.value = '';
      const elApr = document.getElementById('newDebtApr');
      if (elApr) elApr.value = '24.8';
      const elGrace = document.getElementById('newDebtGraceDays');
      if (elGrace) elGrace.value = '120';
      const elMinPct = document.getElementById('newDebtMinPaymentPct');
      if (elMinPct) elMinPct.value = '3.0';
      const elPenalty = document.getElementById('newDebtLatePenaltyPct');
      if (elPenalty) elPenalty.value = '36.0';

      const chkOb = document.getElementById('chkCreateObligation');
      if (chkOb) {
        chkOb.checked = false;
        toggleDebtObligationFields(false);
      }
      const chkRec = document.getElementById('chkReceiveMoney');
      if (chkRec) {
        chkRec.checked = false;
        toggleDebtReceiveAccount(false);
      }

      const recAccSel = document.getElementById('newDebtReceiveAccount');
      if (recAccSel && overviewData && overviewData.accounts) {
        recAccSel.innerHTML = '';
        overviewData.accounts.filter(a => a.type === 'ASSET' && (a.subtype === 'CHECKING' || a.subtype === 'CASH' || a.subtype === 'DEBIT_CARD')).forEach(a => {
          const opt = document.createElement('option');
          opt.value = a.id;
          opt.innerText = `${a.name} (${a.balance_rub} ₽)`;
          recAccSel.appendChild(opt);
        });
      }

      selectDebtType('CREDIT_CARD');
      const debtModal = document.getElementById('modalNewDebt');
      debtModal.classList.remove('hidden');
      debtModal.scrollTop = 0;
      const modalCard = debtModal.querySelector('.card');
      if (modalCard) modalCard.scrollTop = 0;
    }

    function closeNewDebtModal() {
      document.getElementById('modalNewDebt').classList.add('hidden');
    }

    function selectDebtType(subtype) {
      document.querySelectorAll('.debt-type-btn').forEach(btn => {
        if (btn.getAttribute('data-type') === subtype) {
          btn.classList.add('active');
        } else {
          btn.classList.remove('active');
        }
      });
      document.getElementById('newDebtSubtype').value = subtype;

      const subtypeCatMap = {
        'CREDIT_CARD': '💳 Погашение кредитных карт',
        'CONSUMER_LOAN': '📋 Потребительские кредиты',
        'MORTGAGE': '🏠 Ипотечные платежи',
        'AUTO_LOAN': '🚗 Автокредиты',
        'INSTALLMENT_BNPL': '🛍️ Рассрочки и сплиты (BNPL)',
        'PERSONAL_DEBT': '🤝 Возврат долгов людям',
        'LOAN': '📋 Потребительские кредиты'
      };
      const catLabel = document.getElementById('newDebtCategoryLabel');
      if (catLabel) catLabel.innerText = subtypeCatMap[subtype] || '💳 Кредиты, долги и займы';

      const lblName = document.getElementById('lblDebtName');
      const inputName = document.getElementById('newDebtName');
      const lblAmount = document.getElementById('lblDebtAmount');
      const groupLimit = document.getElementById('groupCreditLimit');
      const inputNotes = document.getElementById('newDebtNotes');
      const groupBanking = document.getElementById('groupCreditCardBanking');
      const groupRec = document.getElementById('groupReceiveMoney');

      if (subtype === 'CREDIT_CARD') {
        lblName.innerText = 'Название карты / банк:';
        inputName.placeholder = 'Например: Кредитная СберКарта ТП-1001, Тинькофф...';
        lblAmount.innerText = 'Текущий долг по карте (₽):';
        groupLimit.style.display = 'block';
        if (groupBanking) groupBanking.style.display = 'block';
        if (groupRec) groupRec.style.display = 'none';
        inputNotes.placeholder = 'Договор 165 000 ₽, беспроцентный период 120 дней...';
      } else {
        if (groupBanking) groupBanking.style.display = 'none';
        if (groupRec) groupRec.style.display = 'block';
        if (subtype === 'MORTGAGE') {
          lblName.innerText = 'Название ипотеки (банк / объект):';
          inputName.placeholder = 'Например: Семейная ипотека Сбер (Квартира)...';
          lblAmount.innerText = 'Остаток основного долга (₽):';
          groupLimit.style.display = 'none';
          inputNotes.placeholder = 'Ставка 6%, договор №...';
        } else if (subtype === 'CONSUMER_LOAN') {
          lblName.innerText = 'Название кредита (банк / цель):';
          inputName.placeholder = 'Например: Потребкредит ВТБ на ремонт...';
          lblAmount.innerText = 'Остаток долга (₽):';
          groupLimit.style.display = 'none';
          inputNotes.placeholder = 'Ставка 14%, 36 месяцев...';
        } else if (subtype === 'AUTO_LOAN') {
          lblName.innerText = 'Название автокредита (автомобиль / банк):';
          inputName.placeholder = 'Например: Автокредит Geely, Кредит Совкомбанк...';
          lblAmount.innerText = 'Остаток долга за автомобиль (₽):';
          groupLimit.style.display = 'none';
          inputNotes.placeholder = 'КАСКО, договор №...';
        } else if (subtype === 'PERSONAL_DEBT') {
          lblName.innerText = 'Кому должны (имя / контакт):';
          inputName.placeholder = 'Например: Долг брату Олегу, Займ у друга...';
          lblAmount.innerText = 'Сумма долга (₽):';
          groupLimit.style.display = 'none';
          inputNotes.placeholder = 'Без процентов, вернуть до конца года...';
        } else if (subtype === 'INSTALLMENT_BNPL') {
          lblName.innerText = 'Название рассрочки (магазин / товар):';
          inputName.placeholder = 'Например: Яндекс Сплит (Ноутбук), Долями...';
          lblAmount.innerText = 'Остаток рассрочки (₽):';
          groupLimit.style.display = 'none';
          inputNotes.placeholder = '4 платежа каждые 2 недели...';
        } else {
          lblName.innerText = 'Название задолженности:';
          inputName.placeholder = 'Например: Кредит...';
          lblAmount.innerText = 'Сумма долга (₽):';
          groupLimit.style.display = 'none';
        }
      }
    }

    function toggleDebtObligationFields(checked) {
      const el = document.getElementById('debtObligationFields');
      if (el) el.style.display = checked ? 'grid' : 'none';
    }

    function toggleDebtReceiveAccount(checked) {
      const el = document.getElementById('debtReceiveAccountField');
      if (el) el.style.display = checked ? 'block' : 'none';
    }

    async function submitNewDebt() {
      const name = document.getElementById('newDebtName').value.trim();
      const subtype = document.getElementById('newDebtSubtype').value;
      const initial_debt_rub = parseMobileFloat(document.getElementById('newDebtCurrentAmount')?.value, 0);
      const credit_limit_rub = (subtype === 'CREDIT_CARD') ? parseMobileFloat(document.getElementById('newDebtCreditLimit')?.value, 0) : 0;
      const ownership_scope = document.getElementById('newDebtScope').value;
      const chkOb = document.getElementById('chkCreateObligation').checked;
      const monthly_payment_rub = chkOb ? parseMobileFloat(document.getElementById('newDebtMonthlyPayment')?.value, 0) : 0;
      const due_day = chkOb ? parseInt(document.getElementById('newDebtDueDay')?.value) : null;
      const receive_money = document.getElementById('chkReceiveMoney').checked;
      const destination_account_id = receive_money ? document.getElementById('newDebtReceiveAccount')?.value : null;
      const description = document.getElementById('newDebtNotes').value.trim();
      const msgEl = document.getElementById('newDebtMsg');

      const interest_rate_percent = (subtype === 'CREDIT_CARD') ? parseMobileFloat(document.getElementById('newDebtApr')?.value, 24.8) : 24.8;
      const grace_period_days = (subtype === 'CREDIT_CARD') ? Number(document.getElementById('newDebtGraceDays')?.value ?? 120) : 120;
      const grace_due_date = (subtype === 'CREDIT_CARD') ? (document.getElementById('newDebtGraceDueDate')?.value || null) : null;
      const min_payment_percent = (subtype === 'CREDIT_CARD') ? parseMobileFloat(document.getElementById('newDebtMinPaymentPct')?.value, 3.0) : 3.0;
      const late_penalty_rate_percent = (subtype === 'CREDIT_CARD') ? parseMobileFloat(document.getElementById('newDebtLatePenaltyPct')?.value, 36.0) : 36.0;

      if (!name) {
        msgEl.innerHTML = '<div class="alert alert-error">⚠️ Пожалуйста, укажите название карты или кредита</div>';
        const nameInput = document.getElementById('newDebtName');
        if (nameInput) {
          nameInput.focus();
          nameInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
        return;
      }

      const btn = document.getElementById('btnSubmitNewDebt');
      btn.disabled = true;
      const originalText = btn.innerText;
      btn.innerText = '⏳ Сохранение...';
      try {
        const res = await fetch('/api/debts/create', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({
            name,
            subtype,
            ownership_scope,
            initial_debt_rub,
            credit_limit_rub,
            monthly_payment_rub,
            due_day,
            receive_money,
            destination_account_id,
            description,
            interest_rate_percent,
            grace_period_days,
            grace_due_date,
            min_payment_percent,
            late_penalty_rate_percent
          })
        });
        const data = await res.json();
        if (data.status === 'success') {
          closeNewDebtModal();
          await loadDashboard();
          await loadDebts();
          await loadObligations();
        } else {
          msgEl.innerHTML = `<div class="alert alert-error">❌ ${data.message || 'Ошибка создания задолженности'}</div>`;
          msgEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
      } catch (e) {
        msgEl.innerHTML = `<div class="alert alert-error">❌ Ошибка сети: ${e.message}</div>`;
        msgEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      } finally {
        btn.disabled = false;
        btn.innerText = originalText;
      }
    }

    function openCardSettingsModal(cardId) {
      if (!allDebtsData || !allDebtsData.debts) return;
      const card = allDebtsData.debts.find(c => c.id === cardId);
      if (!card) return;
      const b = card.banking || {};

      document.getElementById('cardSettingsAccId').value = card.id;
      document.getElementById('cardSettingsTitle').innerText = card.name;
      document.getElementById('cardSettingsDebtBal').innerText = (card.debt_rub || '0.00') + ' ' + (card.currency || 'RUB');
      document.getElementById('cardSettingsLimit').value = parseFloat(card.credit_limit_rub) || 0;
      document.getElementById('cardSettingsDueDate').value = b.grace_due_date || '';
      document.getElementById('cardSettingsApr').value = b.interest_rate_percent ?? 24.8;
      document.getElementById('cardSettingsGraceDays').value = b.grace_period_days ?? 120;
      document.getElementById('cardSettingsMinPaymentPct').value = b.min_payment_percent ?? 3.0;
      document.getElementById('cardSettingsLatePenaltyPct').value = b.late_penalty_rate_percent ?? 36.0;
      document.getElementById('cardSettingsMsg').innerHTML = '';

      document.getElementById('modalCardSettings').classList.remove('hidden');
    }

    function closeCardSettingsModal() {
      document.getElementById('modalCardSettings').classList.add('hidden');
    }

    async function submitCardSettings() {
      const accId = document.getElementById('cardSettingsAccId').value;
      const limitRub = parseFloat(document.getElementById('cardSettingsLimit').value) || 0;
      const dueDate = document.getElementById('cardSettingsDueDate').value || null;
      const apr = Number(document.getElementById('cardSettingsApr').value);
      const graceDays = Number(document.getElementById('cardSettingsGraceDays').value);
      const minPct = Number(document.getElementById('cardSettingsMinPaymentPct').value);
      const penaltyPct = Number(document.getElementById('cardSettingsLatePenaltyPct').value);
      const msgEl = document.getElementById('cardSettingsMsg');

      if (![limitRub, apr, graceDays, minPct, penaltyPct].every(Number.isFinite) || [limitRub, apr, graceDays, minPct, penaltyPct].some(v => v < 0) || !Number.isInteger(graceDays)) {
        msgEl.textContent = 'Укажите неотрицательные конечные значения и целое число дней.'; return;
      }
      try {
        const res = await fetch('/api/debts/update-card-settings', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({
            account_id: accId,
            credit_limit_rub: limitRub,
            grace_due_date: dueDate,
            interest_rate_percent: apr,
            grace_period_days: graceDays,
            min_payment_percent: minPct,
            late_penalty_rate_percent: penaltyPct
          })
        });
        const data = await res.json();
        if (data.status === 'success') {
          closeCardSettingsModal();
          await loadDebts();
          await loadDashboard();
        } else {
          msgEl.innerHTML = `<div class="alert alert-error">${data.message || 'Ошибка сохранения'}</div>`;
        }
      } catch (e) {
        msgEl.innerHTML = `<div class="alert alert-error">Ошибка сети: ${e.message}</div>`;
      }
    }

    async function archiveDebt(accountId, encodedName) {
      const name = decodeURIComponent(encodedName || '');
      if (!confirm(`Отправить задолженность "${name}" в архив? Она перестанет отображаться в активных долгах.`)) {
        return;
      }
      try {
        const res = await fetch('/api/debts/archive', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ account_id: accountId })
        });
        const data = await res.json();
        if (data.status === 'success') {
          await loadDashboard();
          await loadDebts();
        } else {
          alert('Ошибка архивации: ' + (data.message || 'Неизвестная ошибка'));
        }
      } catch (e) {
        alert('Ошибка связи: ' + e.message);
      }
    }

    function populatePayDebtSelects(selectedLiabilityId) {
      const liabSel = document.getElementById('payDebtLiabilityAccount');
      const srcSel = document.getElementById('payDebtSourceAccount');
      if (!liabSel || !srcSel) return;

      // Populate Liability Accounts
      liabSel.innerHTML = '';
      if (allDebtsData && allDebtsData.debts) {
        allDebtsData.debts.forEach(d => {
          const opt = document.createElement('option');
          opt.value = d.id;
          opt.innerText = `${d.name} (долг: ${d.debt_rub} ${d.currency || 'RUB'})`;
          if (selectedLiabilityId && d.id === selectedLiabilityId) opt.selected = true;
          liabSel.appendChild(opt);
        });
      }

      // Populate Source Liquid Asset Accounts
      srcSel.innerHTML = '';
      if (overviewData && overviewData.accounts) {
        overviewData.accounts.filter(a => a.type === 'ASSET' && (a.subtype === 'CHECKING' || a.subtype === 'CASH' || a.subtype === 'SAVINGS' || a.subtype === 'DEBIT_CARD')).forEach(a => {
          const opt = document.createElement('option');
          opt.value = a.id;
          opt.innerText = `${a.name} (${a.scope || a.ownership_scope || ''}, ${a.balance_rub} ${a.currency || 'RUB'})`;
          srcSel.appendChild(opt);
        });
      }

      // Populate Debt Repayment Categories
      const catSel = document.getElementById('payDebtCategory');
      if (catSel) {
        catSel.innerHTML = '';
        if (categoryData && categoryData.flat) {
          const expenseCats = categoryData.flat.filter(c => c.type === 'EXPENSE');
          expenseCats.forEach(c => {
            const opt = document.createElement('option');
            opt.value = c.id;
            opt.innerText = `${c.icon || '💳'} ${c.name}`;
            catSel.appendChild(opt);
          });
        }
      }
    }

    function openPayDebtModal(targetLiabilityId, presetAmount, presetPercent) {
      if (!allDebtsData) {
        try {
          fetch('/api/debts', { headers: authHeaders() }).then(r => r.json()).then(d => {
            allDebtsData = d;
            populatePayDebtSelects(targetLiabilityId);
            onDebtLiabilityChanged();
            applyPresetPayDebt(presetAmount, presetPercent);
          });
        } catch (e) {}
      } else {
        populatePayDebtSelects(targetLiabilityId);
        onDebtLiabilityChanged();
        applyPresetPayDebt(presetAmount, presetPercent);
      }
      document.getElementById('payDebtMsg').innerHTML = '';
      document.getElementById('modalPayDebt').classList.remove('hidden');
    }

    function applyPresetPayDebt(presetAmount, presetPercent) {
      if (presetAmount !== undefined && presetAmount !== null && parseFloat(presetAmount) > 0) {
        document.getElementById('payDebtAmount').value = presetAmount;
        onPayDebtAmountRubChanged();
      } else if (presetPercent !== undefined && presetPercent !== null && parseFloat(presetPercent) > 0) {
        document.getElementById('payDebtAmountPercent').value = presetPercent;
        onPayDebtAmountPercentChanged();
      } else {
        document.getElementById('payDebtAmount').value = '';
        document.getElementById('payDebtAmountPercent').value = '';
        updatePayDebtForecast();
      }
    }

    function closePayDebtModal() {
      document.getElementById('modalPayDebt').classList.add('hidden');
    }

    function onDebtLiabilityChanged() {
      const liabId = document.getElementById('payDebtLiabilityAccount')?.value;
      if (!allDebtsData || !allDebtsData.debts) return;
      const d = allDebtsData.debts.find(x => x.id === liabId);
      if (!d) return;
      const curEl = document.getElementById('payDebtCurrentAmount');
      if (curEl) curEl.innerText = d.debt_rub + ' ' + (d.currency || 'RUB');
      const limEl = document.getElementById('payDebtLimitAmount');
      if (limEl) limEl.innerText = (d.credit_limit_rub || '0.00') + ' ' + (d.currency || 'RUB');

      // Auto-select category corresponding to debt subtype
      const catSel = document.getElementById('payDebtCategory');
      if (catSel && categoryData && categoryData.flat) {
        const subtypeCatMap = {
          'CREDIT_CARD': 'cat_debts_credit_card',
          'CONSUMER_LOAN': 'cat_debts_consumer',
          'MORTGAGE': 'cat_debts_mortgage',
          'AUTO_LOAN': 'cat_debts_auto',
          'INSTALLMENT_BNPL': 'cat_debts_bnpl',
          'PERSONAL_DEBT': 'cat_debts_personal',
          'LOAN': 'cat_debts_consumer'
        };
        const targetCatId = subtypeCatMap[d.subtype] || 'cat_debts';
        if (catSel.querySelector('option[value="' + targetCatId + '"]')) {
          catSel.value = targetCatId;
        }
      }
      onPayDebtAmountRubChanged();
    }

    function onPayDebtAmountRubChanged() {
      const liabId = document.getElementById('payDebtLiabilityAccount')?.value;
      const d = (allDebtsData && allDebtsData.debts) ? allDebtsData.debts.find(x => x.id === liabId) : null;
      const debtRub = d ? (parseFloat(d.debt_rub) || 0) : 0;
      const rubVal = parseFloat(document.getElementById('payDebtAmount')?.value) || 0;
      const pctEl = document.getElementById('payDebtAmountPercent');
      if (pctEl) {
        if (debtRub > 0 && rubVal > 0) {
          pctEl.value = ((rubVal / debtRub) * 100).toFixed(1);
        } else {
          pctEl.value = '';
        }
      }
      updatePayDebtForecast();
    }

    function onPayDebtAmountPercentChanged() {
      const liabId = document.getElementById('payDebtLiabilityAccount')?.value;
      const d = (allDebtsData && allDebtsData.debts) ? allDebtsData.debts.find(x => x.id === liabId) : null;
      const debtRub = d ? (parseFloat(d.debt_rub) || 0) : 0;
      const pctVal = parseFloat(document.getElementById('payDebtAmountPercent')?.value) || 0;
      const rubEl = document.getElementById('payDebtAmount');
      if (rubEl) {
        if (debtRub > 0 && pctVal > 0) {
          rubEl.value = ((debtRub * pctVal) / 100).toFixed(2);
        } else {
          rubEl.value = '';
        }
      }
      updatePayDebtForecast();
    }

    function setPayDebtPercent(pct) {
      const pctEl = document.getElementById('payDebtAmountPercent');
      if (pctEl) {
        pctEl.value = pct.toFixed(1);
        onPayDebtAmountPercentChanged();
      }
    }

    function setPayDebtFull() {
      setPayDebtPercent(100.0);
    }

    function addPayDebtAmount(delta) {
      const el = document.getElementById('payDebtAmount');
      const cur = parseFloat(el.value) || 0;
      el.value = (cur + delta).toFixed(2);
      onPayDebtAmountRubChanged();
    }

    let debtForecastSequence = 0;
    let debtForecastController = null;
    async function updatePayDebtForecast() {
      const sequence = ++debtForecastSequence;
      if (debtForecastController) debtForecastController.abort();
      const ids = ['payDebtForecastDays','payDebtForecastDate','payDebtForecastInterest','payDebtForecastSavings'];
      const fields = ids.map(id => document.getElementById(id));
      const statusEl = document.getElementById('payDebtForecastStatus');
      const liabId = document.getElementById('payDebtLiabilityAccount')?.value;
      const debt = allDebtsData?.debts?.find(item => item.id === liabId);
      const amount = document.getElementById('payDebtAmount')?.value;
      const numericAmount = parseMobileFloat(amount, NaN);
      const clear = () => fields.forEach(el => { if (el) el.innerText = '—'; });
      clear();
      if (!debt || !Number.isFinite(numericAmount) || numericAmount <= 0) {
        if (statusEl) statusEl.textContent = ''; return;
      }
      if (numericAmount > Number(debt.debt_rub)) {
        if (statusEl) statusEl.textContent = 'Сумма превышает текущий основной долг.'; return;
      }
      if (numericAmount === Number(debt.debt_rub)) {
        if (fields[0]) fields[0].innerText = 'Полное погашение основного долга';
        if (fields[1]) fields[1].innerText = 'Сегодня';
        if (statusEl) statusEl.textContent = 'Платёж закрывает учтённый основной долг. Проценты по выписке учитываются отдельно.';
        return;
      }
      debtForecastController = new AbortController();
      if (statusEl) statusEl.textContent = 'Расчёт сценария ежемесячных платежей…';
      try {
        const query = new URLSearchParams({liability_account_id: liabId, custom_payment_rub: amount});
        const response = await fetch('/api/debts/calculate-payoff?' + query, {headers: authHeaders(), signal: debtForecastController.signal});
        const data = await response.json();
        if (sequence !== debtForecastSequence) return;
        if (!response.ok || data.status === 'error') throw new Error(data.message || 'Расчёт недоступен');
        const result = data.custom_scenario;
        if (!result) throw new Error('Сценарий не получен');
        if (result.paid_off) {
          if (fields[0]) fields[0].innerText = result.months_to_payoff + ' мес. ≈ ' + result.days_to_payoff + ' дн.';
          if (fields[1]) fields[1].innerText = result.payoff_date || '—';
          if (fields[2]) fields[2].innerText = result.total_interest_rub + ' RUB';
          if (fields[3]) fields[3].innerText = result.interest_savings_rub == null ? 'Не определена' : result.interest_savings_rub + ' RUB';
          if (statusEl) statusEl.textContent = 'Оценка при таком платеже каждый месяц; APR/12, HALF_UP, без новых покупок и комиссий.';
        } else if (statusEl) {
          statusEl.textContent = result.status === 'NON_AMORTIZING'
            ? 'Платёж не уменьшает долг после расчётных процентов. Конечный срок не определён.'
            : 'За 360 расчётных месяцев долг не погашен. Остаток: ' + result.remaining_rub + ' RUB. Конечный срок не определён.';
        }
      } catch (error) {
        if (error.name === 'AbortError' || sequence !== debtForecastSequence) return;
        clear(); if (statusEl) statusEl.textContent = error.message;
      }
    }

    async function submitPayDebt() {
      const liability_account_id = document.getElementById('payDebtLiabilityAccount').value;
      const source_account_id = document.getElementById('payDebtSourceAccount').value;
      const amount_rub = document.getElementById('payDebtAmount').value;
      const parsedAmount = (typeof parseMobileFloat === 'function') ? parseMobileFloat(amount_rub, 0) : (parseFloat(amount_rub) || 0);
      const amount_percent = document.getElementById('payDebtAmountPercent')?.value || null;
      const description = document.getElementById('payDebtDesc').value.trim();
      const msgEl = document.getElementById('payDebtMsg');

      if (!liability_account_id) {
        msgEl.innerHTML = '<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Выберите задолженность для погашения</div>';
        return;
      }
      if (!source_account_id) {
        msgEl.innerHTML = '<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Выберите счет списания</div>';
        return;
      }
      if (!amount_rub || parsedAmount <= 0) {
        msgEl.innerHTML = '<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Укажите сумму погашения больше нуля</div>';
        return;
      }

      try {
        const category_id = document.getElementById('payDebtCategory')?.value || null;
        const res = await fetch('/api/debts/pay', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({
            liability_account_id,
            source_account_id,
            amount_rub,
            amount_percent: amount_percent ? parseFloat(amount_percent) : null,
            description,
            category_id
          })
        });
        const data = await res.json();
        if (data.status === 'success') {
          closePayDebtModal();
          await loadDashboard();
          await loadDebts();
          await loadTransactions(currentSelectedMonth);
        } else {
          msgEl.innerHTML = `<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Ошибка: ${data.message}</div>`;
        }
      } catch (e) {
        msgEl.innerHTML = `<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Ошибка связи: ${e.message}</div>`;
      }
    }

    async function loadEnvelopes() {

      const container = document.getElementById('envelopesListContainer');

      if (!container) return;

      try {

        const res = await fetch('/api/envelopes', { headers: authHeaders() });

        if (res.status === 401 || res.status === 423) return;

        const data = await res.json();

        const summary = data.summary || { envelopes: [], total_saved_rub: '0.00', count: 0, total_target_rub: '0.00' };

        allEnvelopesData = summary.envelopes || [];

        // Update KPI cards

        const savedEl = document.getElementById('envelopesTotalSaved');

        if (savedEl) savedEl.innerText = summary.total_saved_rub + ' ₽';

        const countEl = document.getElementById('envelopesCount');

        if (countEl) countEl.innerText = summary.count;

        const targetEl = document.getElementById('envelopesTotalTarget');

        if (targetEl) targetEl.innerText = summary.total_target_rub + ' ₽';

        if (allEnvelopesData.length === 0) {

          container.innerHTML = `

            <div style="grid-column: 1 / -1; text-align: center; padding: 32px 16px; background: rgba(255,255,255,0.02); border-radius: 12px; border: 1px dashed var(--border);">

              <div style="font-size: 36px; margin-bottom: 8px;">✉️</div>

              <div style="font-size: 16px; font-weight: 600; color: var(--text); margin-bottom: 4px;">У вас пока нет конвертов-копилок</div>

              <div style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">

                Метод конвертов помогает откладывать на отпуск, крупные покупки или подарки, защищая сбережения от импульсивных трат.

              </div>

              <button class="btn btn-success" onclick="openNewEnvelopeModal()">➕ Создать первый конверт</button>

            </div>

          `;

          return;

        }

        container.innerHTML = allEnvelopesData.map(e => {

          const hasTarget = e.target_amount_cents > 0;

          const isDone = hasTarget && e.current_amount_cents >= e.target_amount_cents;

          const barColor = e.color || '#3b82f6';

          let progressSection = '';

          if (hasTarget) {

            progressSection = `

              <div style="margin: 10px 0 6px 0;">

                <div style="display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px; color: var(--text-muted);">

                  <span>Цель: ${e.target_amount_rub} ₽</span>

                  <span>${e.progress_percent}%</span>

                </div>

                <div class="progress-bar-bg" style="height: 6px; border-radius: 3px;">

                  <div class="progress-bar-fill" style="width: ${e.progress_percent}%; background: ${barColor}; height: 100%; border-radius: 3px;"></div>

                </div>

                <div style="font-size: 11px; color: ${isDone ? '#34d399' : 'var(--text-muted)'}; margin-top: 4px;">

                  ${isDone ? '🎉 Цель полностью собрана!' : `Осталось: <strong style="color:#f87171;">${e.remaining_rub} ₽</strong>`}

                </div>

              </div>

            `;

          }

          const accInfo = e.linked_account_name ? `

            <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">🏦 Счет хранения: ${escapeHtml(e.linked_account_name)}</div>

          ` : '';

          return `

            <div class="card" style="margin-bottom: 0; border-top: 4px solid ${barColor}; background: linear-gradient(180deg, rgba(255,255,255,0.03) 0%, rgba(15,23,42,0.6) 100%);">

              <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">

                <div style="display: flex; align-items: center; gap: 8px;">

                  <span style="font-size: 26px;">${e.icon || '✉️'}</span>

                  <div>

                    <strong style="font-size: 16px; color: var(--text);">${escapeHtml(e.name)}</strong>

                    <div style="font-size: 11px; color: var(--text-muted);">${e.category_name || 'Без категории'}</div>

                  </div>

                </div>

                <div style="display: flex; gap: 4px;">

                  <button class="btn btn-secondary" style="padding: 4px 7px; font-size: 11px;" onclick="openEditEnvelopeModal('${e.id}')" title="Редактировать">✏️</button>

                  <button class="btn btn-secondary" style="padding: 4px 7px; font-size: 11px;" onclick="archiveEnvelope('${e.id}')" title="Архивировать">📦</button>

                </div>

              </div>

              <div style="margin: 8px 0;">

                <div style="font-size: 11px; color: var(--text-muted);">Баланс копилки:</div>

                <div style="font-size: 22px; font-weight: 700; color: #34d399;">${e.current_amount_rub} ₽</div>

              </div>

              ${progressSection}

              ${accInfo}

              ${e.note ? `<div style="font-size: 11px; color: var(--text-muted); font-style: italic; margin-top: 6px;">💬 ${escapeHtml(e.note)}</div>` : ''}

              <div style="display: flex; gap: 6px; margin-top: 12px; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 8px;">

                <button class="btn btn-success" style="flex: 1; padding: 6px 8px; font-size: 12px;" onclick="openEnvelopeDepositModal('${e.id}')">📥 Положить</button>

                <button class="btn btn-secondary" style="flex: 1; padding: 6px 8px; font-size: 12px;" onclick="openEnvelopeWithdrawModal('${e.id}')">📤 Взять</button>

              </div>

            </div>

          `;

        }).join('');

      } catch (e) {

        console.error('loadEnvelopes error:', e);

      }

    }

    async function loadEnvelopesWidget() {

      const container = document.getElementById('dashEnvelopesContainer');

      const badge = document.getElementById('dashEnvelopesTotalBadge');

      if (!container) return;

      try {

        const res = await fetch('/api/envelopes', { headers: authHeaders() });

        if (res.status === 401 || res.status === 423) return;

        const data = await res.json();

        const summary = data.summary || { envelopes: [], total_saved_rub: '0.00' };

        allEnvelopesData = summary.envelopes || [];

        if (badge) badge.innerText = `Всего: ${summary.total_saved_rub} ₽`;

        if (allEnvelopesData.length === 0) {

          container.innerHTML = `

            <div style="grid-column: 1 / -1; display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; background: rgba(255,255,255,0.02); border-radius: 8px;">

              <span style="color: var(--text-muted); font-size: 13px;">Конвертов пока нет. Начните откладывать на отпуск или мечту!</span>

              <button class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="openNewEnvelopeModal()">+ Создать конверт</button>

            </div>

          `;

          return;

        }

        container.innerHTML = allEnvelopesData.slice(0, 4).map(e => `

          <div style="padding: 10px 12px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06); border-left: 3px solid ${e.color || '#3b82f6'}; border-radius: 8px;">

            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">

              <span style="font-size: 13px; font-weight: 600; color: var(--text);">${e.icon || '✉️'} ${escapeHtml(e.name)}</span>

              <span style="font-size: 13px; font-weight: 700; color: #34d399;">${e.current_amount_rub} ₽</span>

            </div>

            ${e.target_amount_cents > 0 ? `

              <div class="progress-bar-bg" style="height: 4px; margin-bottom: 6px;">

                <div class="progress-bar-fill" style="width: ${e.progress_percent}%; background: ${e.color || '#3b82f6'}; height: 100%;"></div>

              </div>

            ` : ''}

            <div style="display: flex; gap: 4px; margin-top: 6px;">

              <button class="btn btn-secondary" style="flex: 1; padding: 2px 6px; font-size: 11px;" onclick="openEnvelopeDepositModal('${e.id}')">+ Положить</button>

              <button class="btn btn-secondary" style="flex: 1; padding: 2px 6px; font-size: 11px;" onclick="openEnvelopeWithdrawModal('${e.id}')">- Взять</button>

              <button class="btn btn-secondary" style="padding: 2px 7px; font-size: 11px;" onclick="openEditEnvelopeModal('${e.id}')" title="Редактировать конверт">✏️</button>

            </div>

          </div>

        `).join('');

      } catch (e) {

        console.error('loadEnvelopesWidget error:', e);

      }

    }

    function populateEnvelopeAccountSelect(selectedId) {

      const sel = document.getElementById('envelopeInputAccount');

      if (!sel) return;

      sel.innerHTML = '<option value="">(Не привязывать к конкретному счёту)</option>';

      if (overviewData && overviewData.accounts) {

        overviewData.accounts.filter(a => a.type === 'ASSET').forEach(a => {

          const opt = document.createElement('option');

          opt.value = a.id;

          opt.innerText = `${a.name} (${a.subtype}, ${a.balance_rub} ₽)`;

          if (selectedId && a.id === selectedId) opt.selected = true;

          sel.appendChild(opt);

        });

      }

    }

    function openNewEnvelopeModal() {
      document.getElementById('envelopeEditId').value = '';
      document.getElementById('envelopeModalTitle').innerHTML = '<span>✉️</span> <span>Новый конверт-копилка</span>';
      document.getElementById('envelopeInputName').value = '';
      document.getElementById('envelopeInputTarget').value = '';
      document.getElementById('envelopeInputIcon').value = '✉️';
      document.getElementById('envelopeInputColor').value = '#3b82f6';
      document.getElementById('envelopeInputInitial').value = '0';
      const lbl = document.getElementById('envelopeInitialLabel');
      if (lbl) lbl.innerText = 'Начальный баланс (₽):';
      document.getElementById('envelopeInputNote').value = '';
      document.getElementById('envelopeModalMsg').innerHTML = '';
      populateEnvelopeAccountSelect(null);
      document.getElementById('modalEnvelope').classList.remove('hidden');
    }

    async function openEditEnvelopeModal(envId) {
      if (!allEnvelopesData || allEnvelopesData.length === 0) {
        try {
          const res = await fetch('/api/envelopes', { headers: authHeaders() });
          const d = await res.json();
          allEnvelopesData = (d.summary && d.summary.envelopes) ? d.summary.envelopes : (d.envelopes || []);
        } catch (e) {}
      }
      const env = (allEnvelopesData || []).find(e => e.id === envId);
      if (!env) {
        alert('Конверт-копилка не найден');
        return;
      }
      document.getElementById('envelopeEditId').value = env.id;
      document.getElementById('envelopeModalTitle').innerHTML = '<span>✏️</span> <span>Редактировать конверт-копилку</span>';
      document.getElementById('envelopeInputName').value = env.name || '';
      document.getElementById('envelopeInputTarget').value = (env.target_amount_cents && env.target_amount_cents > 0) ? (env.target_amount_rub || '') : '';
      document.getElementById('envelopeInputIcon').value = env.icon || '✉️';
      document.getElementById('envelopeInputColor').value = env.color || '#3b82f6';
      document.getElementById('envelopeInputInitial').value = env.current_amount_rub || '0';
      const lbl = document.getElementById('envelopeInitialLabel');
      if (lbl) lbl.innerText = 'Текущий баланс накоплений (₽):';
      document.getElementById('envelopeInputNote').value = env.note || '';
      document.getElementById('envelopeModalMsg').innerHTML = '';
      populateEnvelopeAccountSelect(env.linked_account_id);
      document.getElementById('modalEnvelope').classList.remove('hidden');
    }

    function closeEnvelopeModal() {

      document.getElementById('modalEnvelope').classList.add('hidden');

    }

    async function submitSaveEnvelope() {

      const envId = document.getElementById('envelopeEditId').value;

      const name = document.getElementById('envelopeInputName').value.trim();

      const target_amount_rub = document.getElementById('envelopeInputTarget').value || '0';

      const icon = document.getElementById('envelopeInputIcon').value;

      const color = document.getElementById('envelopeInputColor').value;

      const initial_amount_rub = document.getElementById('envelopeInputInitial').value || '0';

      const linked_account_id = document.getElementById('envelopeInputAccount').value || null;

      const note = document.getElementById('envelopeInputNote').value.trim() || null;

      const msgEl = document.getElementById('envelopeModalMsg');

      if (!name) {

        msgEl.innerHTML = '<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Укажите название конверта-копилки</div>';

        return;

      }

      const endpoint = envId ? '/api/envelopes/update' : '/api/envelopes/create';

      const amount_rub = document.getElementById('envelopeInputInitial').value || '0';

      const payload = envId

        ? { envelope_id: envId, name, target_amount_rub, icon, color, current_amount_rub: amount_rub, linked_account_id, note }

        : { name, target_amount_rub, icon, color, initial_amount_rub: amount_rub, linked_account_id, note };

      try {

        const res = await fetch(endpoint, {

          method: 'POST',

          headers: authHeaders(),

          body: JSON.stringify(payload)

        });

        const data = await res.json();

        if (data.status === 'success') {

          closeEnvelopeModal();

          await loadEnvelopes();

          await loadEnvelopesWidget();

          LocalDatabaseVault.syncAfterMutation();

        } else {

          msgEl.innerHTML = `<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Ошибка: ${data.message}</div>`;

        }

      } catch (e) {

        msgEl.innerHTML = `<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Ошибка сети: ${e.message}</div>`;

      }

    }

    async function archiveEnvelope(envId) {

      if (!confirm('Архивировать этот конверт-копилку?')) return;

      try {

        const res = await fetch('/api/envelopes/archive', {

          method: 'POST',

          headers: authHeaders(),

          body: JSON.stringify({ envelope_id: envId })

        });

        const data = await res.json();

        if (data.status === 'success') {

          await loadEnvelopes();

          await loadEnvelopesWidget();

          LocalDatabaseVault.syncAfterMutation();

        } else {

          alert('Ошибка: ' + data.message);

        }

      } catch (e) {

        alert('Ошибка связи: ' + e.message);

      }

    }

    // --- Envelope Deposit Modal ---

    function openEnvelopeDepositModal(envId) {

      activeEnvDeposit = allEnvelopesData.find(e => e.id === envId);

      if (!activeEnvDeposit) return;

      document.getElementById('envDepositId').value = activeEnvDeposit.id;

      document.getElementById('envDepositTitle').innerText = `Положить в: ${activeEnvDeposit.icon || '✉️'} ${activeEnvDeposit.name}`;

      document.getElementById('envDepositCurrentBal').innerText = `Текущий баланс конверта: ${activeEnvDeposit.current_amount_rub} ₽`;

      document.getElementById('envDepositAmount').value = '';

      document.getElementById('envDepositNote').value = `Пополнение конверта "${activeEnvDeposit.name}"`;

      document.getElementById('envDepositMsg').innerHTML = '';

      // Populate source accounts select with liquid asset accounts

      const sel = document.getElementById('envDepositSourceAccount');

      sel.innerHTML = '<option value="">(Без привязки к конкретной карте)</option>';

      if (overviewData && overviewData.accounts) {

        overviewData.accounts.filter(a => a.type === 'ASSET' && (a.subtype === 'CHECKING' || a.subtype === 'CASH' || a.subtype === 'DEBIT_CARD' || a.subtype === 'SAVINGS')).forEach(a => {

          const opt = document.createElement('option');

          opt.value = a.id;

          opt.innerText = `${a.name} (${a.balance_rub} ₽)`;

          sel.appendChild(opt);

        });

      }

      document.getElementById('modalEnvelopeDeposit').classList.remove('hidden');

    }

    function closeEnvelopeDepositModal() {

      document.getElementById('modalEnvelopeDeposit').classList.add('hidden');

    }

    function addEnvDepositAmount(amt) {

      const el = document.getElementById('envDepositAmount');

      const cur = parseFloat(el.value) || 0;

      el.value = (cur + amt).toFixed(2);

    }

    async function submitEnvelopeDeposit() {

      const envelope_id = document.getElementById('envDepositId').value;

      const amount_rub = document.getElementById('envDepositAmount').value;

      const source_account_id = document.getElementById('envDepositSourceAccount').value || null;

      const note = document.getElementById('envDepositNote').value.trim() || null;

      const msgEl = document.getElementById('envDepositMsg');

      if (!amount_rub || parseFloat(amount_rub) <= 0) {

        msgEl.innerHTML = '<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Укажите сумму больше нуля</div>';

        return;

      }

      try {

        const res = await fetch('/api/envelopes/deposit', {

          method: 'POST',

          headers: authHeaders(),

          body: JSON.stringify({ envelope_id, amount_rub, source_account_id, note })

        });

        const data = await res.json();

        if (data.status === 'success') {

          closeEnvelopeDepositModal();

          LocalDatabaseVault.syncAfterMutation();

          await loadEnvelopes();

          await loadEnvelopesWidget();

          await loadDashboard();

        } else {

          msgEl.innerHTML = `<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Ошибка: ${data.message}</div>`;

        }

      } catch (e) {

        msgEl.innerHTML = `<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Ошибка связи: ${e.message}</div>`;

      }

    }

    // --- Envelope Withdraw Modal ---

    function openEnvelopeWithdrawModal(envId) {

      activeEnvWithdraw = allEnvelopesData.find(e => e.id === envId);

      if (!activeEnvWithdraw) return;

      document.getElementById('envWithdrawId').value = activeEnvWithdraw.id;

      document.getElementById('envWithdrawTitle').innerText = `Взять из: ${activeEnvWithdraw.icon || '✉️'} ${activeEnvWithdraw.name}`;

      document.getElementById('envWithdrawCurrentBal').innerText = `Доступно в конверте: ${activeEnvWithdraw.current_amount_rub} ₽`;

      document.getElementById('envWithdrawAmount').value = '';

      document.getElementById('envWithdrawNote').value = `Изъятие из конверта "${activeEnvWithdraw.name}"`;

      document.getElementById('envWithdrawMsg').innerHTML = '';

      // Populate destination accounts select

      const sel = document.getElementById('envWithdrawDestAccount');

      sel.innerHTML = '<option value="">(Без возврата на конкретную карту)</option>';

      if (overviewData && overviewData.accounts) {

        overviewData.accounts.filter(a => a.type === 'ASSET').forEach(a => {

          const opt = document.createElement('option');

          opt.value = a.id;

          opt.innerText = `${a.name} (${a.balance_rub} ₽)`;

          sel.appendChild(opt);

        });

      }

      document.getElementById('modalEnvelopeWithdraw').classList.remove('hidden');

    }

    function closeEnvelopeWithdrawModal() {

      document.getElementById('modalEnvelopeWithdraw').classList.add('hidden');

    }

    function setEnvWithdrawAll() {

      if (!activeEnvWithdraw) return;

      document.getElementById('envWithdrawAmount').value = activeEnvWithdraw.current_amount_rub;

    }

    function addEnvWithdrawAmount(amt) {

      const el = document.getElementById('envWithdrawAmount');

      const cur = parseFloat(el.value) || 0;

      el.value = (cur + amt).toFixed(2);

    }

    async function submitEnvelopeWithdraw() {

      const envelope_id = document.getElementById('envWithdrawId').value;

      const amount_rub = document.getElementById('envWithdrawAmount').value;

      const destination_account_id = document.getElementById('envWithdrawDestAccount').value || null;

      const note = document.getElementById('envWithdrawNote').value.trim() || null;

      const msgEl = document.getElementById('envWithdrawMsg');

      if (!amount_rub || parseFloat(amount_rub) <= 0) {

        msgEl.innerHTML = '<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Укажите сумму больше нуля</div>';

        return;

      }

      try {

        const res = await fetch('/api/envelopes/withdraw', {

          method: 'POST',

          headers: authHeaders(),

          body: JSON.stringify({ envelope_id, amount_rub, destination_account_id, note })

        });

        const data = await res.json();

        if (data.status === 'success') {

          closeEnvelopeWithdrawModal();

          LocalDatabaseVault.syncAfterMutation();

          await loadEnvelopes();

          await loadEnvelopesWidget();

          await loadDashboard();

        } else {

          msgEl.innerHTML = `<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Ошибка: ${data.message}</div>`;

        }

      } catch (e) {

        msgEl.innerHTML = `<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Ошибка связи: ${e.message}</div>`;

      }

    }

    // --- Envelope Transfer Modal ---

    function openEnvelopeTransferModal(fromEnvId) {

      const fromSel = document.getElementById('envTransferFromSelect');

      const toSel = document.getElementById('envTransferToSelect');

      if (!fromSel || !toSel) return;

      fromSel.innerHTML = '';

      toSel.innerHTML = '';

      allEnvelopesData.forEach(e => {

        const opt1 = document.createElement('option');

        opt1.value = e.id;

        opt1.innerText = `${e.icon || '✉️'} ${e.name} (${e.current_amount_rub} ₽)`;

        if (fromEnvId && e.id === fromEnvId) opt1.selected = true;

        fromSel.appendChild(opt1);

        const opt2 = document.createElement('option');

        opt2.value = e.id;

        opt2.innerText = `${e.icon || '✉️'} ${e.name} (${e.current_amount_rub} ₽)`;

        toSel.appendChild(opt2);

      });

      if (toSel.options.length > 1) {

        toSel.selectedIndex = 1;

      }

      onEnvTransferFromChanged();

      document.getElementById('envTransferAmount').value = '';

      document.getElementById('envTransferNote').value = 'Перераспределение накоплений';

      document.getElementById('envTransferMsg').innerHTML = '';

      document.getElementById('modalEnvelopeTransfer').classList.remove('hidden');

    }

    function closeEnvelopeTransferModal() {

      document.getElementById('modalEnvelopeTransfer').classList.add('hidden');

    }

    function onEnvTransferFromChanged() {

      const fromId = document.getElementById('envTransferFromSelect')?.value;

      const infoEl = document.getElementById('envTransferAvailInfo');

      if (!infoEl) return;

      const env = allEnvelopesData.find(e => e.id === fromId);

      if (env) {

        infoEl.innerHTML = `Доступно для перемещения: <strong style="color:#34d399;">${env.current_amount_rub} ₽</strong>`;

      }

    }

    async function submitEnvelopeTransfer() {

      const from_envelope_id = document.getElementById('envTransferFromSelect').value;

      const to_envelope_id = document.getElementById('envTransferToSelect').value;

      const amount_rub = document.getElementById('envTransferAmount').value;

      const note = document.getElementById('envTransferNote').value.trim() || null;

      const msgEl = document.getElementById('envTransferMsg');

      if (from_envelope_id === to_envelope_id) {

        msgEl.innerHTML = '<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Выберите разные конверты для перевода</div>';

        return;

      }

      if (!amount_rub || parseFloat(amount_rub) <= 0) {

        msgEl.innerHTML = '<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Укажите сумму больше нуля</div>';

        return;

      }

      try {

        const res = await fetch('/api/envelopes/transfer', {

          method: 'POST',

          headers: authHeaders(),

          body: JSON.stringify({ from_envelope_id, to_envelope_id, amount_rub, note })

        });

        const data = await res.json();

        if (data.status === 'success') {

          closeEnvelopeTransferModal();

          LocalDatabaseVault.syncAfterMutation();

          await loadEnvelopes();

          await loadEnvelopesWidget();

          LocalDatabaseVault.syncAfterMutation();

        } else {

          msgEl.innerHTML = `<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Ошибка: ${data.message}</div>`;

        }

      } catch (e) {

        msgEl.innerHTML = `<div class="alert alert-danger" style="padding:6px 10px; font-size:12px;">Ошибка связи: ${e.message}</div>`;

      }

    }

    // =========================================================================
    // Client-Side Local Database Vault (IndexedDB + localStorage Fallback)
    // Ensures 100% of financial data persists on the user's phone/browser
    // and seamlessly survives Vercel serverless cold starts.
    // =========================================================================
    const LocalDatabaseVault = {
      dbName: 'FamilyFinancesOS_DB',
      storeName: 'vault',
      key: 'primary_db',
      _dbPromise: null,

      async getDB() {
        if (this._dbPromise) return this._dbPromise;
        if (!window.indexedDB) return null;
        this._dbPromise = new Promise((resolve) => {
          try {
            const req = indexedDB.open(this.dbName, 1);
            req.onupgradeneeded = (e) => {
              const db = e.target.result;
              if (!db.objectStoreNames.contains(this.storeName)) {
                db.createObjectStore(this.storeName);
              }
            };
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => resolve(null);
          } catch (e) {
            resolve(null);
          }
        });
        return this._dbPromise;
      },

      async saveSnapshot(blob_base64, sha256, size_bytes) {
        if (!blob_base64) return false;
        const record = {
          blob_base64,
          sha256,
          size_bytes: size_bytes || Math.round(blob_base64.length * 0.75),
          updated_at: new Date().toISOString(),
          timestamp: Date.now()
        };
        let saved = false;
        try {
          const db = await this.getDB();
          if (db) {
            await new Promise((resolve, reject) => {
              const tx = db.transaction(this.storeName, 'readwrite');
              const store = tx.objectStore(this.storeName);
              const putReq = store.put(record, this.key);
              putReq.onsuccess = () => resolve(true);
              putReq.onerror = () => reject(putReq.error);
            });
            saved = true;
          }
        } catch (e) {
          console.warn('[Vault] IndexedDB save notice:', e);
        }
        try {
          localStorage.setItem('ffos_vault_meta', JSON.stringify({
            sha256: record.sha256,
            size_bytes: record.size_bytes,
            updated_at: record.updated_at,
            timestamp: record.timestamp
          }));
          if (blob_base64.length < 4000000) {
            localStorage.setItem('ffos_vault_blob', blob_base64);
          }
        } catch (e) {
          console.warn('[Vault] localStorage cache notice:', e);
        }
        this.updateBadge();
        return saved;
      },

      async getSnapshot() {
        try {
          const db = await this.getDB();
          if (db) {
            const rec = await new Promise((resolve, reject) => {
              const tx = db.transaction(this.storeName, 'readonly');
              const store = tx.objectStore(this.storeName);
              const getReq = store.get(this.key);
              getReq.onsuccess = () => resolve(getReq.result || null);
              getReq.onerror = () => reject(getReq.error);
            });
            if (rec && rec.blob_base64) return rec;
          }
        } catch (e) {
          console.warn('[Vault] IndexedDB get notice:', e);
        }
        try {
          const blob = localStorage.getItem('ffos_vault_blob');
          const metaStr = localStorage.getItem('ffos_vault_meta');
          if (blob) {
            const meta = metaStr ? JSON.parse(metaStr) : {};
            return {
              blob_base64: blob,
              sha256: meta.sha256 || '',
              size_bytes: meta.size_bytes || Math.round(blob.length * 0.75),
              updated_at: meta.updated_at || new Date().toISOString(),
              timestamp: meta.timestamp || Date.now()
            };
          }
        } catch (e) {
          console.warn('[Vault] localStorage fallback notice:', e);
        }
        return null;
      },

      async hasLocalSnapshot() {
        const snap = await this.getSnapshot();
        return !!(snap && snap.blob_base64);
      },

      async autoRestoreIfEmpty() {
        try {
          const snap = await this.getSnapshot();
          if (!snap || !snap.blob_base64) return false;

          const badge = document.getElementById('localVaultBadge');
          if (badge) badge.innerText = '💾 Восстановление данных...';

          const res = await fetch('/api/database/restore-blob', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              blob_base64: snap.blob_base64,
              sha256: snap.sha256
            })
          });
          const data = await res.json();
          if (res.ok && data.status === 'ok') {
            if (data.token) {
              sessionToken = data.token;
              sessionStorage.setItem('ffos_session_token', data.token);
              localStorage.setItem('ffos_session_token', data.token);
            }
            this.updateBadge();
            return true;
          }
        } catch (e) {
          console.warn('[Vault] Auto-restore error:', e);
        }
        return false;
      },

      _debounceTimer: null,
      syncAfterMutation() {
        if (this._debounceTimer) clearTimeout(this._debounceTimer);
        this._debounceTimer = setTimeout(async () => {
          try {
            const token = sessionToken || sessionStorage.getItem('ffos_session_token') || localStorage.getItem('ffos_session_token');
            if (!token) return;
            const res = await fetch('/api/database/export-blob', {
              headers: { 'Authorization': 'Bearer ' + token }
            });
            if (!res.ok) return;
            const data = await res.json();
            if (data.status === 'ok' && data.blob_base64) {
              await this.saveSnapshot(data.blob_base64, data.sha256, data.size_bytes);
            }
          } catch (e) {
            console.warn('[Vault] Auto-export error:', e);
          }
        }, 500);
      },

      async updateBadge() {
        const badge = document.getElementById('localVaultBadge');
        const timeEl = document.getElementById('vaultTime');
        if (!badge) return;
        const snap = await this.getSnapshot();
        if (snap && snap.updated_at) {
          const d = new Date(snap.updated_at);
          const timeStr = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
          if (timeEl) timeEl.innerText = timeStr;
          else badge.innerText = `💾 На телефоне (${timeStr})`;
          badge.style.display = 'inline-flex';
          badge.title = `Локальная база сохранена: ${d.toLocaleString()} (${Math.round((snap.size_bytes || 0)/1024)} КБ)`;
        } else {
          if (timeEl) timeEl.innerText = 'сохранено';
          badge.style.display = 'inline-flex';
        }
      },

      async downloadBackupFile() {
        try {
          const token = sessionToken || sessionStorage.getItem('ffos_session_token') || localStorage.getItem('ffos_session_token');
          const res = await fetch('/api/database/export-file', {
            headers: token ? { 'Authorization': 'Bearer ' + token } : {}
          });
          if (res.ok) {
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `family_finances_backup_${new Date().toISOString().slice(0, 10)}.db`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            return;
          }
        } catch (e) {
          console.warn('[Vault] File download fallback to blob:', e);
        }
        const snap = await this.getSnapshot();
        if (snap && snap.blob_base64) {
          const byteChars = atob(snap.blob_base64);
          const byteNums = new Array(byteChars.length);
          for (let i = 0; i < byteChars.length; i++) {
            byteNums[i] = byteChars.charCodeAt(i);
          }
          const byteArray = new Uint8Array(byteNums);
          const blob = new Blob([byteArray], { type: 'application/x-sqlite3' });
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `family_finances_backup_${new Date().toISOString().slice(0, 10)}.db`;
          document.body.appendChild(a);
          a.click();
          window.URL.revokeObjectURL(url);
          document.body.removeChild(a);
        }
      },

      async restoreFromFile(file) {
        if (!file) return;
        const reader = new FileReader();
        reader.onload = async (e) => {
          try {
            const arrayBuffer = e.target.result;
            const bytes = new Uint8Array(arrayBuffer);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
              binary += String.fromCharCode(bytes[i]);
            }
            const b64 = btoa(binary);

            const token = sessionToken || sessionStorage.getItem('ffos_session_token') || localStorage.getItem('ffos_session_token');
            const headers = { 'Content-Type': 'application/json' };
            if (token) headers['Authorization'] = 'Bearer ' + token;

            const res = await fetch('/api/database/restore-blob', {
              method: 'POST',
              headers,
              body: JSON.stringify({ blob_base64: b64 })
            });
            const data = await res.json();
            if (res.ok && data.status === 'ok') {
              await this.saveSnapshot(b64, null, bytes.byteLength);
              if (data.token) {
                sessionToken = data.token;
                sessionStorage.setItem('ffos_session_token', data.token);
                localStorage.setItem('ffos_session_token', data.token);
              }
              alert('✅ База данных успешно восстановлена из файла!');
              closeVaultModal();
              await loadStatus();
              await loadDashboard();
            } else {
              alert('❌ Ошибка восстановления: ' + (data.error || data.message || 'Неизвестная ошибка'));
            }
          } catch (err) {
            alert('❌ Ошибка чтения файла: ' + err.message);
          }
        };
        reader.readAsArrayBuffer(file);
      }
    };

    function openVaultModal() {
      const modal = document.getElementById('vaultModal');
      if (!modal) return;
      modal.classList.remove('hidden');
      updateVaultModalInfo();
    }

    function closeVaultModal() {
      const modal = document.getElementById('vaultModal');
      if (modal) modal.classList.add('hidden');
    }

    function syncVaultNow() {
      LocalDatabaseVault.syncAfterMutation();
      updateVaultModalInfo();
    }

    function downloadVaultBackup() {
      LocalDatabaseVault.downloadBackupFile();
    }

    function restoreVaultFromFile(file) {
      LocalDatabaseVault.restoreFromFile(file);
    }

    async function updateVaultModalInfo() {
      const infoEl = document.getElementById('vaultStatusInfo');
      if (!infoEl) return;
      const snap = await LocalDatabaseVault.getSnapshot();
      if (snap && snap.updated_at) {
        const d = new Date(snap.updated_at);
        infoEl.innerHTML = `
          <div style="background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.3); border-radius: 8px; padding: 10px; margin-bottom: 12px; font-size: 13px;">
            <div style="font-weight: 600; color: #34d399; margin-bottom: 4px;">✅ Данные в безопасности на вашем телефоне</div>
            <div>Сохранено: <strong>${d.toLocaleString()}</strong></div>
            <div>Размер базы: <strong>${Math.round((snap.size_bytes || 0) / 1024)} КБ</strong></div>
            <div style="color: var(--text-muted); font-size: 11px; margin-top: 4px;">Все счета, долги и транзакции привязаны к этому браузеру и не зависят от перезагрузок Vercel.</div>
          </div>
        `;
      } else {
        infoEl.innerHTML = `
          <div style="background: rgba(99,102,241,0.1); border: 1px solid rgba(99,102,241,0.3); border-radius: 8px; padding: 10px; margin-bottom: 12px; font-size: 13px;">
            <div style="font-weight: 600; color: #a5b4fc; margin-bottom: 4px;">ℹ️ Локальное хранилище готово</div>
            <div style="color: var(--text-muted); font-size: 11px;">При первом добавлении данных резервная копия автоматически сохранится в память телефона.</div>
          </div>
        `;
      }
    }

    if (document.readyState === 'loading') {

      document.addEventListener('DOMContentLoaded', loadStatus);

    } else {

      loadStatus();

    }


    window.addEventListener('error', (event) => {
      console.error('[Global Window Error]', event.error || event.message);
      const anyScreenVisible = ['errorScreen', 'lockScreen', 'setupScreen', 'loginScreen', 'mainDashboard'].some(id => {
        const el = document.getElementById(id);
        return el && !el.classList.contains('hidden');
      });
      if (!anyScreenVisible) {
        showErrorScreen('Сбой отображения', 'Произошла непредвиденная ошибка в браузере: ' + (event.message || 'Неизвестная ошибка'));
      }
    });

    window.addEventListener('unhandledrejection', (event) => {
      console.error('[Unhandled Rejection]', event.reason);
      const anyScreenVisible = ['errorScreen', 'lockScreen', 'setupScreen', 'loginScreen', 'mainDashboard'].some(id => {
        const el = document.getElementById(id);
        return el && !el.classList.contains('hidden');
      });
      if (!anyScreenVisible) {
        showErrorScreen('Сбой загрузки данных', 'Не удалось завершить операцию: ' + (event.reason?.message || event.reason || 'Ошибка запроса'));
      }
    });

    
    // Init privacy mask preference
    if (localStorage.getItem('ffos_privacy_masked') === 'true') {
      document.body.classList.add('privacy-masked');
      const pIcon = document.getElementById('privacyIcon');
      if (pIcon) pIcon.innerText = '🙈';
    }

    // Bottom Sheet Swipe / Drag dismiss interaction for mobile devices
    function initBottomSheetTouch() {
      const modal = document.getElementById('modalNewTx');
      if (!modal) return;
      const card = modal.querySelector('.bottom-sheet-card');
      const handle = modal.querySelector('.bottom-sheet-handle-bar');
      if (!card || !handle) return;

      let startY = 0;
      let currentY = 0;
      let isDragging = false;

      handle.addEventListener('touchstart', (e) => {
        if (window.innerWidth >= 768) return;
        startY = e.touches[0].clientY;
        currentY = startY;
        isDragging = true;
        card.style.transition = 'none';
      }, { passive: true });

      window.addEventListener('touchmove', (e) => {
        if (!isDragging || window.innerWidth >= 768) return;
        currentY = e.touches[0].clientY;
        const delta = currentY - startY;
        if (delta > 0) {
          card.style.transform = `translateY(${delta}px)`;
        }
      }, { passive: true });

      window.addEventListener('touchend', () => {
        if (!isDragging || window.innerWidth >= 768) return;
        isDragging = false;
        card.style.transition = 'transform 0.25s cubic-bezier(0.16, 1, 0.3, 1)';
        const delta = currentY - startY;
        if (delta > 85) {
          card.style.transform = 'translateY(100%)';
          setTimeout(() => {
            closeNewTxModal();
            card.style.transform = '';
          }, 200);
        } else {
          card.style.transform = 'translateY(0)';
        }
      }, { passive: true });
    }

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', initBottomSheetTouch);
    } else {
      initBottomSheetTouch();
    }

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeNewTxModal();
      }
    });

    // Expose core transaction and category methods on window
    window.openNewTxModal = openNewTxModal;
    window.closeNewTxModal = closeNewTxModal;
    window.setModalTxType = setModalTxType;
    window.addTxInputAmount = addTxInputAmount;
    window.resetModalTxAmount = resetModalTxAmount;
    window.syncTxAmount = syncTxAmount;
    window.setModalTxDateToday = setModalTxDateToday;
    window.openTransferModal = openTransferModal;
    window.submitModalTransaction = submitModalTransaction;
    window.submitTransaction = submitTransaction;
    window.setTxTypeSegment = setTxTypeSegment;
    window.onTxTypeChange = onTxTypeChange;
    window.toggleCategoryDropdown = toggleCategoryDropdown;
    window.filterCategoryDropdown = filterCategoryDropdown;
    window.onSelectCategory = onSelectCategory;
    window.submitSmartTx = submitSmartTx;
    window.submitQuickInput = submitQuickInput;
    window.openEditTxModal = openEditTxModal;
    window.submitEditTx = submitEditTx;
    window.submitEditTransaction = submitEditTransaction;
    window.deleteTransaction = deleteTransaction;

    // Expose core debt and credit card methods on window
    window.openNewDebtModal = openNewDebtModal;
    window.closeNewDebtModal = closeNewDebtModal;
    window.selectDebtType = selectDebtType;
    window.submitNewDebt = submitNewDebt;
    window.openPayDebtModal = openPayDebtModal;
    window.closePayDebtModal = closePayDebtModal;
    window.submitPayDebt = submitPayDebt;
    window.setPayDebtPercent = setPayDebtPercent;
    window.setPayDebtFull = setPayDebtFull;
    window.archiveDebt = archiveDebt;
    window.updatePayDebtForecast = updatePayDebtForecast;

    window.addEventListener('load', loadStatus);

    function scrollNavigation(delta) {
      document.getElementById('navTabsBar').scrollBy({ left: delta, behavior: 'smooth' });
    }

    /* ── Nav Tabs Drag-to-Scroll + Wheel + Chevron Visibility ── */
    (function initNavDragScroll() {
      const navTabs = document.getElementById('navTabsBar');
      if (!navTabs) return;
      const positionKey = 'ffos_nav_scroll_left';
      let pointerId = null, startX = 0, scrollLeftStart = 0;
      let dragging = false, suppressClickUntil = 0, restored = false;

      navTabs.addEventListener('pointerdown', function(e) {
        // Touch keeps the browser's native pan, momentum and cancellation.
        if (e.pointerType === 'touch' || !e.isPrimary || e.button !== 0) return;
        pointerId = e.pointerId;
        startX = e.clientX;
        scrollLeftStart = navTabs.scrollLeft;
        dragging = false;
        suppressClickUntil = 0;
      });
      document.addEventListener('pointermove', function(e) {
        if (e.pointerId !== pointerId) return;
        const delta = e.clientX - startX;
        if (!dragging && Math.abs(delta) < 6) return;
        if (!dragging) {
          dragging = true;
          navTabs.classList.add('is-dragging');
          navTabs.setPointerCapture(pointerId);
        }
        e.preventDefault();
        navTabs.scrollLeft = scrollLeftStart - delta;
      }, { passive: false });

      function finishDrag(e) {
        if (pointerId === null || (e && e.pointerId !== undefined && e.pointerId !== pointerId)) return;
        const releasedPointer = pointerId;
        if (dragging) suppressClickUntil = performance.now() + 500;
        pointerId = null;
        dragging = false;
        navTabs.classList.remove('is-dragging');
        if (navTabs.hasPointerCapture(releasedPointer)) navTabs.releasePointerCapture(releasedPointer);
        savePosition();
      }
      document.addEventListener('pointerup', finishDrag);
      document.addEventListener('pointercancel', finishDrag);
      navTabs.addEventListener('lostpointercapture', finishDrag);
      window.addEventListener('blur', () => finishDrag());
      navTabs.addEventListener('click', function(e) {
        if (performance.now() < suppressClickUntil && e.detail !== 0) {
          e.preventDefault();
          e.stopImmediatePropagation();
          suppressClickUntil = 0;
        }
      }, true);
      navTabs.addEventListener('dragstart', e => e.preventDefault());
      navTabs.addEventListener('wheel', function(e) {
        if (e.ctrlKey || Math.abs(e.deltaY) <= Math.abs(e.deltaX)) return;
        const multiplier = e.deltaMode === 1 ? 16 : (e.deltaMode === 2 ? navTabs.clientWidth : 1);
        const delta = e.deltaY * multiplier;
        const maxScroll = navTabs.scrollWidth - navTabs.clientWidth;
        const next = Math.max(0, Math.min(maxScroll, navTabs.scrollLeft + delta));
        // At either edge the document must remain vertically scrollable.
        if (Math.abs(next - navTabs.scrollLeft) > 0.5) {
          e.preventDefault();
          navTabs.scrollLeft = next;
        }
      }, { passive: false });

      function savePosition() {
        if (!restored) return;
        try { sessionStorage.setItem(positionKey, String(navTabs.scrollLeft)); } catch (e) {}
      }
      function updateChevrons() {
        if (!navTabs.clientWidth) return;
        if (!restored) {
          restored = true;
          try {
            const saved = Number(sessionStorage.getItem(positionKey));
            if (Number.isFinite(saved) && saved > 0) navTabs.scrollTo({ left: saved, behavior: 'instant' });
          } catch (e) {}
        }
        const sl = document.getElementById('navScrollLeft');
        const sr = document.getElementById('navScrollRight');
        const maxScroll = navTabs.scrollWidth - navTabs.clientWidth;
        if (sl) {
          sl.disabled = navTabs.scrollLeft <= 1;
          sl.setAttribute('aria-disabled', String(sl.disabled));
        }
        if (sr) {
          sr.disabled = navTabs.scrollLeft >= maxScroll - 1;
          sr.setAttribute('aria-disabled', String(sr.disabled));
        }
      }
      navTabs.addEventListener('scroll', () => { updateChevrons(); savePosition(); }, { passive: true });
      window.addEventListener('resize', updateChevrons);
      if (window.ResizeObserver) new ResizeObserver(updateChevrons).observe(navTabs);
      updateChevrons();
    })();

  </script>

</body>

</html>

"""

GLOBAL_DISCOVERY_BEACON = None

def start_server(port: int = PORT, host: str = "127.0.0.1"):

    global GLOBAL_DISCOVERY_BEACON

    if DB_PATH.exists() and not STRICT_ENCRYPTION:

        init_database(DB_PATH)

    elif not ENC_DB_PATH.exists() and not STRICT_ENCRYPTION:

        init_database()

    # Attempt seamless auto-unlock with default password for frictionless local UX

    if GLOBAL_STORAGE.exists() and not GLOBAL_STORAGE.is_unlocked():

        try:

            GLOBAL_STORAGE.open("Family2026!")

            print(f"[{APP_NAME}] Хранилище автоматически разблокировано мастер-паролем.")

        except Exception:

            print(f"[{APP_NAME}] Хранилище защищено пользовательским мастер-паролем (ожидает разблокировки).")

    # Start LAN P2P Discovery Beacon (Disabled by default for 100% local operation)
    if ENABLE_P2P_SYNC:
        try:
            from family_finances_os.sync import PeerDiscoveryBeacon, P2PSyncEngine
            sync_engine = P2PSyncEngine()
            GLOBAL_DISCOVERY_BEACON = PeerDiscoveryBeacon(
                device_id=sync_engine.device_id,
                device_name=sync_engine.device_name,
                http_port=port
            )
            GLOBAL_DISCOVERY_BEACON.start()
        except Exception as e:
            print(f"[{APP_NAME}] Discovery beacon notice: {e}")

    socketserver.TCPServer.allow_reuse_address = True

    with socketserver.TCPServer((host, port), FamilyFinancesHandler) as httpd:

        display_host = "127.0.0.1" if host == "0.0.0.0" else host

        print(f"[{APP_NAME}] Сервер запущен на http://{display_host}:{port}")

        print("Этап 5: Релизная версия Family Finances OS (Offline-First, Envelope Encryption, P2P Sync).")

        try:

            httpd.serve_forever()

        except KeyboardInterrupt:

            print(f"\n[{APP_NAME}] Завершение работы...")

        finally:

            if GLOBAL_STORAGE.is_unlocked():

                try:

                    GLOBAL_STORAGE.save()

                    GLOBAL_STORAGE.lock()

                    print(f"[{APP_NAME}] База данных надёжно зашифрована и сохранена на диск.")

                except Exception as e:

                    print(f"[{APP_NAME}] Ошибка сохранения при завершении: {e}")

            if GLOBAL_DISCOVERY_BEACON:

                GLOBAL_DISCOVERY_BEACON.stop()

if __name__ == "__main__":

    start_server()

