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

const CACHE_NAME = 'ffos-shell-v17';

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

            total_cents, paid_cents, unpaid_cents = ledger.calculate_unpaid_obligations_cents(month_year=month)

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
                parsed = urllib.parse.urlparse(self.path)
                qs = urllib.parse.parse_qs(parsed.query)
                liability_acc_id = qs.get("liability_account_id", [None])[0]
                custom_rub = qs.get("custom_payment_rub", [None])[0]
                custom_pct = qs.get("custom_payment_percent", [None])[0]

                debt_cents = 0
                apr = 24.8
                grace_days = 120
                grace_due = None
                min_pct = 3.0

                if liability_acc_id:
                    conn = ledger._get_conn()
                    cur = conn.cursor()
                    cur.execute("""
                        SELECT a.id, a.subtype, a.credit_limit_cents, a.description,
                            COALESCE(SUM(CASE WHEN p.posting_type = 'CREDIT' THEN p.amount_cents ELSE 0 END), 0) -
                            COALESCE(SUM(CASE WHEN p.posting_type = 'DEBIT' THEN p.amount_cents ELSE 0 END), 0) as balance_cents
                        FROM accounts a
                        LEFT JOIN postings p ON a.id = p.account_id
                        LEFT JOIN transactions t ON p.transaction_id = t.id AND t.is_voided = 0
                        WHERE a.id = ?
                        GROUP BY a.id;
                    """, (liability_acc_id,))
                    row = cur.fetchone()
                    if row:
                        debt_cents = max(0, row["balance_cents"])
                        raw_desc = row["description"] or ""
                        if raw_desc.strip().startswith("{"):
                            try:
                                parsed_meta = json.loads(raw_desc)
                                apr = float(parsed_meta.get("interest_rate_percent", 24.8))
                                grace_days = int(parsed_meta.get("grace_period_days", 120))
                                grace_due = parsed_meta.get("grace_due_date")
                                min_pct = float(parsed_meta.get("min_payment_percent", 3.0))
                            except Exception:
                                pass
                else:
                    debt_rub = qs.get("debt_rub", [0])[0]
                    debt_cents = rubles_to_cents(debt_rub)
                    apr = float(qs.get("interest_rate_percent", [24.8])[0])
                    min_pct = float(qs.get("min_payment_percent", [3.0])[0])

                c_cents = rubles_to_cents(custom_rub) if custom_rub else None
                c_pct = float(custom_pct) if custom_pct else None

                res = ledger.calculate_credit_payoff_scenarios(
                    debt_cents=debt_cents,
                    interest_rate_percent=apr,
                    min_payment_percent=min_pct,
                    grace_period_days=grace_days,
                    grace_due_date=grace_due,
                    custom_payment_cents=c_cents,
                    custom_payment_percent=c_pct
                )
                self._send_json(res)
            except Exception as e:
                self._send_json({"status": "error", "message": str(e)}, status=400)
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

                # 1. Pull changes from remote peer

                pull_body = json.dumps({"since_hlc": body.get("since_hlc")}).encode("utf-8")

                nonce = str(uuid.uuid4())[:16]

                hlc_val = sync_engine.hlc.now()

                sig = sign_sync_payload(pull_body, sync_engine.sync_passphrase, nonce, hlc_val)

                req_pull = urllib.request.Request(

                    f"http://{peer_ip}:{peer_port}/api/sync/pull",

                    data=pull_body,

                    headers={

                        "Content-Type": "application/json",

                        "X-FFOS-Signature": sig,

                        "X-FFOS-Nonce": nonce,

                        "X-FFOS-HLC": hlc_val

                    }

                )

                with urllib.request.urlopen(req_pull, timeout=5.0) as resp:

                    remote_changes = json.loads(resp.read().decode("utf-8"))

                # Apply remote changes locally

                apply_res = sync_engine.apply_remote_changes(remote_changes)

                # 2. Push our changes to remote peer

                our_changes = sync_engine.export_changes(since_hlc=None)

                push_body = json.dumps(our_changes).encode("utf-8")

                nonce2 = str(uuid.uuid4())[:16]

                hlc_val2 = sync_engine.hlc.now()

                sig2 = sign_sync_payload(push_body, sync_engine.sync_passphrase, nonce2, hlc_val2)

                req_push = urllib.request.Request(

                    f"http://{peer_ip}:{peer_port}/api/sync/push",

                    data=push_body,

                    headers={

                        "Content-Type": "application/json",

                        "X-FFOS-Signature": sig2,

                        "X-FFOS-Nonce": nonce2,

                        "X-FFOS-HLC": hlc_val2

                    }

                )

                with urllib.request.urlopen(req_push, timeout=5.0) as resp2:

                    push_res = json.loads(resp2.read().decode("utf-8"))

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
            account_id = body.get("account_id")
            if not account_id:
                self._send_json({"status": "error", "message": "Не указан ID задолженности"}, 400)
                return
            ledger = self._get_ledger()
            success = ledger.archive_account(account_id)
            conn = ledger._get_conn()
            cursor = conn.cursor()
            try:
                cursor.execute("UPDATE obligations SET is_active = 0 WHERE payment_account_id = ?", (account_id,))
                conn.commit()
                ledger._save_if_encrypted()
            finally:
                ledger._close_if_local(conn)
            self._send_json({"status": "success", "archived": success})
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

                if (amount_rub is None or str(amount_rub).strip() == "") and amount_percent is not None:
                    pct = float(amount_percent)
                    if pct <= 0:
                        raise ValueError("Процент погашения должен быть больше нуля.")
                    conn = ledger._get_conn()
                    cur = conn.cursor()
                    cur.execute("""
                        SELECT 
                            COALESCE(SUM(CASE WHEN p.posting_type = 'CREDIT' THEN p.amount_cents ELSE 0 END), 0) -
                            COALESCE(SUM(CASE WHEN p.posting_type = 'DEBIT' THEN p.amount_cents ELSE 0 END), 0) as balance_cents
                        FROM accounts a
                        LEFT JOIN postings p ON a.id = p.account_id
                        LEFT JOIN transactions t ON p.transaction_id = t.id AND t.is_voided = 0
                        WHERE a.id = ?
                        GROUP BY a.id;
                    """, (liability_acc_id,))
                    row = cur.fetchone()
                    cur_debt = row["balance_cents"] if row else 0
                    amount_cents = round(cur_debt * (pct / 100.0))
                    if not desc or desc.strip() == "Погашение задолженности":
                        desc = f"Погашение ({pct:.1f}% / {cents_to_rubles(amount_cents)} ₽)"
                    else:
                        desc = f"{desc} ({pct:.1f}% / {cents_to_rubles(amount_cents)} ₽)"
                else:
                    amount_cents = rubles_to_cents(amount_rub)
                    if amount_percent is not None:
                        pct = float(amount_percent)
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

                    member_id=user.get("member_id")

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

                    member_id=user.get("member_id")

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

                    member_id=user.get("member_id")

                )

                self._send_json(res)

            except Exception as e:

                self._send_json({"status": "error", "message": str(e)}, 400)

            return

        self._send_json({"error": "Not Found"}, 404)

    def _render_app_html(self) -> str:

        return """<!DOCTYPE html>

<html lang="ru">

<head>

  <meta charset="UTF-8">

  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">

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

  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600;700&display=swap" rel="stylesheet">

  <style>
    /* Concept 1: Revolut / Cash App Dark Design System Tokens */
    :root, [data-theme="dark"] {
      --bg: #0c0d12;
      --card-bg: #141720;
      --card-hover: #1a1e2b;
      --border: rgba(255, 255, 255, 0.07);
      --border-hover: rgba(255, 255, 255, 0.14);
      --border-focus: #2563eb;
      --text: #ffffff;
      --text-muted: #8b929e;
      --text-soft: #a8b0bd;
      --primary: #2563eb;
      --primary-hover: #1d4ed8;
      --primary-accent: #3b82f6;
      --primary-gradient: linear-gradient(135deg, #2563eb 0%, #3b82f6 100%);
      --accent-blue: #3b82f6;
      --accent-purple: #8b5cf6;
      --success: #10b981;
      --danger: #ef4444;
      --warning: #f59e0b;
      --purple: #8b5cf6;
      --input-bg: #0f1118;
      --modal-bg: #141720;
      --box-bg: rgba(255, 255, 255, 0.025);
      --shadow: 0 4px 20px rgba(0, 0, 0, 0.45);
      --shadow-lg: 0 16px 40px rgba(0, 0, 0, 0.7);
      --card-radius: 18px;
    }

    [data-theme="light"] {
      --bg: #f8fafc;
      --bg-gradient: linear-gradient(180deg, #f8fafc 0%, #f1f5f9 100%);
      --card-bg: #ffffff;
      --card-hover: #f0f2f5;
      --border: #e4e7ec;
      --border-hover: #d0d5dd;
      --border-focus: #2563eb;
      --text: #0f172a;
      --text-muted: #64748b;
      --text-soft: #475569;
      --primary: #2563eb;
      --primary-hover: #1d4ed8;
      --primary-accent: #3b82f6;
      --primary-gradient: linear-gradient(135deg, #2563eb 0%, #3b82f6 100%);
      --accent-blue: #3b82f6;
      --accent-purple: #8b5cf6;
      --success: #16a34a;
      --danger: #dc2626;
      --warning: #d97706;
      --purple: #8b5cf6;
      --input-bg: #f8fafc;
      --modal-bg: #ffffff;
      --box-bg: #f1f5f9;
      --shadow: 0 4px 16px rgba(0, 0, 0, 0.05);
      --shadow-lg: 0 16px 36px rgba(0, 0, 0, 0.1);
      --card-radius: 18px;
    }

    /* Base Reset & Crisp Typography */
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Inter", "SF Pro Display", "Segoe UI", Roboto, sans-serif;
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

    /* Revolut Header & Top Bar */
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
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      transition: background-color 0.2s, border-color 0.2s;
    }

    .brand-block {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .brand-logo {
      display: flex;
      align-items: center;
      gap: 10px;
      text-decoration: none;
      cursor: pointer;
    }

    .brand-icon {
      font-size: 18px;
      line-height: 1;
      width: 36px;
      height: 36px;
      border-radius: 10px;
      background: var(--primary-gradient);
      display: flex;
      align-items: center;
      justify-content: center;
      color: #ffffff;
      box-shadow: 0 2px 8px rgba(37, 99, 235, 0.3);
      filter: none !important;
    }

    .brand-title {
      font-size: 18px;
      font-weight: 700;
      color: var(--text);
      letter-spacing: -0.02em;
      line-height: 1.15;
    }

    .brand-tag {
      display: block;
      font-size: 11px;
      font-weight: 500;
      color: var(--text-muted);
      letter-spacing: 0.02em;
    }

    .family-scope-chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(37, 99, 235, 0.08);
      border: 1px solid rgba(37, 99, 235, 0.22);
      color: #3b82f6;
      padding: 4px 12px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 600;
    }

    [data-theme="dark"] .family-scope-chip {
      color: #3b82f6;
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: nowrap;
    }

    .btn-icon-round {
      padding: 7px 14px !important;
      border-radius: 9999px !important;
      font-size: 13px !important;
      font-weight: 600 !important;
      display: inline-flex !important;
      align-items: center !important;
      justify-content: center !important;
      gap: 6px !important;
      cursor: pointer;
      background: var(--card-hover) !important;
      border: 1px solid var(--border) !important;
      color: var(--text) !important;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
    }

    .btn-icon-round:hover {
      transform: translateY(-1px);
      background: rgba(255, 255, 255, 0.08) !important;
      border-color: var(--border-hover) !important;
    }

    [data-theme="light"] .btn-icon-round:hover {
      background: #e5e8ef !important;
    }

    .status-indicator-btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.25);
      color: #10b981;
      font-size: 12px;
      font-weight: 600;
      padding: 6px 12px;
      border-radius: 9999px;
      cursor: pointer;
      transition: all 0.2s;
    }

    [data-theme="dark"] .status-indicator-btn {
      color: #34d399;
    }

    .status-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: #10b981;
      box-shadow: 0 0 8px rgba(16, 185, 129, 0.6);
      animation: pulseDot 2.5s infinite;
    }

    @keyframes pulseDot {
      0% { transform: scale(0.95); opacity: 0.8; }
      50% { transform: scale(1.15); opacity: 1; }
      100% { transform: scale(0.95); opacity: 0.8; }
    }

    .desktop-only-text {
      display: inline;
    }

    /* Privacy Mask Mode */
    body.privacy-masked .stat-val,
    body.privacy-masked .hero-balance-val,
    body.privacy-masked .overview-balance-val,
    body.privacy-masked #overviewAccountsBody td:last-child {
      filter: blur(7px);
      user-select: none;
      transition: filter 0.2s ease;
    }
    body.privacy-masked .stat-val:active,
    body.privacy-masked .stat-val:hover,
    body.privacy-masked .hero-balance-val:active,
    body.privacy-masked .hero-balance-val:hover,
    body.privacy-masked #overviewAccountsBody td:last-child:active,
    body.privacy-masked #overviewAccountsBody td:last-child:hover {
      filter: none;
    }

    /* Revolut Segmented Capsule Navigation Tabs */
    .nav-tabs {
      display: flex;
      flex-wrap: nowrap;
      gap: 6px;
      margin-bottom: 24px;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 9999px;
      padding: 5px;
      overflow-x: auto;
      overflow-y: hidden;
      -webkit-overflow-scrolling: touch;
      touch-action: pan-x;
      scrollbar-width: thin;
      scrollbar-color: rgba(255, 255, 255, 0.4) rgba(255, 255, 255, 0.06);
    }
    .nav-tabs::-webkit-scrollbar {
      height: 6px;
      display: block;
    }
    .nav-tabs::-webkit-scrollbar-track {
      background: rgba(255, 255, 255, 0.06);
      border-radius: 9999px;
    }
    .nav-tabs::-webkit-scrollbar-thumb {
      background: rgba(255, 255, 255, 0.38);
      border-radius: 9999px;
      border: 1px solid rgba(0, 0, 0, 0.2);
    }
    .nav-tabs::-webkit-scrollbar-thumb:hover {
      background: var(--primary);
    }
    [data-theme="light"] .nav-tabs {
      scrollbar-color: rgba(0, 0, 0, 0.35) rgba(0, 0, 0, 0.06);
    }
    [data-theme="light"] .nav-tabs::-webkit-scrollbar-track {
      background: rgba(0, 0, 0, 0.06);
    }
    [data-theme="light"] .nav-tabs::-webkit-scrollbar-thumb {
      background: rgba(0, 0, 0, 0.32);
    }

    .tab-btn {
      flex-shrink: 0;
      white-space: nowrap;
      background: transparent;
      color: var(--text-muted);
      border: 1px solid transparent;
      padding: 8px 18px;
      border-radius: 9999px;
      cursor: pointer;
      font-weight: 600;
      font-size: 13px;
      letter-spacing: -0.01em;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
      white-space: nowrap;
    }

    .tab-btn:hover {
      color: var(--text);
      background: var(--card-hover);
    }

    [data-theme="dark"] .tab-btn.active,
    :root .tab-btn.active {
      color: #0c0d12 !important;
      background: #ffffff !important;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.35);
      border-color: transparent !important;
    }

    [data-theme="light"] .tab-btn.active {
      color: #ffffff !important;
      background: #0f172a !important;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.12);
      border-color: transparent !important;
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
        flex-wrap: nowrap !important;
        overflow-x: auto !important;
        overflow-y: hidden !important;
        -webkit-overflow-scrolling: touch !important;
        touch-action: pan-x !important;
        scrollbar-width: thin !important;
        scrollbar-color: rgba(255, 255, 255, 0.45) rgba(255, 255, 255, 0.08) !important;
        gap: 4px !important;
        padding-bottom: 8px !important;
        margin-bottom: 16px !important;
      }
      .nav-tabs::-webkit-scrollbar {
        height: 5px !important;
        display: block !important;
      }
      .nav-tabs::-webkit-scrollbar-track {
        background: rgba(255, 255, 255, 0.06) !important;
        border-radius: 9999px !important;
      }
      .nav-tabs::-webkit-scrollbar-thumb {
        background: rgba(255, 255, 255, 0.4) !important;
        border-radius: 9999px !important;
      }
      .tab-btn {
        flex-shrink: 0 !important;
        white-space: nowrap !important;
        padding: 7px 14px !important;
        font-size: 12px !important;
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
      background: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
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
      width: 44px;
      height: 5px;
      background: rgba(255, 255, 255, 0.3);
      border-radius: 999px;
      margin: 0 auto;
      transition: background 0.2s ease;
    }

    [data-theme="light"] .bottom-sheet-handle {
      background: rgba(0, 0, 0, 0.2);
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
        background: rgba(0, 0, 0, 0.65) !important;
        touch-action: pan-y;
      }
      #modalNewTx .bottom-sheet-card {
        max-width: 100% !important;
        width: 100% !important;
        border-radius: 24px 24px 0 0 !important;
        margin: 0 !important;
        border-left: none !important;
        border-right: none !important;
        border-bottom: none !important;
        max-height: 85vh !important;
        padding: 14px 20px calc(24px + env(safe-area-inset-bottom, 20px)) 20px !important;
        animation: revolutSlideUp 0.32s cubic-bezier(0.16, 1, 0.3, 1);
        box-shadow: 0 -10px 40px rgba(0, 0, 0, 0.5) !important;
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
        backdrop-filter: blur(20px) !important;
        -webkit-backdrop-filter: blur(20px) !important;
        border: 1px solid var(--border) !important;
        margin-bottom: 18px !important;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35) !important;
      }

      .nav-tabs {
        display: flex !important;
        flex-wrap: wrap !important;
        gap: 8px !important;
        padding: 8px 12px !important;
        border-radius: 16px !important;
        background: rgba(17, 24, 39, 0.6) !important;
        backdrop-filter: blur(20px) !important;
        -webkit-backdrop-filter: blur(20px) !important;
        margin-bottom: 24px !important;
        overflow-x: visible !important;
      }

      .tab-btn {
        padding: 8px 18px !important;
        font-size: 13px !important;
        font-weight: 600 !important;
        border-radius: 10px !important;
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
      border-top: 3px solid #2563eb !important;
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

    /* Navigation Tabs in Light Theme */
    [data-theme="light"] .nav-tabs {
      background: #f1f5f9 !important;
      border: 1px solid #e2e8f0 !important;
      box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.04) !important;
    }

    [data-theme="light"] .tab-btn {
      color: #64748b !important;
      background: transparent !important;
    }

    [data-theme="light"] .tab-btn:hover {
      color: #0f172a !important;
      background: #e2e8f0 !important;
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

    /* Month navigator light mode */
    [data-theme="light"] .month-navigator-bar {
      background: #ffffff !important;
      border: 1px solid #e2e8f0 !important;
      box-shadow: 0 4px 16px -2px rgba(15, 23, 42, 0.06) !important;
      color: #0f172a !important;
    }
    [data-theme="light"] .month-navigator-bar span {
      color: #0f172a !important;
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

  </style>

</head>

<body>

  <div class="container">

    <div class="header">
      <div class="brand-block">
        <div class="brand-logo" onclick="switchTab('tab-overview')">
          <span class="brand-icon">💎</span>
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
        <!-- Privacy Masking Button (Mask balances in public) -->
        <button id="btnPrivacyToggle" class="btn btn-secondary btn-icon-round hidden" onclick="togglePrivacyMask()" title="Скрыть/показать суммы (режим приватности)">
          <span id="privacyIcon">👁️</span>
        </button>

        <!-- Discreet Status Dot -->
        <button id="btnStatusIndicator" class="status-indicator-btn hidden" onclick="openSettingsModal()" title="Система защищена AES-256 • Данные на телефоне">
          <span class="status-dot"></span>
          <span class="status-dot-label desktop-only-text">Защищено</span>
        </button>

        <!-- Theme Toggle -->
        <button id="themeToggleBtn" class="btn btn-secondary btn-icon-round" onclick="toggleTheme()" title="Переключить тему оформления">
          <span id="themeToggleIcon">☀️</span> <span id="themeToggleText" class="desktop-only-text">Светлая</span>
        </button>

        <!-- Settings & Security Modal Trigger -->
        <button id="btnOpenSettings" class="btn btn-secondary btn-icon-round hidden" onclick="openSettingsModal()" title="Настройки и безопасность">
          <span>⚙️</span>
          <span class="desktop-only-text">Настройки</span>
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
            <h3 id="modalTxHeaderTitle" style="font-size: 18px; font-weight: 700; color: var(--text); margin: 0;">Новый расход семьи</h3>
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
                <div id="modalTxCatSelectedName" style="font-size: 14px; font-weight: 600; color: var(--text);">Продукты и супермаркеты</div>
                <div id="modalTxCatSelectedParent" style="font-size: 11px; color: var(--text-muted);">Нажмите для выбора из меню категорий</div>
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
<div class="month-navigator-bar" style="background: rgba(30, 41, 59, 0.85); border: 1px solid var(--border); border-radius: 12px; padding: 12px 18px; margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.25);">
  <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
    <span style="font-weight: 600; font-size: 14px; color: var(--text-muted); display: flex; align-items: center; gap: 6px;">
      <span style="font-size: 18px;">📅</span>
      <span>Период учёта:</span>
    </span>
    <div style="display: flex; align-items: center; gap: 6px;">
      <button type="button" class="btn btn-secondary" style="padding: 6px 12px; font-size: 14px;" onclick="shiftSelectedMonth(-1)" title="Предыдущий месяц">◀</button>
      <select id="globalMonthSelect" onchange="onGlobalMonthSelectChange(this.value)" style="padding: 6px 14px; font-size: 14px; font-weight: 600; background: var(--input-bg); color: var(--text); border: 1px solid var(--border); border-radius: 8px; cursor: pointer; min-width: 170px;">
        <!-- Filled dynamically -->
      </select>
      <button type="button" class="btn btn-secondary" style="padding: 6px 12px; font-size: 14px;" onclick="shiftSelectedMonth(1)" title="Следующий месяц">▶</button>
    </div>
    <button type="button" id="btnCurrentMonthReset" class="btn btn-secondary" style="padding: 6px 12px; font-size: 12px; display: none;" onclick="resetToCurrentMonth()">🔄 Текущий месяц</button>
  </div>
  <div id="pastMonthNotice" style="display: none; align-items: center; gap: 8px; font-size: 13px; color: #fbbf24; background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.35); border-radius: 8px; padding: 6px 14px;">
    <span>⚠️ <strong>Архивный режим:</strong> <span id="pastMonthNoticeLabel"></span>. Все операции и бюджеты фильтруются за этот месяц.</span>
  </div>
</div>

<!-- Desktop Navigation Tabs -->
<div class="nav-tabs">

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
              <span class="revolut-action-label" style="font-weight: 700;">🔴 + Расход</span>
            </button>

            <button class="hero-action-btn revolut-action-btn" id="heroBtnIncome" onclick="openNewTxModal('INCOME')">
              <div class="hero-action-icon revolut-icon-income">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                  <line x1="12" y1="5" x2="12" y2="19"></line>
                  <line x1="5" y1="12" x2="19" y2="12"></line>
                </svg>
              </div>
              <span class="revolut-action-label" style="font-weight: 700;">🟢 ＋ Доход</span>
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
              <span class="revolut-action-label" style="font-weight: 600;">⇄ Перевод</span>
            </button>

            <button class="hero-action-btn revolut-action-btn" id="heroBtnGoals" onclick="switchTab('goals')">
              <div class="hero-action-icon revolut-icon-goals">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="12" cy="12" r="10"></circle>
                  <circle cx="12" cy="12" r="6"></circle>
                  <circle cx="12" cy="12" r="2"></circle>
                </svg>
              </div>
              <span class="revolut-action-label" style="font-weight: 600;">🎯 Цели</span>
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
              <span style="font-size: 15px; font-weight: 600; letter-spacing: -0.01em;">Revolut Family Debit</span>
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
              <div style="text-align: right;">
                <div style="font-size: 10px; opacity: 0.7; text-transform: uppercase;">Срок</div>
                <div style="font-mono font-weight: 600;">12/29</div>
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
          <div style="overflow-x: auto; -webkit-overflow-scrolling: touch;">

          <h3 style="margin-bottom: 12px; font-size: 16px;">Балансы всех счетов семьи</h3>

          <table>

            <thead>

              <tr>

                <th>Код</th>

                <th>Счет</th>

                <th>Тип</th>

                <th>Принадлежность</th>

                <th style="text-align: right;">Текущий остаток</th>

              </tr>

            </thead>

            <tbody id="overviewAccountsBody"></tbody>

          </table>
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

      if (tabId === 'tab-tx') renderCategoryChips();

      if (tabId === 'tab-import') populateImportAccounts();

    }

    // --- Stage 7 Analytics & Forecast State & Functions ---

    let currentAnalyticsPeriod = 'current_month';

    let currentForecastDays = 30;

    let forecastIncludeBurn = true;

    function changeAnalyticsPeriod(period) {

      currentAnalyticsPeriod = period;

      document.querySelectorAll('.period-pills .pill-btn').forEach(btn => btn.classList.remove('active'));

      const activeBtnMap = {

        'current_month': 'pillCurrentMonth',

        'prev_month': 'pillPrevMonth',

        '30d': 'pill30d',

        '90d': 'pill90d',

        'all': 'pillAll'

      };

      const btnEl = document.getElementById(activeBtnMap[period]);

      if (btnEl) btnEl.classList.add('active');

      loadAnalytics();

    }

    function changeForecastHorizon(days) {

      currentForecastDays = days;

      [30, 60, 90].forEach(d => {

        const btn = document.getElementById('btnForecast' + d);

        if (btn) btn.classList.toggle('active', d === days);

      });

      loadForecast();

    }

    function toggleForecastBurn() {

      const chk = document.getElementById('chkIncludeBurn');

      forecastIncludeBurn = chk ? chk.checked : true;

      loadForecast();

    }

    async function loadAnalytics(period) {
      try {
        const targetPeriod = period || currentAnalyticsPeriod || currentSelectedMonth || 'current_month';
        currentAnalyticsPeriod = targetPeriod;
        const res = await fetch('/api/analytics/summary?period=' + targetPeriod, { headers: authHeaders() });

        if (res.status === 401 || res.status === 423) return;

        const data = await res.json();

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

              <td style="font-weight:500;">${t.description}</td>

              <td>${t.category_icon} ${t.category_name}</td>

              <td style="font-weight:600; color:#f87171;">-${t.amount_rub} ₽</td>

            </tr>

          `).join('');

        }

      } catch (err) {

        console.error('Error loading analytics:', err);

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

      try {

        const res = await fetch('/api/forecast/cashflow?days=' + currentForecastDays + '&include_burn=' + (forecastIncludeBurn ? '1' : '0'), { headers: authHeaders() });

        if (res.status === 401 || res.status === 423) return;

        const data = await res.json();

        // 1. Stats strip

        document.getElementById('fcStartLiquid').innerText = data.starting_liquid_rub + ' ₽';

        document.getElementById('fcCreditDebt').innerText = '-' + data.credit_debt_rub + ' ₽';

        document.getElementById('fcDailyBurn').innerText = data.daily_burn_rub + ' ₽/дн';

        document.getElementById('fcMinBalance').innerText = data.min_projected_balance_rub + ' ₽';

        document.getElementById('fcMinBalance').style.color = data.min_projected_balance_cents < 0 ? '#ef4444' : '#34d399';

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

        console.error('Error loading forecast:', err);

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

      const tbody = document.getElementById('overviewAccountsBody');

      tbody.innerHTML = '';

      overviewData.accounts.forEach(a => {

        const tr = document.createElement('tr');

        const scopeBadge = a.scope === 'COMMON' ? '<span class="badge">Общий</span>' :

                          (a.scope === 'PERSONAL_HUSBAND' ? '<span class="badge" style="background:#0e7490;">Муж</span>' : '<span class="badge" style="background:#be185d;">Жена</span>');

        tr.innerHTML = `

          <td style="font-family:monospace; color:var(--text-muted);">${a.code}</td>

          <td><strong>${a.name}</strong></td>

          <td>${a.subtype}</td>

          <td>${scopeBadge}</td>

          <td style="font-weight:700; text-align: right; font-variant-numeric: tabular-nums;">${a.balance_rub} ₽</td>

        `;

        tbody.appendChild(tr);

      });

    }

    function renderManageAccounts() {

      const tbody = document.getElementById('manageAccountsBody');

      tbody.innerHTML = '';

      overviewData.accounts.forEach(a => {

        const tr = document.createElement('tr');

        const limitDisplay = a.credit_limit_cents > 0 ? a.credit_limit_rub + ' ₽' : '—';

        tr.innerHTML = `

          <td style="font-family:monospace;">${a.code}</td>

          <td>${a.name}</td>

          <td>${a.subtype}</td>

          <td>${a.scope}</td>

          <td>${a.balance_rub} ₽</td>

          <td>${limitDisplay}</td>

          <td><button class="btn btn-secondary" style="padding:4px 8px; font-size:12px;" onclick="archiveAccount('${a.id}')">Архив</button></td>

        `;

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

        const res = await fetch('/api/obligations', { headers: authHeaders() });

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

            <span class="badge" style="background: #5b21b6; color: #ddd6fe;">${data.month_year}</span>

          </div>

          <table>

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

              <td><strong>до ${o.due_day}-го</strong></td>

              <td><strong>${o.name}</strong>${o.note ? `<br><small style="color:var(--text-muted);">${o.note}</small>` : ''}</td>

              <td style="font-weight: 700; font-size: 15px;">${o.amount_rub} ₽</td>

              <td>${o.category_icon} ${o.category_name}</td>

              <td>${statusBadge}</td>

              <td>

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

        body: JSON.stringify({ obligation_id: obligationId })

      });

      await loadObligations();

      await loadDashboard();

    }

    async function unpayObligation(obligationId) {

      const res = await fetch('/api/obligations/unpay', {

        method: 'POST',

        headers: authHeaders(),

        body: JSON.stringify({ obligation_id: obligationId })

      });

      await loadObligations();

      await loadDashboard();

    }

    async function archiveObligation(obligationId) {

      if (!confirm('Архивировать это обязательство?')) return;

      await fetch('/api/obligations/archive', {

        method: 'POST',

        headers: authHeaders(),

        body: JSON.stringify({ obligation_id: obligationId })

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
            const postingSummary = t.postings.map(p => `${p.type === 'DEBIT' ? 'Дт' : 'Кт'} ${p.account_name} (${p.amount_rub} ₽)`).join('<br>');
            const mainAmount = t.postings[0] ? t.postings[0].amount_rub + ' ₽' : '0.00 ₽';
            const safeDesc = encodeURIComponent(t.description || '');
            const isExpense = (t.tx_type === 'EXPENSE');
            tr.innerHTML = `
              <td><strong>${t.tx_date}</strong></td>
              <td><span class="badge" style="background:var(--card-bg); border:1px solid var(--border);">${t.category_icon || '🏷️'} ${t.category_name}</span></td>
              <td>${t.description}</td>
              <td style="font-size: 13px;">${postingSummary}</td>
              <td style="font-weight: 700; text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums; color: ${isExpense ? '#f87171' : '#34d399'};">${isExpense ? '-' : '+'}${mainAmount}</td>
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
            const safeDesc = encodeURIComponent(t.description || '');
            const isExpense = (t.tx_type === 'EXPENSE');
            tr.innerHTML = `
              <td style="white-space: nowrap; font-size: 13px; color: var(--text-muted);">${t.tx_date}</td>
              <td><span class="badge" style="background:var(--card-bg); border:1px solid var(--border); font-size: 12px;">${t.category_icon || '🏷️'} ${t.category_name}</span></td>
              <td style="font-weight: 500; font-size: 14px; max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${t.description}</td>
              <td style="font-weight: 700; text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums; color: ${isExpense ? '#f87171' : '#34d399'};">${isExpense ? '-' : '+'}${mainAmount}</td>
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

        balances.push({ account_id: mainAcc.id, balance_cents: Math.round(parseFloat(mainCard) * 100) });

      }

      if (wifeAcc && parseFloat(wifeCard) > 0) {

        balances.push({ account_id: wifeAcc.id, balance_cents: Math.round(parseFloat(wifeCard) * 100) });

      }

      if (cashAcc && parseFloat(cash) > 0) {

        balances.push({ account_id: cashAcc.id, balance_cents: Math.round(parseFloat(cash) * 100) });

      }

      if (credAcc) {

        balances.push({

          account_id: credAcc.id,

          balance_cents: Math.round(parseFloat(credDebt) * 100),

          credit_limit_cents: Math.round(parseFloat(credLimit) * 100)

        });

      }

      const obligations = [];

      if (oblName && parseFloat(oblAmount) > 0) {

        obligations.push({

          name: oblName,

          amount_cents: Math.round(parseFloat(oblAmount) * 100),

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

          <td>${item.date}</td>

          <td>${dirBadge}</td>

          <td>${item.description}</td>

          <td>

            <select id="importCatSelect_${idx}" style="padding:4px; font-size:12px; background:var(--card-bg); color:var(--text); border:1px solid var(--border); border-radius:4px;" onchange="currentPreviewItems[${idx}].category_id = this.value">

              <option value="">Без категории</option>

              ${categoryData ? categoryData.map(c => `<option value="${c.id}" ${c.id === item.category_id ? 'selected' : ''}>${c.name}</option>`).join('') : ''}

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

        if (data.status === 'success') {

          alert(`Успешно импортировано операций: ${data.imported_count} (пропущено дубликатов: ${data.skipped_count})`);

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

            const accLabel = p.account_name ? ` · 💳 ${p.account_name}` : '';

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

            ? `<div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">🏦 Счет: ${g.account_name}</div>`

            : '';

          return `

            <div class="card" style="margin-bottom: 0; display: flex; flex-direction: column; justify-content: space-between; border-color: ${isDone ? '#059669' : 'var(--border)'}; background: ${isDone ? 'rgba(5, 150, 105, 0.05)' : 'var(--card-bg)'};">

              <div>

                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">

                  <div style="display: flex; align-items: center; gap: 8px;">

                    <span style="font-size: 26px;">${g.icon || '🎯'}</span>

                    <div>

                      <div style="font-weight: 700; font-size: 16px; color: var(--text);">${g.name}</div>

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

                  ${g.note ? `<div style="font-size: 11px; color: var(--text-muted); font-style: italic; margin-top: 6px;">💬 ${g.note}</div>` : ''}

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

              <span style="font-size: 13px; font-weight: 600; color: var(--text);">${g.icon || '🎯'} ${g.name}</span>

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
            urgentText.innerHTML = `<strong>Срочное внимание по кредитным картам семьи!</strong> Приближается срок платежа или допущена просрочка (карт с платежом: <strong>${allDebtsData.urgent_cards_count || 1}</strong>). Общий обязательный платеж: <strong>${allDebtsData.total_min_payments_rub || '0.00'} ₽</strong>. Внесите платежи вовремя, чтобы избежать штрафной неустойки 36% годовых и начисления процентов!`;
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
                  <span>Лимит: <strong>${d.credit_limit_rub || '0.00'} ₽</strong> | Доступно: <strong>${d.available_rub || '0.00'} ₽</strong></span>
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
            const statusBadge = `<span class="badge" style="background:${statusBg}; color:${statusColor}; border:1px solid ${statusColor}; font-weight:700; font-size:11px; padding:3px 8px;">${b.status_label || 'Активна'}</span>`;

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
                  ${b.warning_message || 'Контроль платежей по кредитной карте активен.'}
                </div>

                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; margin-bottom: 10px;">
                  <div style="background: var(--card-hover); padding: 8px 10px; border-radius: 6px;">
                    <div style="font-size: 11px; color: var(--text-muted);">Обязательный мин. платеж:</div>
                    <div style="font-size: 15px; font-weight: 700; color: #fbbf24;">${b.min_payment_formatted || b.min_payment_rub || '0.00'} ₽</div>
                    <div style="font-size: 10px; color: var(--text-muted);">${b.min_payment_percent || 3.0}% от суммы долга</div>
                  </div>
                  <div style="background: var(--card-hover); padding: 8px 10px; border-radius: 6px;">
                    <div style="font-size: 11px; color: var(--text-muted);">Ставка банка вне грейса:</div>
                    <div style="font-size: 15px; font-weight: 700; color: #94a3b8;">${b.interest_rate_percent || 24.8}% <span style="font-size: 11px;">годовых</span></div>
                    <div style="font-size: 10px; color: var(--text-muted);">0.0% в льготный период</div>
                  </div>
                  <div style="background: var(--card-hover); padding: 8px 10px; border-radius: 6px;">
                    <div style="font-size: 11px; color: var(--text-muted);">Неустойка за просрочку:</div>
                    <div style="font-size: 15px; font-weight: 700; color: #f87171;">${b.late_penalty_rate_percent || 36.0}% <span style="font-size: 11px;">годовых</span></div>
                    <div style="font-size: 10px; color: var(--text-muted);">по договору Сбербанка</div>
                  </div>
                </div>

                <!-- Overdue Simulation Box -->
                ${hasDebt ? `
                  <div style="background: rgba(239, 68, 68, 0.08); border: 1px dashed rgba(239, 68, 68, 0.4); border-radius: 8px; padding: 10px 12px; margin-bottom: 10px;">
                    <div style="font-size: 12px; font-weight: 700; color: #fca5a5; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 4px; margin-bottom: 6px;">
                      <span>⚠️ Расчет банковских штрафов при просрочке на 30 дней:</span>
                      <span style="font-size: 13px; color: #ef4444; font-weight: 800;">+${b.simulation_30d_extra_rub || '0.00'} ₽ переплаты</span>
                    </div>
                    <div style="font-size: 11px; color: var(--text-muted); display: grid; grid-template-columns: 1fr 1fr; gap: 6px; line-height: 1.4;">
                      <div>• Проценты по ставке (${b.interest_rate_percent || 24.8}%): <strong style="color:#f87171;">+${b.simulation_30d_interest_rub || '0.00'} ₽</strong></div>
                      <div>• Неустойка банка (${b.late_penalty_rate_percent || 36.0}%): <strong style="color:#f87171;">+${b.simulation_30d_penalty_rub || '0.00'} ₽</strong></div>
                    </div>
                    <div style="margin-top: 6px; padding-top: 6px; border-top: 1px solid rgba(239, 68, 68, 0.2); font-size: 12px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                      <span>Итого к оплате банку при просрочке:</span>
                      <strong style="color: #fca5a5; font-size: 14px;">${b.simulation_30d_total_rub || '0.00'} ₽</strong>
                    </div>
                  </div>
                ` : ''}

                <!-- Action buttons for this card -->
                <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                  ${hasDebt ? `
                    <button class="btn btn-secondary" style="font-size: 12px; padding: 6px 10px; color: #fbbf24; border-color: rgba(251, 191, 36, 0.4);" onclick="openPayDebtModal('${d.id}', ${b.min_payment_rub || 0})">
                      💳 Внести мин. платеж (${b.min_payment_formatted || b.min_payment_rub || '0.00'} ₽)
                    </button>
                    <button class="btn btn-danger" style="font-size: 12px; padding: 6px 10px;" onclick="openPayDebtModal('${d.id}', ${fullDebtNum})">
                      💰 Закрыть весь долг (${d.debt_rub || '0.00'} ₽)
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
              <span>📅 Привязан регулярный платеж: <strong>${d.linked_obligation.amount_rub || '0.00'} ₽</strong> (до ${d.linked_obligation.due_day}-го числа)</span>
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
                    <span style="font-size: 11px; color: var(--text-muted);">Расчет по договору Сбербанка (${d.banking.interest_rate_percent || 24.8}% APR)</span>
                  </div>

                  <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 8px; margin-bottom: 8px;">
                    <!-- Grace Period -->
                    ${graceSc && graceSc.is_active ? `
                      <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.4); border-radius: 6px; padding: 8px 10px; display: flex; flex-direction: column; justify-content: space-between;">
                        <div>
                          <div style="font-size: 11px; font-weight: 700; color: #34d399; margin-bottom: 2px;">💎 В льготный период (0% переплаты)</div>
                          <div style="font-size: 11px; color: var(--text-muted); line-height: 1.3;">
                            Срок: <strong style="color: var(--text);">${graceSc.days_left || 0} дн.</strong> (до ${graceSc.due_date || 'конца грейса'})<br>
                            Переплата: <strong style="color: #34d399;">0.00 ₽</strong> (100% экономия)
                          </div>
                        </div>
                        <button class="btn btn-secondary" style="font-size: 11px; padding: 4px 8px; margin-top: 6px; color: #34d399; border-color: rgba(52,211,153,0.4);" onclick="openPayDebtModal('${d.id}', ${fullDebtNum}, 100)">
                          Закрыть без процентов (${d.debt_rub || '0.00'} ₽)
                        </button>
                      </div>
                    ` : ''}

                    <!-- Minimum Payment Warning -->
                    ${minSc ? `
                      <div style="background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 6px; padding: 8px 10px; display: flex; flex-direction: column; justify-content: space-between;">
                        <div>
                          <div style="font-size: 11px; font-weight: 700; color: #fca5a5; margin-bottom: 2px;">⚠️ Мин. платеж (${minSc.payment_percent || 3.0}% от долга)</div>
                          <div style="font-size: 11px; color: var(--text-muted); line-height: 1.3;">
                            Платеж: <strong style="color: #fbbf24;">${minSc.first_payment_rub || '0.00'} ₽/мес</strong> (${minSc.payment_percent || 3.0}%)<br>
                            Срок: <strong style="color: #f87171;">${minSc.days_to_payoff || 0} дн.</strong> (${minSc.months_to_payoff || 0} мес.)<br>
                            Переплата: <strong style="color: #ef4444;">+${minSc.total_interest_rub || '0.00'} ₽</strong>
                          </div>
                        </div>
                        <button class="btn btn-secondary" style="font-size: 11px; padding: 4px 8px; margin-top: 6px; color: #fbbf24; border-color: rgba(251,191,36,0.4);" onclick="openPayDebtModal('${d.id}', ${(minSc.first_payment_cents || 0) / 100}, ${minSc.payment_percent || 3.0})">
                          Мин. платеж (${minSc.first_payment_rub || '0.00'} ₽)
                        </button>
                      </div>
                    ` : ''}

                    <!-- Accelerated Horizons -->
                    ${accSc.filter(Boolean).map(a => `
                      <div style="background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 6px; padding: 8px 10px; display: flex; flex-direction: column; justify-content: space-between;">
                        <div>
                          <div style="font-size: 11px; font-weight: 700; color: #38bdf8; margin-bottom: 2px;">⚡ ${a.label || 'Ускоренное погашение'}</div>
                          <div style="font-size: 11px; color: var(--text-muted); line-height: 1.3;">
                            Платеж: <strong style="color: var(--text);">${a.monthly_payment_rub || '0.00'} ₽/мес</strong> (${a.monthly_payment_percent || 0}%)<br>
                            Срок: <strong style="color: #38bdf8;">${a.days || 0} дн.</strong> (${a.months || 0} мес.)<br>
                            Экономия: <strong style="color: #34d399;">+${a.interest_savings_rub || '0.00'} ₽</strong>
                          </div>
                        </div>
                        <button class="btn btn-secondary" style="font-size: 11px; padding: 4px 8px; margin-top: 6px; color: #38bdf8; border-color: rgba(56,189,248,0.4);" onclick="openPayDebtModal('${d.id}', ${(a.monthly_payment_cents || 0) / 100}, ${a.monthly_payment_percent || 0})">
                          Платить ${a.monthly_payment_rub || '0.00'} ₽/мес
                        </button>
                      </div>
                    `).join('')}
                  </div>
                </div>
              `;
            }
          }

          const safeName = encodeURIComponent(d.name || '');

          return `
            <div class="card" style="margin-bottom: 0; border-left: 4px solid ${hasDebt ? '#ef4444' : '#10b981'};">
              <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 10px;">
                <div>
                  <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                    <span style="font-size: 18px;">${cfg.icon}</span>
                    <strong style="font-size: 16px; color: var(--text);">${d.name}</strong>
                    ${typeBadge}
                    ${scopeBadge}
                    <span style="font-family: monospace; color: var(--text-muted); font-size: 11px;">${d.code}</span>
                  </div>
                  <div style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">
                    Остаток задолженности: <strong style="color: ${hasDebt ? '#f87171' : '#34d399'}; font-size: 17px;">${d.debt_rub || '0.00'} ₽</strong>
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
      
      // Defaults according to Sberbank contract TP-1001
      const now = new Date();
      const lastDayOfMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0);
      const yyyy = lastDayOfMonth.getFullYear();
      const mm = String(lastDayOfMonth.getMonth() + 1).padStart(2, '0');
      const dd = String(lastDayOfMonth.getDate()).padStart(2, '0');
      const defDueDate = `${yyyy}-${mm}-${dd}`;

      const elDue = document.getElementById('newDebtGraceDueDate');
      if (elDue) elDue.value = defDueDate;
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
      const grace_period_days = (subtype === 'CREDIT_CARD') ? (parseInt(document.getElementById('newDebtGraceDays')?.value) || 120) : 120;
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
      document.getElementById('cardSettingsDebtBal').innerText = (card.debt_rub || '0.00') + ' ₽';
      document.getElementById('cardSettingsLimit').value = parseFloat(card.credit_limit_rub) || 0;
      document.getElementById('cardSettingsDueDate').value = b.grace_due_date || '';
      document.getElementById('cardSettingsApr').value = b.interest_rate_percent || 24.8;
      document.getElementById('cardSettingsGraceDays').value = b.grace_period_days || 120;
      document.getElementById('cardSettingsMinPaymentPct').value = b.min_payment_percent || 3.0;
      document.getElementById('cardSettingsLatePenaltyPct').value = b.late_penalty_rate_percent || 36.0;
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
      const apr = parseFloat(document.getElementById('cardSettingsApr').value) || 24.8;
      const graceDays = parseInt(document.getElementById('cardSettingsGraceDays').value) || 120;
      const minPct = parseFloat(document.getElementById('cardSettingsMinPaymentPct').value) || 3.0;
      const penaltyPct = parseFloat(document.getElementById('cardSettingsLatePenaltyPct').value) || 36.0;
      const msgEl = document.getElementById('cardSettingsMsg');

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
          opt.innerText = `${d.name} (долг: ${d.debt_rub} ₽)`;
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
          opt.innerText = `${a.name} (${a.scope || a.ownership_scope || ''}, ${a.balance_rub} ₽)`;
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
      if (curEl) curEl.innerText = d.debt_rub + ' ₽';
      const limEl = document.getElementById('payDebtLimitAmount');
      if (limEl) limEl.innerText = (d.credit_limit_rub || '0.00') + ' ₽';

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

    function updatePayDebtForecast() {
      const box = document.getElementById('payDebtForecastBox');
      if (!box) return;
      const liabId = document.getElementById('payDebtLiabilityAccount')?.value;
      const d = (allDebtsData && allDebtsData.debts) ? allDebtsData.debts.find(x => x.id === liabId) : null;
      const debtRub = d ? (parseFloat(d.debt_rub) || 0) : 0;
      const payRub = parseFloat(document.getElementById('payDebtAmount')?.value) || 0;

      const daysEl = document.getElementById('payDebtForecastDays');
      const dateEl = document.getElementById('payDebtForecastDate');
      const intEl = document.getElementById('payDebtForecastInterest');
      const savEl = document.getElementById('payDebtForecastSavings');
      const statusEl = document.getElementById('payDebtForecastStatus');

      if (debtRub <= 0 || payRub <= 0) {
        if (daysEl) daysEl.innerText = '—';
        if (dateEl) dateEl.innerText = '—';
        if (intEl) intEl.innerText = '—';
        if (savEl) savEl.innerText = '—';
        if (statusEl) statusEl.innerText = '';
        return;
      }

      const apr = (d && d.banking && d.banking.interest_rate_percent) ? parseFloat(d.banking.interest_rate_percent) : 24.8;
      const monthlyRate = (apr / 100.0) / 12.0;

      let baseInterest = 0;
      let dBase = debtRub;
      let mBase = 0;
      while (dBase > 0 && mBase < 360) {
        mBase++;
        const intr = dBase * monthlyRate;
        baseInterest += intr;
        const minP = Math.max(150, dBase * 0.03);
        const effP = Math.min(dBase + intr, minP < intr + 10 ? intr + 10 : minP);
        dBase -= (effP - intr);
      }

      if (payRub >= debtRub) {
        if (daysEl) daysEl.innerText = '0 дней (полное погашение)';
        if (dateEl) dateEl.innerText = 'Сегодня';
        if (intEl) intEl.innerText = '0.00 ₽ (0%)';
        if (savEl) savEl.innerText = '+' + baseInterest.toFixed(2) + ' ₽ (100% экономия)';
        if (statusEl) statusEl.innerHTML = '<span style="color:#34d399; font-weight:700;">✅ Полное закрытие</span>';
        return;
      }

      let dSim = debtRub;
      let months = 0;
      let totalInt = 0;
      let maxMonths = 360;
      let isTrapped = false;

      while (dSim > 0 && months < maxMonths) {
        months++;
        const intr = dSim * monthlyRate;
        totalInt += intr;
        if (payRub <= intr && dSim > 0) {
          isTrapped = true;
          break;
        }
        const princ = Math.min(dSim, payRub - intr);
        dSim -= princ;
      }

      if (isTrapped) {
        if (daysEl) daysEl.innerText = 'Бесконечно ⚠️';
        if (dateEl) dateEl.innerText = 'Платеж меньше ежемесячных процентов!';
        if (intEl) intEl.innerText = 'Долг не закроется';
        if (savEl) savEl.innerText = 'Увеличьте сумму платежа';
        if (statusEl) statusEl.innerHTML = '<span style="color:#ef4444; font-weight:700;">⚠️ Ловушка</span>';
        return;
      }

      const days = months * 30;
      const now = new Date();
      now.setDate(now.getDate() + days);
      const targetDateStr = now.toISOString().slice(0, 10);
      const savings = Math.max(0, baseInterest - totalInt);

      if (daysEl) daysEl.innerText = days + ' дн. (' + months + ' мес.)';
      if (dateEl) dateEl.innerText = targetDateStr;
      if (intEl) intEl.innerText = totalInt.toFixed(2) + ' ₽';
      if (savEl) savEl.innerText = '+' + savings.toFixed(2) + ' ₽';
      if (statusEl) statusEl.innerHTML = '<span style="color:#38bdf8; font-weight:700;">⚡ Расчет готов</span>';
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

            <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">🏦 Счет хранения: ${e.linked_account_name}</div>

          ` : '';

          return `

            <div class="card" style="margin-bottom: 0; border-top: 4px solid ${barColor}; background: linear-gradient(180deg, rgba(255,255,255,0.03) 0%, rgba(15,23,42,0.6) 100%);">

              <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">

                <div style="display: flex; align-items: center; gap: 8px;">

                  <span style="font-size: 26px;">${e.icon || '✉️'}</span>

                  <div>

                    <strong style="font-size: 16px; color: var(--text);">${e.name}</strong>

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

              ${e.note ? `<div style="font-size: 11px; color: var(--text-muted); font-style: italic; margin-top: 6px;">💬 ${e.note}</div>` : ''}

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

              <span style="font-size: 13px; font-weight: 600; color: var(--text);">${e.icon || '✉️'} ${e.name}</span>

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

