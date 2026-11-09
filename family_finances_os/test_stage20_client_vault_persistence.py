"""
Stage 20 Test: Client-Side Local Database Vault & Vercel Mobile Persistence
Ensures:
1. GET /api/database/export-blob returns valid base64 payload, sha256 checksum, size, and SQLite header.
2. GET /api/database/export-file downloads SQLite binary with attachment header for phone storage.
3. POST /api/database/restore-blob restores SQLite database on empty server (Vercel cold start) without requiring prior session, and issues a session token for the restored owner.
4. POST /api/database/restore-blob requires authentication if owner already exists (dual-gate security).
5. POST /api/database/restore-blob rejects non-SQLite / malformed payloads with HTTP 400.
6. POST /api/database/restore-blob rejects payloads > 20 MB with HTTP 413.
7. Frontend contains LocalDatabaseVault (IndexedDB + localStorage fallback), autoRestoreIfEmpty hook in loadStatus, mutation sync hooks, and UI vault modal.
"""
import io
import json
import base64
import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from family_finances_os.db import init_database, get_connection
from family_finances_os.auth import AuthService, GLOBAL_SESSION_MANAGER
from family_finances_os.ledger import LedgerEngine
from family_finances_os.web_server import FamilyFinancesHandler


class MockSocket:
    def __init__(self, raw_data: bytes):
        self.input_bytes = raw_data
        self.output = bytearray()

    def makefile(self, mode, *args, **kwargs):
        if 'r' in mode:
            return io.BytesIO(self.input_bytes)
        class WriteWrapper:
            def __init__(self, target): self.target = target
            def write(self, b): self.target.extend(b)
            def flush(self): pass
        return WriteWrapper(self.output)

    def sendall(self, b):
        self.output.extend(b)


class TestStage20ClientVaultPersistence(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ffos_s20_")
        self.db_path = Path(self.test_dir) / "family_finances.db"
        init_database(self.db_path)
        self.auth = AuthService(conn_or_path=self.db_path)
        self.owner = self.auth.create_owner("master", "Глава Семьи", "MasterPassword123!")
        self.session_token = GLOBAL_SESSION_MANAGER.create_session(self.owner)

        self.ledger = LedgerEngine(conn_or_path=self.db_path)
        self.ledger.seed_default_chart_of_accounts()
        self.acc = self.ledger.create_account("Наличные", "ASSET", "CASH", "COMMON")

    def _execute_request(self, method: str, path: str, headers: dict = None, body: bytes = b"", custom_db: Path = None):
        headers = headers or {}
        if "Host" not in headers:
            headers["Host"] = "127.0.0.1:8000"
        if body and "Content-Length" not in headers:
            headers["Content-Length"] = str(len(body))

        req_lines = [f"{method} {path} HTTP/1.1"]
        for k, v in headers.items():
            req_lines.append(f"{k}: {v}")
        req_lines.append("")
        req_lines.append("")
        raw_request = "\r\n".join(req_lines).encode("utf-8") + body

        sock = MockSocket(raw_request)

        target_db = custom_db or self.db_path
        with patch("family_finances_os.web_server.DB_PATH", target_db):
            with patch("family_finances_os.config.DB_PATH", target_db):
                handler = FamilyFinancesHandler(sock, ("127.0.0.1", 54321), None)

        output_bytes = sock.output
        header_end = output_bytes.find(b"\r\n\r\n")
        if header_end == -1:
            return 500, {}, b""
        raw_headers = output_bytes[:header_end].decode("utf-8", errors="replace")
        resp_body = output_bytes[header_end + 4:]

        lines = raw_headers.split("\r\n")
        status_line = lines[0]
        status_code = int(status_line.split(" ")[1])

        resp_headers = {}
        for h in lines[1:]:
            if ": " in h:
                k, v = h.split(": ", 1)
                resp_headers[k.lower()] = v

        return status_code, resp_headers, resp_body

    def test_01_export_blob_authenticated(self):
        """GET /api/database/export-blob returns valid base64-encoded SQLite blob."""
        status, headers, body = self._execute_request(
            "GET",
            "/api/database/export-blob",
            headers={"Authorization": f"Bearer {self.session_token}"}
        )
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data.get("status"), "ok")
        self.assertIn("blob_base64", data)
        self.assertIn("sha256", data)
        self.assertIn("size_bytes", data)

        raw_bytes = base64.b64decode(data["blob_base64"])
        self.assertEqual(len(raw_bytes), data["size_bytes"])
        self.assertEqual(hashlib.sha256(raw_bytes).hexdigest(), data["sha256"])
        self.assertTrue(raw_bytes.startswith(b"SQLite format 3\x00") or raw_bytes.startswith(b"FFOS_ENV\x01"))

        # Verify decoded database can be queried
        temp_verify = Path(self.test_dir) / "verify.db"
        temp_verify.write_bytes(raw_bytes)
        conn = sqlite3.connect(str(temp_verify))
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM users;")
        user_count = cur.fetchone()[0]
        conn.close()
        self.assertGreaterEqual(user_count, 1)

    def test_02_export_file_download(self):
        """GET /api/database/export-file downloads SQLite binary file."""
        status, headers, body = self._execute_request(
            "GET",
            "/api/database/export-file",
            headers={"Authorization": f"Bearer {self.session_token}"}
        )
        self.assertEqual(status, 200)
        self.assertIn("content-disposition", headers)
        self.assertIn("attachment", headers["content-disposition"])
        self.assertTrue(body.startswith(b"SQLite format 3\x00") or body.startswith(b"FFOS_ENV\x01"))

    def test_03_restore_blob_unauthenticated_when_no_owner(self):
        """Cold-start restore: when server has no owner, unauthenticated restore-blob succeeds and returns token."""
        # 1. Export valid blob from populated DB
        conn = get_connection(self.db_path)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        conn.close()
        valid_bytes = self.db_path.read_bytes()
        valid_b64 = base64.b64encode(valid_bytes).decode("ascii")
        checksum = hashlib.sha256(valid_bytes).hexdigest()

        # 2. Create clean empty database without owner (simulating Vercel cold-start)
        clean_db = Path(self.test_dir) / "clean_empty.db"
        init_database(clean_db)  # creates schema, but no owner exists

        status, headers, body = self._execute_request(
            "POST",
            "/api/database/restore-blob",
            body=json.dumps({"blob_base64": valid_b64, "sha256": checksum}).encode("utf-8"),
            custom_db=clean_db
        )
        self.assertEqual(status, 200)
        res = json.loads(body.decode("utf-8"))
        self.assertEqual(res.get("status"), "ok")
        self.assertTrue(res.get("restored"))
        self.assertIn("token", res)
        self.assertIsNotNone(res["token"])
        self.assertEqual(res["user"]["username"], "master")

        # Verify clean_db now has the owner
        auth_check = AuthService(conn_or_path=clean_db)
        self.assertTrue(auth_check.has_owner())

    def test_04_restore_blob_requires_auth_when_owner_exists(self):
        """Dual-gate check: when owner exists, unauthenticated restore-blob is rejected with HTTP 401."""
        valid_bytes = self.db_path.read_bytes()
        valid_b64 = base64.b64encode(valid_bytes).decode("ascii")

        # Unauthenticated request to active DB
        status, headers, body = self._execute_request(
            "POST",
            "/api/database/restore-blob",
            body=json.dumps({"blob_base64": valid_b64}).encode("utf-8")
        )
        self.assertEqual(status, 401)

        # Authenticated request to active DB
        status, headers, body = self._execute_request(
            "POST",
            "/api/database/restore-blob",
            headers={"Authorization": f"Bearer {self.session_token}"},
            body=json.dumps({"blob_base64": valid_b64}).encode("utf-8")
        )
        self.assertEqual(status, 200)

    def test_05_restore_blob_rejects_malformed_and_corrupt(self):
        """POST /api/database/restore-blob rejects non-SQLite / corrupted payloads with HTTP 400."""
        # Non-SQLite text
        bad_b64 = base64.b64encode(b"Hello world, not a database at all!").decode("ascii")
        status, headers, body = self._execute_request(
            "POST",
            "/api/database/restore-blob",
            headers={"Authorization": f"Bearer {self.session_token}"},
            body=json.dumps({"blob_base64": bad_b64}).encode("utf-8")
        )
        self.assertEqual(status, 400)
        res = json.loads(body.decode("utf-8"))
        self.assertIn("error", res)

        # Invalid base64 string
        status, headers, body = self._execute_request(
            "POST",
            "/api/database/restore-blob",
            headers={"Authorization": f"Bearer {self.session_token}"},
            body=json.dumps({"blob_base64": "!!!not_base64"}).encode("utf-8")
        )
        self.assertEqual(status, 400)

    def test_06_restore_blob_payload_size_limit(self):
        """POST /api/database/restore-blob rejects payloads > 20 MB with HTTP 413."""
        status, headers, body = self._execute_request(
            "POST",
            "/api/database/restore-blob",
            headers={
                "Authorization": f"Bearer {self.session_token}",
                "Content-Length": str(25 * 1024 * 1024)
            },
            body=b""
        )
        self.assertEqual(status, 413)

    def test_07_frontend_contains_client_vault_and_sync_hooks(self):
        """UI must include LocalDatabaseVault, autoRestoreIfEmpty hook, and mobile vault modal."""
        handler = FamilyFinancesHandler.__new__(FamilyFinancesHandler)
        html = handler._render_app_html()

        # LocalDatabaseVault object in JS
        self.assertIn("LocalDatabaseVault", html)
        self.assertIn("indexedDB", html)
        self.assertIn("autoRestoreIfEmpty", html)
        self.assertIn("syncAfterMutation", html)

        # UI elements
        self.assertIn("localVaultBadge", html)
        self.assertIn("vaultModal", html)
        self.assertIn("/api/database/export-blob", html)
        self.assertIn("/api/database/restore-blob", html)


    def test_08_stateless_session_across_instances(self):
        """Cross-container validation: token created by one SessionManager instance must be valid in another."""
        from family_finances_os.security import SessionManager
        sm1 = SessionManager()
        user_info = {"user_id": "u_test", "username": "admin", "role": "OWNER"}
        token = sm1.create_session(user_info)

        # Simulate fresh Lambda instance with brand new SessionManager instance
        sm2 = SessionManager()
        validated_user = sm2.validate_session(token)
        self.assertIsNotNone(validated_user)
        self.assertEqual(validated_user["username"], "admin")
        self.assertEqual(validated_user["role"], "OWNER")


if __name__ == "__main__":
    unittest.main()
