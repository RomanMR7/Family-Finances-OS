"""
Family Finances OS - Stage 8 Comprehensive Verification Test Suite
Tests all requirements of Stage 8 (Variant 3):
1. Progressive Web App (PWA): Web App Manifest (/manifest.json) validation.
2. Progressive Web App (PWA): Service Worker (/sw.js) lifecycle & Cache-First/Network-First rules.
3. Vector App Icon (/icon.svg) rendering.
4. Pure Python QR Generator Engine (ISO/IEC 18004 SVG rendering & ECC levels).
5. LAN IP Cascade Resolution (FFOS_EXTERNAL_HOST -> Host Header -> Probe).
6. Authenticated QR Device Pairing Endpoint (/api/device/qr-pair) with IP override.
7. QR Single-Use Pairing Handshake (/api/auth/pair-login) & Auto-Authentication.
8. Production Docker Architecture: Dockerfile, docker-compose.yml, volume persistence, non-root user.
"""
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from family_finances_os.db import init_database, get_connection
from family_finances_os.auth import AuthService, GLOBAL_SESSION_MANAGER
from family_finances_os.qr import QRCode, generate_qr_svg
from family_finances_os.web_server import (
    FamilyFinancesHandler,
    resolve_external_host,
    get_lan_ip_candidates
)


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


class TestStage8PwaQrDocker(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ffos_s8_")
        self.db_path = Path(self.test_dir) / "test_stage8.db"
        init_database(self.db_path)
        self.conn = get_connection(self.db_path)
        self.auth = AuthService(conn_or_path=self.conn)
        self.owner = self.auth.create_owner("owner_s8", "Глава семьи", "masterPass123!")
        self.token = GLOBAL_SESSION_MANAGER.create_session(self.owner)

    def tearDown(self):
        GLOBAL_SESSION_MANAGER.clear_all_sessions()
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _execute_request(self, method: str, path: str, body: dict = None, headers: dict = None):
        """Simulates an HTTP request against FamilyFinancesHandler."""
        body_bytes = json.dumps(body).encode("utf-8") if body is not None else b""
        req_lines = [f"{method} {path} HTTP/1.1", "Host: localhost:8000"]
        if body_bytes:
            req_lines.append(f"Content-Length: {len(body_bytes)}")
            req_lines.append("Content-Type: application/json")
        if headers:
            for k, v in headers.items():
                req_lines.append(f"{k}: {v}")
        req_lines.append("")
        req_lines.append("")
        raw_req = "\r\n".join(req_lines).encode("utf-8") + body_bytes

        mock_sock = MockSocket(raw_req)

        class MockServer:
            server_port = 8000

        class DummyHandler(FamilyFinancesHandler):
            def __init__(self, request, client_address, server):
                self.request = request
                self.client_address = client_address
                self.server = server
                self.setup()
                try:
                    self.handle()
                finally:
                    self.finish()

            def finish(self):
                pass

        DummyHandler(mock_sock, ("127.0.0.1", 54321), MockServer())

        resp_bytes = bytes(mock_sock.output)
        parts = resp_bytes.split(b"\r\n\r\n", 1)
        header_text = parts[0].decode("utf-8", errors="replace")
        status_line = header_text.splitlines()[0] if header_text else ""
        status_code = int(status_line.split()[1]) if len(status_line.split()) >= 2 else 500
        resp_body = parts[1] if len(parts) > 1 else b""
        return status_code, header_text, resp_body

    def test_01_manifest_json_endpoint(self):
        """PWA: GET /manifest.json returns valid schema with required fields."""
        status, headers, body = self._execute_request("GET", "/manifest.json")
        self.assertEqual(status, 200)
        self.assertIn("application/manifest+json", headers)

        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["name"], "Family Finances OS")
        self.assertIn("Финансы", data["short_name"])
        self.assertEqual(data["display"], "standalone")
        self.assertEqual(data["start_url"], "/")
        self.assertEqual(data["background_color"], "#0b1120")
        self.assertEqual(data["theme_color"], "#0b1120")
        self.assertIsInstance(data["icons"], list)
        self.assertGreaterEqual(len(data["icons"]), 1)
        self.assertEqual(data["icons"][0]["src"], "/icon.svg")

    def test_02_service_worker_endpoint(self):
        """PWA: GET /sw.js returns Service Worker with cache shell & API network isolation."""
        status, headers, body = self._execute_request("GET", "/sw.js")
        self.assertEqual(status, 200)
        self.assertIn("application/javascript", headers)

        sw_text = body.decode("utf-8")
        self.assertIn("addEventListener('install'", sw_text)
        self.assertIn("addEventListener('activate'", sw_text)
        self.assertIn("addEventListener('fetch'", sw_text)
        # Verify precache shell includes root and manifest
        self.assertIn("'/manifest.json'", sw_text)
        self.assertIn("'/icon.svg'", sw_text)
        # CRITICAL INVARIANT: Verify /api/ is isolated from Cache-First
        self.assertIn("url.pathname.startsWith('/api/')", sw_text)

    def test_03_app_icon_svg_endpoint(self):
        """PWA: GET /icon.svg returns crisp vector SVG application icon."""
        status, headers, body = self._execute_request("GET", "/icon.svg")
        self.assertEqual(status, 200)
        self.assertIn("image/svg+xml", headers)

        svg_text = body.decode("utf-8")
        self.assertIn("<svg", svg_text)
        self.assertIn("viewBox=\"0 0 512 512\"", svg_text)
        self.assertIn("₽", svg_text)

    def test_04_pure_python_qr_code_generator(self):
        """QR Engine: Pure-Python QR generator ISO/IEC 18004 rendering."""
        # Short URL
        qr1 = QRCode("http://192.168.1.50:8000")
        svg1 = qr1.to_svg()
        self.assertIn("<svg", svg1)
        self.assertIn("<path", svg1)
        self.assertIn("<rect", svg1)
        self.assertGreater(qr1.size, 20)

        # Longer URL with pairing token (~55 chars)
        long_url = "http://192.168.1.100:8000/?pair_token=abcd1234efgh5678ijkl9012"
        qr2 = QRCode(long_url, ecc="M")
        self.assertGreaterEqual(qr2.version, 3)
        svg2 = qr2.to_svg(box_size=10, border=4)
        self.assertIn("viewBox=\"0 0", svg2)
        self.assertIn("shape-rendering=\"crispEdges\"", svg2)

    def test_05_lan_host_resolution_cascade(self):
        """LAN: External host cascade resolution logic."""
        # 1. Environment variable override
        os.environ["FFOS_EXTERNAL_HOST"] = "192.168.1.200"
        try:
            res_env = resolve_external_host({}, fallback_host="127.0.0.1")
            self.assertEqual(res_env, "192.168.1.200")
        finally:
            del os.environ["FFOS_EXTERNAL_HOST"]

        # 2. Incoming Host header (if not localhost)
        headers = {"Host": "192.168.1.88:8000"}
        res_header = resolve_external_host(headers, fallback_host="127.0.0.1")
        self.assertEqual(res_header, "192.168.1.88")

        # 3. Docker internal IP (172.x) should be filtered out
        docker_headers = {"Host": "172.18.0.2:8000"}
        res_docker = resolve_external_host(docker_headers, fallback_host="127.0.0.1")
        self.assertNotEqual(res_docker, "172.18.0.2")

    def test_06_qr_device_pairing_endpoint(self):
        """API: GET /api/device/qr-pair generates valid pairing payload and SVG."""
        # Unauthenticated request must be rejected (401)
        status_unauth, _, _ = self._execute_request("GET", "/api/device/qr-pair")
        self.assertEqual(status_unauth, 401)

        # Authenticated request
        headers = {"Authorization": f"Bearer {self.token}"}
        status, _, body = self._execute_request("GET", "/api/device/qr-pair?override_ip=192.168.1.77", headers=headers)
        self.assertEqual(status, 200)

        data = json.loads(body.decode("utf-8"))
        self.assertTrue(data["ok"])
        self.assertEqual(data["lan_ip"], "192.168.1.77")
        self.assertIn("192.168.1.77:8000", data["pair_url"])
        self.assertIn("pair_token=", data["pair_url"])
        self.assertIn("<svg", data["qr_svg"])
        self.assertEqual(data["expires_in"], 600)
        self.assertTrue(len(data["token"]) >= 16)

    def test_07_qr_pair_login_handshake(self):
        """Auth: POST /api/auth/pair-login validates and consumes pairing token single-use."""
        # 1. Create pairing token
        pairing_token = GLOBAL_SESSION_MANAGER.create_pairing_token(self.owner, ttl_seconds=600)

        # 2. Pair login with valid token
        body = {"token": pairing_token}
        status, _, resp_body = self._execute_request("POST", "/api/auth/pair-login", body=body)
        self.assertEqual(status, 200)

        data = json.loads(resp_body.decode("utf-8"))
        self.assertEqual(data["status"], "ok")
        new_session_token = data["session_token"]
        self.assertTrue(len(new_session_token) >= 32)
        self.assertEqual(data["user"]["username"], "owner_s8")

        # 3. Single-use invariant: reuse must be rejected (401)
        status_reuse, _, resp_reuse = self._execute_request("POST", "/api/auth/pair-login", body=body)
        self.assertEqual(status_reuse, 401)

        # 4. Invalid token rejected
        status_bad, _, _ = self._execute_request("POST", "/api/auth/pair-login", body={"token": "nonexistent_token"})
        self.assertEqual(status_bad, 401)

    def test_08_docker_artifacts_verification(self):
        """Docker: Verify Dockerfile, docker-compose.yml and deployment scripts."""
        root = Path(__file__).resolve().parent.parent

        # 1. Dockerfile
        dockerfile_path = root / "Dockerfile"
        self.assertTrue(dockerfile_path.exists(), "Dockerfile must exist")
        df_content = dockerfile_path.read_text(encoding="utf-8")
        self.assertIn("FROM python:3.12-slim", df_content)
        self.assertIn("useradd", df_content)
        self.assertIn("appuser", df_content)
        self.assertIn("EXPOSE 8000/tcp", df_content)
        self.assertIn("EXPOSE 41234/udp", df_content)
        self.assertIn("HEALTHCHECK", df_content)

        # 2. docker-compose.yml
        compose_path = root / "docker-compose.yml"
        self.assertTrue(compose_path.exists(), "docker-compose.yml must exist")
        compose_content = compose_path.read_text(encoding="utf-8")
        self.assertIn("8000:8000", compose_content)
        self.assertIn("41234:41234/udp", compose_content)
        self.assertIn("./family_finances_os/data:/app/family_finances_os/data", compose_content)

        # 3. requirements.txt
        req_path = root / "requirements.txt"
        self.assertTrue(req_path.exists(), "requirements.txt must exist")
        self.assertIn("cryptography", req_path.read_text(encoding="utf-8"))

        # 4. Launch scripts
        self.assertTrue((root / "start_docker.bat").exists())
        self.assertTrue((root / "start_docker.sh").exists())

    def test_09_rendered_html_javascript_syntax_integrity(self):
        """Frontend QA Guard: Parse embedded JS in HTML & Service Worker for syntax and delimiter integrity."""
        import re

        # 1. Render HTML
        html = FamilyFinancesHandler._render_app_html(None)
        self.assertTrue(html.startswith("<!DOCTYPE html>"), "HTML must have standard doctype")

        # 2. Extract embedded script blocks
        scripts = re.findall(r'<script>(.*?)</script>', html, re.DOTALL)
        self.assertGreaterEqual(len(scripts), 1, "HTML must contain at least one <script> block")

        for s_idx, script in enumerate(scripts):
            lines = script.split("\n")
            in_single = False
            in_double = False
            in_backtick = False
            escaped = False
            paren_depth = 0
            brace_depth = 0
            bracket_depth = 0

            for l_num, line in enumerate(lines, 1):
                i = 0
                while i < len(line):
                    ch = line[i]
                    if escaped:
                        escaped = False
                        i += 1
                        continue
                    if ch == '\\':
                        escaped = True
                        i += 1
                        continue

                    if not in_single and not in_double and not in_backtick:
                        # Check comment
                        if ch == '/' and i + 1 < len(line) and line[i + 1] == '/':
                            break
                        if ch == '(': paren_depth += 1
                        elif ch == ')': paren_depth -= 1
                        elif ch == '{': brace_depth += 1
                        elif ch == '}': brace_depth -= 1
                        elif ch == '[': bracket_depth += 1
                        elif ch == ']': bracket_depth -= 1
                        elif ch == '"': in_double = True
                        elif ch == "'": in_single = True
                        elif ch == '`': in_backtick = True
                    elif in_double:
                        if ch == '"': in_double = False
                    elif in_single:
                        if ch == "'": in_single = False
                    elif in_backtick:
                        if ch == '`': in_backtick = False
                    i += 1

                # CRITICAL INVARIANT: Single/double quotes must not span newlines unescaped
                self.assertFalse(
                    in_single,
                    f"Script {s_idx+1}: Unterminated single quote literal across newline at line {l_num}: {line.strip()}"
                )
                self.assertFalse(
                    in_double,
                    f"Script {s_idx+1}: Unterminated double quote literal across newline at line {l_num}: {line.strip()}"
                )

            # Assert complete delimiter balancing
            self.assertEqual(paren_depth, 0, f"Script {s_idx+1}: Unbalanced parentheses ()")
            self.assertEqual(brace_depth, 0, f"Script {s_idx+1}: Unbalanced curly braces {{}}")
            self.assertEqual(bracket_depth, 0, f"Script {s_idx+1}: Unbalanced brackets []")
            self.assertFalse(in_backtick, f"Script {s_idx+1}: Unterminated backtick template literal")

        # 3. Verify critical entrypoint functions and UX helpers exist
        full_js = "\n".join(scripts)
        required_identifiers = [
            "DOMContentLoaded",
            "loadStatus",
            "togglePasswordVisibility",
            "submitUnlock",
            "submitSetup",
            "submitLogin",
            "loadDashboard",
            "triggerLanSync"
        ]
        for ident in required_identifiers:
            self.assertIn(ident, full_js, f"Required JS function/identifier '{ident}' missing in client script")

        # 4. Verify all HTML event handlers correspond to existing JS declarations
        events = re.findall(r'on[a-z]+="([^"]+)"', html)
        for ev in events:
            called = re.findall(r'([a-zA-Z0-9_]+)\s*\(', ev)
            for fn in called:
                if fn in ('alert', 'confirm', 'prompt', 'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval', 'getElementById', 'add', 'if'):
                    continue
                pattern = r'\b(?:function\s+' + fn + r'|(?:const|let|var)\s+' + fn + r'\s*=)\b'
                self.assertTrue(
                    re.search(pattern, full_js),
                    f"HTML event handler calls undefined JS function: {fn}() in '{ev}'"
                )



if __name__ == "__main__":
    unittest.main()
