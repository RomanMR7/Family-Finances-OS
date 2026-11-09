import os
import sys
import urllib.parse
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Flag Vercel runtime
os.environ["VERCEL"] = "1"

from family_finances_os.config import DB_PATH, DATA_DIR, ENC_DB_PATH
from family_finances_os.db import init_database
from family_finances_os.web_server import FamilyFinancesHandler, GLOBAL_STORAGE

_initialized = False

def _ensure_initialized():
    global _initialized
    if not _initialized:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            if not DB_PATH.exists():
                init_database(DB_PATH)
            if GLOBAL_STORAGE.exists() and not GLOBAL_STORAGE.is_unlocked():
                try:
                    GLOBAL_STORAGE.open("Family2026!")
                except Exception:
                    pass
            _initialized = True
        except Exception as e:
            print(f"[Vercel Init Error]: {e}", file=sys.stderr)


class handler(FamilyFinancesHandler):
    """Vercel Serverless Function entry point bridging to FamilyFinancesHandler."""

    def _normalize_vercel_path(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        if "__url" in qs and qs["__url"]:
            self.path = qs["__url"][0]
        elif "x-forwarded-uri" in self.headers:
            self.path = self.headers["x-forwarded-uri"]
        elif "x-real-path" in self.headers:
            self.path = self.headers["x-real-path"]

    def do_GET(self):
        _ensure_initialized()
        self._normalize_vercel_path()
        return super().do_GET()

    def do_POST(self):
        _ensure_initialized()
        self._normalize_vercel_path()
        return super().do_POST()
