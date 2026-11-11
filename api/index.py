"""Vercel serves the public project page without loading financial storage."""
import sys
from pathlib import Path
root=Path(__file__).resolve().parent.parent
if str(root) not in sys.path:
    sys.path.insert(0,str(root))
from family_finances_os.hosted import handler as PublicHandler


class handler(PublicHandler):
    """Explicit entry point for Vercel's static Python handler discovery."""

    pass
