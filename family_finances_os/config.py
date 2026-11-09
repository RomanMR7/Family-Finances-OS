"""
Family Finances OS - Configuration Module
"""
import os
import tempfile
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).resolve().parent
if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    DATA_DIR = Path(tempfile.gettempdir()) / "family_finances_data"
else:
    DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "family_finances.db"
ENC_DB_PATH = DATA_DIR / "family_finances.db.enc"

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Application constants
APP_NAME = "Family Finances OS"
APP_VERSION = "0.2.0-alpha"

# Security constants
# OWASP 2024 recommendation for PBKDF2-HMAC-SHA256: 600,000 iterations
PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 32
NONCE_SIZE = 12  # Standard for AES-GCM
SESSION_TOKEN_SIZE = 32
SESSION_TTL_SECONDS = 86400  # 24 hours

# Magic bytes for encrypted database container headers
ENC_MAGIC = b"FFOS_ENC\x01"         # Legacy direct AES-256-GCM container
ENC_ENV_MAGIC = b"FFOS_ENV\x01"     # Envelope Encryption container (v2)

# Envelope encryption parameters
DEK_SIZE = 32                      # 256-bit AES Data Encryption Key
DEK_TAG_SIZE = 16                  # 128-bit GCM tag
ENCRYPTED_DEK_SIZE = 48            # DEK_SIZE + DEK_TAG_SIZE

# Strict encryption mode (when True, refuses to create or read plaintext databases)
STRICT_ENCRYPTION = False

# Default currency
DEFAULT_CURRENCY = "RUB"
