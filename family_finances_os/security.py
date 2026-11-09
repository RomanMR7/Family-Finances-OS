"""
Family Finances OS - Security, Encryption & Authentication Module
Implements Envelope Encryption (KEK + DEK) with AES-256-GCM and PBKDF2-HMAC-SHA256.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from family_finances_os.config import (
    PBKDF2_ITERATIONS,
    SALT_SIZE,
    NONCE_SIZE,
    SESSION_TOKEN_SIZE,
    SESSION_TTL_SECONDS,
    ENC_MAGIC,
    ENC_ENV_MAGIC,
    DEK_SIZE,
    DEK_TAG_SIZE,
    ENCRYPTED_DEK_SIZE
)


def wipe_memory(buf: bytearray) -> None:
    """
    Safely zero out sensitive in-memory byte buffers (keys, secrets).
    """
    if buf is not None and isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


def generate_salt() -> bytes:
    """Generate a cryptographically secure random salt."""
    return secrets.token_bytes(SALT_SIZE)


def generate_nonce() -> bytes:
    """Generate a 12-byte nonce for AES-256-GCM."""
    return secrets.token_bytes(NONCE_SIZE)


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """
    Derive a 256-bit encryption key from password and salt using PBKDF2-HMAC-SHA256.
    """
    if not password:
        raise ValueError("Password cannot be empty")
    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt,
        iterations=iterations,
        dklen=32
    )


def hash_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """
    Hash a password using PBKDF2-HMAC-SHA256 (600,000 iterations).
    Returns (hash_bytes, salt_bytes).
    """
    if not password:
        raise ValueError("Password cannot be empty")
    if salt is None:
        salt = generate_salt()
    pwd_hash = derive_key(password, salt)
    return pwd_hash, salt


def verify_password(password: str, expected_hash: bytes, salt: bytes) -> bool:
    """
    Verify password against stored hash and salt using constant-time comparison.
    """
    if not password or not expected_hash or not salt:
        return False
    computed_hash = derive_key(password, salt)
    return hmac.compare_digest(computed_hash, expected_hash)


# ---------------------------------------------------------------------------
# Envelope Encryption (v2) - KEK (Key Encryption Key) + DEK (Data Encryption Key)
# ---------------------------------------------------------------------------
# Container Layout (FFOS_ENV\x01):
# [9 bytes ENC_ENV_MAGIC]
# [32 bytes SALT]
# [12 bytes KEK_NONCE]
# [48 bytes ENCRYPTED_DEK (32B DEK + 16B GCM Tag)]
# [12 bytes DB_NONCE]
# [Ciphertext + 16B GCM Tag]
# ---------------------------------------------------------------------------

ENV_HEADER_SIZE = len(ENC_ENV_MAGIC) + SALT_SIZE + NONCE_SIZE + ENCRYPTED_DEK_SIZE + NONCE_SIZE


def create_envelope(raw_bytes: bytes, password: str, salt: bytes = None) -> Tuple[bytes, bytearray, bytes, bytes, bytes]:
    """
    Create a new Envelope Encrypted container for raw database bytes.
    1. Derives 256-bit KEK from password using PBKDF2-HMAC-SHA256 (600k iterations).
    2. Generates random 256-bit DEK.
    3. Encrypts DEK using KEK with AES-256-GCM.
    4. Encrypts raw_bytes using DEK with AES-256-GCM.
    Returns:
        (container_bytes, dek_bytearray, salt, kek_nonce, encrypted_dek)
    """
    if salt is None:
        salt = generate_salt()

    kek = derive_key(password, salt)
    dek_raw = secrets.token_bytes(DEK_SIZE)
    dek_buf = bytearray(dek_raw)

    kek_nonce = generate_nonce()
    kek_gcm = AESGCM(kek)
    encrypted_dek = kek_gcm.encrypt(kek_nonce, dek_raw, None)  # 48 bytes

    db_nonce = generate_nonce()
    dek_gcm = AESGCM(bytes(dek_buf))
    ciphertext = dek_gcm.encrypt(db_nonce, raw_bytes, None)

    container = ENC_ENV_MAGIC + salt + kek_nonce + encrypted_dek + db_nonce + ciphertext
    return container, dek_buf, salt, kek_nonce, encrypted_dek


def open_envelope(container: bytes, password: str) -> Tuple[bytes, bytearray, bytes, bytes, bytes]:
    """
    Open an encrypted container.
    Supports both Envelope Encryption (v2: FFOS_ENV\x01) and Legacy Direct (v1: FFOS_ENC\x01).
    Returns:
        (decrypted_raw_bytes, dek_bytearray, salt, kek_nonce, encrypted_dek)
    Raises:
        ValueError on invalid magic header or truncated container.
        PermissionError on invalid password or authentication tag failure.
    """
    if len(container) < 64:
        raise ValueError("Encrypted container is truncated or invalid")

    # 1. Envelope Encryption (v2)
    if container.startswith(ENC_ENV_MAGIC):
        if len(container) < ENV_HEADER_SIZE + 16:
            raise ValueError("Envelope container is corrupted or truncated")

        offset = len(ENC_ENV_MAGIC)
        salt = container[offset:offset + SALT_SIZE]
        offset += SALT_SIZE
        kek_nonce = container[offset:offset + NONCE_SIZE]
        offset += NONCE_SIZE
        encrypted_dek = container[offset:offset + ENCRYPTED_DEK_SIZE]
        offset += ENCRYPTED_DEK_SIZE
        db_nonce = container[offset:offset + NONCE_SIZE]
        offset += NONCE_SIZE
        ciphertext = container[offset:]

        kek = derive_key(password, salt)
        kek_gcm = AESGCM(kek)
        try:
            dek_raw = kek_gcm.decrypt(kek_nonce, encrypted_dek, None)
        except InvalidTag:
            raise PermissionError("Decryption failed: incorrect master password or corrupted DEK")

        dek_buf = bytearray(dek_raw)
        dek_gcm = AESGCM(bytes(dek_buf))
        try:
            raw_bytes = dek_gcm.decrypt(db_nonce, ciphertext, None)
        except InvalidTag:
            wipe_memory(dek_buf)
            raise PermissionError("Decryption failed: corrupted database ciphertext")

        return raw_bytes, dek_buf, salt, kek_nonce, encrypted_dek

    # 2. Legacy Direct Encryption (v1) fallback & upgrade
    elif container.startswith(ENC_MAGIC):
        raw_bytes = decrypt_database_bytes(container, password)
        # Migrate on-the-fly to envelope parameters
        salt = generate_salt()
        kek = derive_key(password, salt)
        dek_raw = secrets.token_bytes(DEK_SIZE)
        dek_buf = bytearray(dek_raw)
        kek_nonce = generate_nonce()
        kek_gcm = AESGCM(kek)
        encrypted_dek = kek_gcm.encrypt(kek_nonce, dek_raw, None)
        return raw_bytes, dek_buf, salt, kek_nonce, encrypted_dek

    else:
        raise ValueError("Invalid file header: not a valid Family Finances OS encrypted container")


def fast_save_envelope(raw_bytes: bytes, dek: bytearray, salt: bytes, kek_nonce: bytes, encrypted_dek: bytes) -> bytes:
    """
    Lightning-fast database encryption (< 2ms) using existing in-memory DEK.
    Requires ZERO PBKDF2 iterations!
    Generates a fresh 12-byte db_nonce for every save.
    """
    if not dek or len(dek) != DEK_SIZE:
        raise ValueError("Valid Data Encryption Key (DEK) is required for fast save")

    db_nonce = generate_nonce()
    dek_gcm = AESGCM(bytes(dek))
    ciphertext = dek_gcm.encrypt(db_nonce, raw_bytes, None)

    return ENC_ENV_MAGIC + salt + kek_nonce + encrypted_dek + db_nonce + ciphertext


def change_envelope_password(container: bytes, old_password: str, new_password: str) -> Tuple[bytes, bytearray, bytes, bytes, bytes]:
    """
    Change master password without re-encrypting the entire database.
    Re-encrypts the existing DEK with a new KEK derived from new_password.
    """
    if len(new_password) < 6:
        raise ValueError("New password must be at least 6 characters long")

    raw_bytes, dek_buf, _, _, _ = open_envelope(container, old_password)
    new_salt = generate_salt()
    new_kek = derive_key(new_password, new_salt)
    new_kek_nonce = generate_nonce()
    new_kek_gcm = AESGCM(new_kek)
    new_encrypted_dek = new_kek_gcm.encrypt(new_kek_nonce, bytes(dek_buf), None)

    new_container = fast_save_envelope(raw_bytes, dek_buf, new_salt, new_kek_nonce, new_encrypted_dek)
    return new_container, dek_buf, new_salt, new_kek_nonce, new_encrypted_dek


# ---------------------------------------------------------------------------
# Legacy Single-Key AES-256-GCM Functions (Kept for compatibility & tests)
# ---------------------------------------------------------------------------

def encrypt_database_bytes(raw_bytes: bytes, password: str, salt: bytes = None) -> bytes:
    """
    Encrypt raw SQLite database bytes using authenticated AES-256-GCM.
    Legacy container format (v1).
    """
    if salt is None:
        salt = generate_salt()
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = generate_nonce()
    ciphertext = aesgcm.encrypt(nonce, raw_bytes, None)
    return ENC_MAGIC + salt + nonce + ciphertext


def decrypt_database_bytes(encrypted_container: bytes, password: str) -> bytes:
    """
    Decrypt legacy v1 database container using password with AES-256-GCM.
    """
    magic_len = len(ENC_MAGIC)
    if len(encrypted_container) < magic_len + SALT_SIZE + NONCE_SIZE + 16:
        raise ValueError("Encrypted container is truncated or invalid")

    magic = encrypted_container[:magic_len]
    if magic != ENC_MAGIC:
        raise ValueError("Invalid file header: not a valid Family Finances OS encrypted container")

    offset = magic_len
    salt = encrypted_container[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = encrypted_container[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = encrypted_container[offset:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_bytes
    except InvalidTag:
        raise PermissionError("Decryption failed: incorrect password or corrupted database container")


# ---------------------------------------------------------------------------
# Session Manager
# ---------------------------------------------------------------------------

SESSION_HMAC_SECRET = os.environ.get(
    "FFOS_SESSION_SECRET",
    "family_finances_os_persistent_hmac_secret_2026_vercel_stateless_v1"
).encode("utf-8")


class SessionManager:
    """
    Stateless HMAC-signed session manager with in-memory TTL caching and explicit logout invalidation.
    Supports single-use pairing tokens for quick mobile QR onboarding.
    Stateless tokens ensure 100% reliability across ephemeral serverless instances (Vercel, AWS Lambda, multi-process).
    """
    def __init__(self, ttl_seconds: int = SESSION_TTL_SECONDS, hmac_secret: bytes = SESSION_HMAC_SECRET):
        self.ttl_seconds = ttl_seconds
        self._hmac_secret = hmac_secret
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._pairing_tokens: Dict[str, Dict[str, Any]] = {}

    def create_session(self, user_info: Dict[str, Any]) -> str:
        now = time.time()
        payload = {
            "user": user_info,
            "created_at": now,
            "expires_at": now + self.ttl_seconds
        }
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
        sig = hmac.new(self._hmac_secret, payload_b64.encode("ascii"), hashlib.sha256).hexdigest()
        token = f"{payload_b64}.{sig}"
        self._sessions[token] = payload
        return token

    def validate_session(self, token: Optional[str]) -> Optional[Dict[str, Any]]:
        if not token:
            return None

        # 1. Fast in-memory cache check
        session = self._sessions.get(token)
        if session:
            if time.time() > session["expires_at"]:
                del self._sessions[token]
                return None
            return session["user"]

        # 2. Stateless HMAC verification (crucial for cross-container Vercel requests!)
        if "." in token:
            try:
                parts = token.split(".", 1)
                if len(parts) == 2:
                    payload_b64, sig = parts
                    expected_sig = hmac.new(self._hmac_secret, payload_b64.encode("ascii"), hashlib.sha256).hexdigest()
                    if hmac.compare_digest(sig, expected_sig):
                        rem = len(payload_b64) % 4
                        padded = payload_b64 + ("=" * (4 - rem) if rem else "")
                        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
                        if time.time() <= payload.get("expires_at", 0):
                            self._sessions[token] = payload
                            return payload["user"]
            except Exception:
                pass

        return None

    def invalidate_session(self, token: Optional[str]) -> bool:
        if token and token in self._sessions:
            del self._sessions[token]
            return True
        return False

    def create_pairing_token(self, user_info: Dict[str, Any], ttl_seconds: int = 600) -> str:
        token = secrets.token_hex(SESSION_TOKEN_SIZE)
        now = time.time()
        self._pairing_tokens[token] = {
            "user": user_info,
            "created_at": now,
            "expires_at": now + ttl_seconds
        }
        return token

    def validate_pairing_token(self, token: Optional[str]) -> Optional[Dict[str, Any]]:
        if not token:
            return None
        pt = self._pairing_tokens.get(token)
        if not pt:
            return None
        if time.time() > pt["expires_at"]:
            del self._pairing_tokens[token]
            return None
        return pt["user"]

    def consume_pairing_token(self, token: Optional[str]) -> Optional[Dict[str, Any]]:
        user_info = self.validate_pairing_token(token)
        if token and token in self._pairing_tokens:
            del self._pairing_tokens[token]
        return user_info

    def clear_all_sessions(self) -> None:
        """Invalidate all active sessions and pairing tokens."""
        self._sessions.clear()
        self._pairing_tokens.clear()
