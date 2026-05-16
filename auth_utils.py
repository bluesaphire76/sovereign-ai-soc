from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any


DEFAULT_TOKEN_TTL_SECONDS = int(os.environ.get("AI_SOC_AUTH_TOKEN_TTL_SECONDS", "28800"))
MIN_AUTH_SECRET_LENGTH = 32
DEFAULT_AUTH_SECRET_FILE = ".runtime/auth_secret"


def _read_secret_file(path: Path) -> str | None:
    if not path.exists():
        return None

    value = path.read_text(encoding="utf-8").strip()

    if not value:
        return None

    return value


def _write_secret_file(path: Path, secret: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)

    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(secret)
        handle.write("\n")


def get_auth_secret() -> str:
    configured_secret = os.environ.get("AI_SOC_AUTH_SECRET")

    if configured_secret:
        if len(configured_secret) < MIN_AUTH_SECRET_LENGTH:
            raise RuntimeError(
                "AI_SOC_AUTH_SECRET is too short. Use at least 32 characters."
            )

        return configured_secret

    secret_file = Path(
        os.environ.get("AI_SOC_AUTH_SECRET_FILE", DEFAULT_AUTH_SECRET_FILE)
    )

    file_secret = _read_secret_file(secret_file)

    if file_secret:
        if len(file_secret) < MIN_AUTH_SECRET_LENGTH:
            raise RuntimeError(
                f"Auth secret file {secret_file} contains a value shorter than "
                f"{MIN_AUTH_SECRET_LENGTH} characters."
            )

        return file_secret

    generated_secret = secrets.token_urlsafe(48)
    _write_secret_file(secret_file, generated_secret)

    return generated_secret


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def hash_password(password: str) -> str:
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")

    iterations = 210_000
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    ).hex()

    return f"pbkdf2_sha256${iterations}${salt}${digest}"


def verify_password(password: str, password_hash: str | None) -> bool:
    if not password_hash:
        return False

    try:
        algorithm, iterations_raw, salt, expected_digest = password_hash.split("$", 3)
    except ValueError:
        return False

    if algorithm != "pbkdf2_sha256":
        return False

    try:
        iterations = int(iterations_raw)
    except ValueError:
        return False

    actual_digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    ).hex()

    return hmac.compare_digest(actual_digest, expected_digest)


def create_access_token(
    *,
    user_id: int,
    username: str,
    role: str,
    ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS,
) -> dict[str, Any]:
    now = int(time.time())
    expires_at = now + ttl_seconds

    header = {
        "alg": "HS256",
        "typ": "JWT",
    }

    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": now,
        "exp": expires_at,
    }

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    signature = hmac.new(
        get_auth_secret().encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).digest()

    token = f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"

    return {
        "access_token": token,
        "expires_at": expires_at,
        "token_type": "bearer",
    }


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".", 2)
    except ValueError as exc:
        raise ValueError("Invalid token format.") from exc

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    expected_signature = hmac.new(
        get_auth_secret().encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).digest()

    actual_signature = _b64url_decode(signature_b64)

    if not hmac.compare_digest(actual_signature, expected_signature):
        raise ValueError("Invalid token signature.")

    payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))

    if int(payload.get("exp", 0)) < int(time.time()):
        raise ValueError("Token expired.")

    return payload
