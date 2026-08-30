"""Loot encryption at rest (Fernet / AES-128-CBC+HMAC).

Key resolution order:
  1. AEGIS_LOOT_KEY environment variable (urlsafe base64, 32 bytes)
  2. auto-generated key file at <workspace>/.aegis-loot.key (chmod 600)

If the `cryptography` package is missing, encryption degrades to a warning
and plaintext — the CLI surfaces this loudly at session start.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

try:
    from cryptography.fernet import Fernet, InvalidToken
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

PREFIX = "enc:v1:"


class LootCipher:
    def __init__(self, workspace: str | Path = "."):
        self.fernet = None
        self.error = ""
        if not _HAS_CRYPTO:
            self.error = "cryptography package not installed — loot NOT encrypted"
            return
        key = os.environ.get("AEGIS_LOOT_KEY", "")
        key_file = Path(workspace) / ".aegis-loot.key"
        if not key and key_file.exists():
            key = key_file.read_text(encoding="utf-8").strip()
        if not key:
            key = Fernet.generate_key().decode()
            key_file.write_text(key, encoding="utf-8")
            try:
                key_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
        try:
            self.fernet = Fernet(key.encode() if isinstance(key, str) else key)
        except (ValueError, TypeError) as exc:
            self.error = f"invalid loot key: {exc}"

    @property
    def active(self) -> bool:
        return self.fernet is not None

    def encrypt(self, value: str) -> str:
        if not self.fernet or not value:
            return value
        return PREFIX + self.fernet.encrypt(value.encode()).decode()

    def decrypt(self, value: str) -> str:
        if not value or not value.startswith(PREFIX):
            return value
        if not self.fernet:
            return "<encrypted: key unavailable>"
        try:
            return self.fernet.decrypt(value[len(PREFIX):].encode()).decode()
        except InvalidToken:
            return "<encrypted: wrong key>"

    @staticmethod
    def mask(value: str) -> str:
        """Redacted display form for reports."""
        if not value:
            return ""
        tail = value[-4:] if len(value) >= 4 else value
        return f"••••••{tail}"
