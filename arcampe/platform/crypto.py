"""Encryption at rest with per-tenant keys (envelope encryption) and an in-transit policy check.

Each tenant gets its own 256-bit data key, wrapped by a key-encryption key (KEK). In Azure the KEK
would live in Key Vault Managed HSM; here it is generated in memory for the demo. The tenant id is
bound as AES-GCM associated data, so a blob from one tenant cannot be decrypted as another tenant's.
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

TLS_MIN = (1, 2)
ALLOWED_CIPHER_PREFIXES = ("TLS_AES_", "TLS_CHACHA20_", "ECDHE-")


class KeyRing:
    def __init__(self, kek: bytes | None = None) -> None:
        self._kek = kek or AESGCM.generate_key(bit_length=256)
        self._wrapped: dict[str, bytes] = {}

    def wrapped_key(self, tenant_id: str) -> bytes:
        if tenant_id not in self._wrapped:
            self._wrapped[tenant_id] = aes_key_wrap(self._kek, AESGCM.generate_key(bit_length=256))
        return self._wrapped[tenant_id]

    def _dek(self, tenant_id: str) -> bytes:
        return aes_key_unwrap(self._kek, self.wrapped_key(tenant_id))

    def encrypt(self, tenant_id: str, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + AESGCM(self._dek(tenant_id)).encrypt(nonce, plaintext, tenant_id.encode())

    def decrypt(self, tenant_id: str, blob: bytes) -> bytes:
        return AESGCM(self._dek(tenant_id)).decrypt(blob[:12], blob[12:], tenant_id.encode())

    def rotate_kek(self, new_kek: bytes | None = None) -> None:
        """Re-wrap every tenant data key under a new KEK; stored ciphertext is untouched."""
        new = new_kek or AESGCM.generate_key(bit_length=256)
        self._wrapped = {t: aes_key_wrap(new, aes_key_unwrap(self._kek, w)) for t, w in self._wrapped.items()}
        self._kek = new


def transit_policy_ok(endpoint: dict) -> tuple[bool, str]:
    """endpoint: {"scheme": "https", "min_tls": "1.2", "ciphers": [...]}"""
    if endpoint.get("scheme") != "https":
        return False, "not HTTPS"
    major, minor = (int(x) for x in str(endpoint.get("min_tls", "1.0")).split("."))
    if (major, minor) < TLS_MIN:
        return False, f"TLS {major}.{minor} below 1.2"
    weak = [c for c in endpoint.get("ciphers", []) if not c.startswith(ALLOWED_CIPHER_PREFIXES)]
    return (not weak, "ok" if not weak else f"weak ciphers {weak}")
