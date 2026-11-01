"""Tenant-isolated evidence store: every read and write is scoped, encrypted and audited."""
from __future__ import annotations

import json

from .audit_log import AuditLog
from .crypto import KeyRing
from .rbac import AccessDenied, Principal, authorize


class TenantStore:
    def __init__(self, keys: KeyRing | None = None, log: AuditLog | None = None) -> None:
        self.keys = keys or KeyRing()
        self.log = log or AuditLog()
        self._blobs: dict[tuple[str, str], bytes] = {}

    def put(self, p: Principal, tenant_id: str, key: str, value: dict, at: str) -> None:
        authorize(p, "upload_evidence", tenant_id)
        self._blobs[(tenant_id, key)] = self.keys.encrypt(tenant_id, json.dumps(value, sort_keys=True).encode())
        self.log.append(at, tenant_id, p.id, "put", key)

    def get(self, p: Principal, tenant_id: str, key: str, at: str) -> dict:
        try:
            authorize(p, "read", tenant_id)
        except AccessDenied:
            self.log.append(at, p.tenant_id, p.id, "denied_read", f"{tenant_id}/{key}")
            raise
        self.log.append(at, tenant_id, p.id, "get", key)
        return json.loads(self.keys.decrypt(tenant_id, self._blobs[(tenant_id, key)]))

    def keys_for(self, tenant_id: str) -> list[str]:
        return sorted(k for t, k in self._blobs if t == tenant_id)

    def raw(self, tenant_id: str, key: str) -> bytes:
        """Ciphertext as stored (for tests and backups)."""
        return self._blobs[(tenant_id, key)]

    def snapshot(self) -> dict:
        return {f"{t}\x1f{k}": v for (t, k), v in self._blobs.items()}

    def load_snapshot(self, snap: dict) -> None:
        self._blobs = {tuple(k.split("\x1f", 1)): v for k, v in snap.items()}
