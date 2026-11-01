"""Append-only audit trail where each entry carries the hash of the one before it (AU-09, AU-10).

Changing, deleting or reordering any entry breaks verify(). The head hash can be anchored
somewhere the platform cannot write (for example an immutable blob) to detect truncation.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

GENESIS = "0" * 64


def _h(prev: str, body: dict) -> str:
    return hashlib.sha256((prev + json.dumps(body, sort_keys=True, separators=(",", ":"))).encode()).hexdigest()


@dataclass(frozen=True)
class Entry:
    seq: int
    at: str
    tenant_id: str
    actor: str
    action: str
    target: str
    detail: dict
    prev: str
    hash: str

    def body(self) -> dict:
        return {"seq": self.seq, "at": self.at, "tenant_id": self.tenant_id, "actor": self.actor,
                "action": self.action, "target": self.target, "detail": self.detail}


class AuditLog:
    def __init__(self) -> None:
        self._entries: list[Entry] = []

    @property
    def head(self) -> str:
        return self._entries[-1].hash if self._entries else GENESIS

    def append(self, at: str, tenant_id: str, actor: str, action: str, target: str, detail: dict | None = None) -> Entry:
        body = {"seq": len(self._entries), "at": at, "tenant_id": tenant_id, "actor": actor, "action": action,
                "target": target, "detail": detail or {}}
        e = Entry(**body, prev=self.head, hash=_h(self.head, body))
        self._entries.append(e)
        return e

    def entries(self, tenant_id: str | None = None) -> list[Entry]:
        return [e for e in self._entries if tenant_id is None or e.tenant_id == tenant_id]

    def verify(self, anchored_head: str | None = None) -> tuple[bool, str]:
        prev = GENESIS
        for i, e in enumerate(self._entries):
            if e.seq != i:
                return False, f"sequence gap at {i}"
            if e.prev != prev:
                return False, f"broken link at seq {i}"
            if _h(prev, e.body()) != e.hash:
                return False, f"entry {i} was modified"
            prev = e.hash
        if anchored_head is not None and anchored_head != prev:
            return False, "head does not match anchor (log truncated or replaced)"
        return True, f"{len(self._entries)} entries verified"

    def to_jsonl(self) -> str:
        return "".join(json.dumps({**e.body(), "prev": e.prev, "hash": e.hash}, sort_keys=True) + "\n"
                       for e in self._entries)

    @classmethod
    def from_jsonl(cls, text: str) -> "AuditLog":
        log = cls()
        for line in text.splitlines():
            d = json.loads(line)
            log._entries.append(Entry(**d))
        return log
