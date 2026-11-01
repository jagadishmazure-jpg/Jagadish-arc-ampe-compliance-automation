"""Auditor area: audit mode that freezes data, evidence sampling and an evidence package with a manifest.

* AuditStore.freeze() turns on audit mode: every write raises AuditModeError, so the population an
  auditor sampled cannot change under them. Unfreeze needs a named person and a reason, and is logged.
* sample_size() follows a common attribute-sampling rule of thumb by control frequency (author's table,
  not a standard's text). sample() is deterministic: the same seed and population give the same picks.
* package() builds a zip with one file per evidence record and manifest.json holding each file's SHA-256;
  verify() re-hashes and lists any mismatch.
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from dataclasses import dataclass, field

from .. import TODAY
from ..platform.audit_log import AuditLog

# frequency -> (minimum sample, maximum sample)
SAMPLE_TABLE = {"annual": (1, 1), "quarterly": (2, 2), "monthly": (2, 3), "weekly": (5, 10), "daily": (20, 40),
                "multiple_daily": (25, 60)}
_FIXED_ZIP_TIME = (2026, 10, 31, 0, 0, 0)


class AuditModeError(RuntimeError):
    pass


@dataclass
class AuditStore:
    data: dict = field(default_factory=dict)
    frozen: bool = False
    frozen_hash: str = ""
    log: AuditLog = field(default_factory=AuditLog)

    def digest(self) -> str:
        return hashlib.sha256(json.dumps(self.data, sort_keys=True, default=str).encode()).hexdigest()

    def put(self, key: str, value, actor: str, at: str = TODAY) -> None:
        if self.frozen:
            self.log.append(at, "lakehaven", actor, "write.refused", key, {"reason": "audit mode"})
            raise AuditModeError(f"audit mode is on: {key} is read-only")
        self.data[key] = value
        self.log.append(at, "lakehaven", actor, "write", key)

    def delete(self, key: str, actor: str, at: str = TODAY) -> None:
        if self.frozen:
            raise AuditModeError(f"audit mode is on: cannot delete {key}")
        self.data.pop(key, None)
        self.log.append(at, "lakehaven", actor, "delete", key)

    def freeze(self, actor: str, at: str = TODAY) -> str:
        self.frozen = True
        self.frozen_hash = self.digest()
        self.log.append(at, "lakehaven", actor, "audit_mode.on", "store", {"sha256": self.frozen_hash})
        return self.frozen_hash

    def unfreeze(self, actor: str, reason: str, at: str = TODAY) -> None:
        if not reason.strip():
            raise ValueError("a reason is required to leave audit mode")
        if actor.startswith("agent:"):
            raise PermissionError("an agent cannot end audit mode")
        self.frozen = False
        self.log.append(at, "lakehaven", actor, "audit_mode.off", "store", {"reason": reason})

    def unchanged_since_freeze(self) -> bool:
        return bool(self.frozen_hash) and self.digest() == self.frozen_hash


def sample_size(frequency: str, population: int) -> int:
    if frequency not in SAMPLE_TABLE:
        raise ValueError(f"unknown frequency {frequency}")
    if population <= 0:
        return 0
    lo, hi = SAMPLE_TABLE[frequency]
    if hi == lo:
        n = lo
    else:  # scale between lo and hi with population, capped
        ref = {"monthly": 12, "weekly": 52, "daily": 250, "multiple_daily": 1000}[frequency]
        n = lo + round((hi - lo) * min(1.0, population / ref))
    return min(population, n)


def sample(population: list[str], n: int, seed: str = "2026-Q4") -> list[str]:
    """Deterministic pseudo-random sample: order by SHA-256(seed + item), take the first n."""
    ranked = sorted(set(population), key=lambda x: hashlib.sha256(f"{seed}|{x}".encode()).hexdigest())
    return sorted(ranked[:n])


def plan(evidence, seed: str = "2026-Q4") -> list[dict]:
    """Sample plan per evidence kind. Frequency is inferred from the kind (author's mapping)."""
    freq = {"account": "daily", "change": "weekly", "pull_request": "weekly", "backup_job": "daily",
            "log_review": "weekly", "training": "annual", "policy_doc": "annual", "hr_event": "monthly",
            "incident": "quarterly", "vendor": "annual", "vuln_scan": "monthly"}
    pops: dict[str, list[str]] = {}
    for e in evidence:
        pops.setdefault(e.kind, []).append(e.evidence_id)
    rows = []
    for kind in sorted(pops):
        f = freq.get(kind, "quarterly")
        n = sample_size(f, len(pops[kind]))
        rows.append({"kind": kind, "frequency": f, "population": len(pops[kind]), "sample": n,
                     "picked": sample(pops[kind], n, seed)})
    return rows


def package(evidence, title: str = "evidence-package") -> bytes:
    buf = io.BytesIO()
    manifest = {"title": title, "files": {}}
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for e in sorted(evidence, key=lambda x: x.evidence_id):
            body = json.dumps(e.to_dict(), sort_keys=True, indent=1).encode()
            name = f"evidence/{e.evidence_id}.json"
            manifest["files"][name] = hashlib.sha256(body).hexdigest()
            z.writestr(zipfile.ZipInfo(name, _FIXED_ZIP_TIME), body)
        z.writestr(zipfile.ZipInfo("manifest.json", _FIXED_ZIP_TIME),
                   json.dumps(manifest, sort_keys=True, indent=1).encode())
    return buf.getvalue()


def verify(blob: bytes) -> list[str]:
    """Return problems (empty list = intact)."""
    z = zipfile.ZipFile(io.BytesIO(blob))
    man = json.loads(z.read("manifest.json"))
    problems = []
    names = set(z.namelist()) - {"manifest.json"}
    for name, h in man["files"].items():
        if name not in names:
            problems.append(f"missing {name}")
        elif hashlib.sha256(z.read(name)).hexdigest() != h:
            problems.append(f"hash mismatch {name}")
    for extra in sorted(names - set(man["files"])):
        problems.append(f"not in manifest {extra}")
    return problems
