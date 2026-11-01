"""One evidence schema for every source, with lineage and a content hash.

Every connector, webhook and OpenAPI feed ends up as Evidence. The content hash covers the
fields that matter (tenant, source, kind, subject, observed date, attributes), so any later
change to the record is detectable. Lineage records each step that touched the record.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, replace

CATEGORIES = ("identity", "cloud", "itsm", "collaboration", "security", "devops", "docs", "hr",
              "finance", "platform", "webhook", "openapi")


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(text: str | bytes) -> str:
    if isinstance(text, str):
        text = text.encode()
    return hashlib.sha256(text).hexdigest()


@dataclass(frozen=True)
class LineageStep:
    step: str          # fetch | normalize | webhook-verify | map | review
    actor: str         # connector or component name
    at: str            # ISO date/time (simulated clock)
    input_sha256: str
    output_sha256: str


@dataclass(frozen=True)
class Evidence:
    tenant_id: str
    source: str
    category: str
    kind: str
    subject: str
    observed_at: str
    attributes: dict
    control_hints: tuple[str, ...] = ()
    lineage: tuple[LineageStep, ...] = ()
    content_sha256: str = ""
    evidence_id: str = ""

    def core(self) -> dict:
        return {"tenant_id": self.tenant_id, "source": self.source, "kind": self.kind,
                "subject": self.subject, "observed_at": self.observed_at, "attributes": self.attributes}

    def to_dict(self) -> dict:
        d = asdict(self)
        d["lineage"] = [asdict(x) for x in self.lineage]
        return d


def make(tenant_id: str, source: str, category: str, kind: str, subject: str, observed_at: str,
         attributes: dict, control_hints=(), lineage=()) -> Evidence:
    if category not in CATEGORIES:
        raise ValueError(f"unknown category {category}")
    if not tenant_id:
        raise ValueError("tenant_id is required")
    e = Evidence(tenant_id, source, category, kind, str(subject), str(observed_at), dict(attributes),
                 tuple(control_hints), tuple(lineage))
    h = sha256_hex(canonical_json(e.core()))
    return replace(e, content_sha256=h, evidence_id=f"ev-{h[:16]}")


def verify(e: Evidence) -> bool:
    """True if the record still matches its hash and its lineage ends at that hash."""
    h = sha256_hex(canonical_json(e.core()))
    if h != e.content_sha256:
        return False
    return not e.lineage or e.lineage[-1].output_sha256 == h


def add_step(e: Evidence, step: str, actor: str, at: str, input_sha256: str) -> Evidence:
    return replace(e, lineage=e.lineage + (LineageStep(step, actor, at, input_sha256, e.content_sha256),))
