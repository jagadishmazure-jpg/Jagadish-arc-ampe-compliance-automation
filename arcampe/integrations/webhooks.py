"""Signed webhook receiver: HMAC-SHA256 signature, timestamp tolerance, replay cache, idempotency.

Header format (one header):  X-ArcAmpe-Signature: t=<unix seconds>,v1=<hex hmac>
Signed string:               f"{t}.{raw body}"
A request is accepted once. Re-sending the same signature is a replay (409). Re-sending the same
event id with a new signature is a duplicate delivery and returns the first result (200, no new evidence).
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field

from .schema import CATEGORIES, Evidence, add_step, make, sha256_hex

TOLERANCE_SECONDS = 300
HEADER = "X-ArcAmpe-Signature"


def sign(secret: bytes, body: bytes, ts: int) -> str:
    mac = hmac.new(secret, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def parse_header(h: str) -> tuple[int, list[str]]:
    parts = dict(p.split("=", 1) for p in h.split(",") if "=" in p)
    if "t" not in parts or "v1" not in parts:
        raise ValueError("malformed signature header")
    return int(parts["t"]), [v for k, v in (p.split("=", 1) for p in h.split(",")) if k == "v1"]


@dataclass
class Result:
    status: int
    reason: str
    evidence: Evidence | None = None


@dataclass
class WebhookReceiver:
    tenant_id: str
    secrets: list[bytes]                      # current + previous during rotation
    seen_signatures: dict[str, int] = field(default_factory=dict)
    processed: dict[str, Result] = field(default_factory=dict)
    max_body: int = 256_000

    def _prune(self, now: int) -> None:
        for s, t in list(self.seen_signatures.items()):
            if now - t > 2 * TOLERANCE_SECONDS:
                del self.seen_signatures[s]

    def handle(self, headers: dict, body: bytes, now: int) -> Result:
        if len(body) > self.max_body:
            return Result(413, "body too large")
        h = headers.get(HEADER)
        if not h:
            return Result(401, "missing signature")
        try:
            ts, sigs = parse_header(h)
        except ValueError:
            return Result(400, "malformed signature header")
        if abs(now - ts) > TOLERANCE_SECONDS:
            return Result(401, "timestamp outside tolerance")
        good = any(hmac.compare_digest(sign(s, body, ts).split("v1=")[1], v) for s in self.secrets for v in sigs)
        if not good:
            return Result(401, "bad signature")
        self._prune(now)
        if h in self.seen_signatures:
            return Result(409, "replay")
        self.seen_signatures[h] = ts
        try:
            msg = json.loads(body)
            eid = msg["id"]
        except (ValueError, KeyError):
            return Result(400, "body must be JSON with an id")
        if eid in self.processed:
            first = self.processed[eid]
            return Result(200, "duplicate delivery (idempotent)", first.evidence)
        try:
            ev = self.to_evidence(msg, now, sha256_hex(body))
        except (KeyError, ValueError) as e:
            return Result(422, f"cannot normalize: {e}")
        res = Result(202, "accepted", ev)
        self.processed[eid] = res
        return res

    def to_evidence(self, msg: dict, now: int, body_hash: str) -> Evidence:
        cat = msg.get("category", "webhook")
        if cat not in CATEGORIES:
            raise ValueError(f"unknown category {cat}")
        e = make(self.tenant_id, msg["source"], cat, msg["kind"], msg["subject"], msg["observed_at"],
                 msg.get("attributes", {}), tuple(msg.get("control_hints", ())))
        return add_step(e, "webhook-verify", "webhooks.WebhookReceiver", str(now), body_hash)
