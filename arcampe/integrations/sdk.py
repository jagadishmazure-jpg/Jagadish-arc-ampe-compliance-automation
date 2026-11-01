"""Native connector SDK. Subclass BaseConnector, point it at a payload, write normalize().

Connectors in this repo read offline fixtures only. A connector never opens a network socket;
fetch() is the single place that would call a real API, and here it reads data/fixtures/.
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Iterator

from .. import DATA, TODAY
from .schema import Evidence, add_step, canonical_json, make, sha256_hex


class NetworkDisabled(RuntimeError):
    pass


class BaseConnector(ABC):
    name: str = ""
    category: str = ""
    method: str = "native-sdk"
    product: str = ""          # the technology the real connector would talk to
    read_only_scopes: tuple[str, ...] = ()

    def __init__(self, tenant_id: str, payload: dict | None = None, as_of: str = TODAY):
        self.tenant_id = tenant_id
        self._payload = payload
        self.as_of = as_of

    def fetch(self) -> dict:
        if self._payload is not None:
            return self._payload
        path = DATA / "fixtures" / "connectors" / f"{self.name}.json"
        return json.loads(path.read_text())

    def call_api(self, *_a, **_k):  # pragma: no cover - guard only
        raise NetworkDisabled(f"{self.name}: live API calls are disabled in this repo")

    @abstractmethod
    def records(self, raw: dict) -> Iterator[dict]:
        """Yield dicts with kind, subject, observed_at, attributes, control_hints."""

    def collect(self) -> list[Evidence]:
        raw = self.fetch()
        raw_hash = sha256_hex(canonical_json(raw))
        out = []
        for rec in self.records(raw):
            e = make(self.tenant_id, self.name, self.category, rec["kind"], rec["subject"],
                     rec.get("observed_at", self.as_of), rec.get("attributes", {}), rec.get("control_hints", ()))
            e = add_step(e, "fetch", self.name, self.as_of, raw_hash)
            e = add_step(e, "normalize", f"{self.name}.records", self.as_of, sha256_hex(canonical_json(rec)))
            out.append(e)
        return out
