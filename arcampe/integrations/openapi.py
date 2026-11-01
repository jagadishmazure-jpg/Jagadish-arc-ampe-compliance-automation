"""OpenAPI-driven generic connector: point it at a spec and a small mapping, no code needed.

The spec's x-arcampe block says which GET operation returns records, where the list lives and how
fields map onto the evidence schema. Offline, the response is the example in the spec itself.
"""
from __future__ import annotations

import json
from collections.abc import Iterator

from .. import DATA
from .sdk import BaseConnector


def _dig(obj, path: str):
    for part in path.split("."):
        if part == "":
            continue
        obj = obj[int(part)] if isinstance(obj, list) else obj[part]
    return obj


class SpecError(ValueError):
    pass


def validate_spec(spec: dict) -> list[str]:
    errs = []
    if not str(spec.get("openapi", "")).startswith("3."):
        errs.append("openapi version must be 3.x")
    x = spec.get("x-arcampe")
    if not x:
        return errs + ["missing x-arcampe mapping"]
    for k in ("operationId", "records", "kind", "subject", "category"):
        if k not in x:
            errs.append(f"x-arcampe.{k} missing")
    ops = {op.get("operationId"): (p, m) for p, item in spec.get("paths", {}).items() for m, op in item.items()}
    if x.get("operationId") not in ops:
        errs.append("operationId not found in paths")
    elif ops[x["operationId"]][1] != "get":
        errs.append("only read-only GET operations are allowed")
    return errs


class OpenAPIConnector(BaseConnector):
    method = "openapi"

    def __init__(self, tenant_id: str, spec: dict, **kw):
        errs = validate_spec(spec)
        if errs:
            raise SpecError("; ".join(errs))
        self.spec = spec
        x = spec["x-arcampe"]
        self.name = x.get("name", spec["info"]["title"].lower().replace(" ", "_"))
        self.category = x["category"]
        self.product = spec["info"]["title"]
        super().__init__(tenant_id, **kw)

    def _operation(self) -> dict:
        for item in self.spec["paths"].values():
            for op in item.values():
                if op.get("operationId") == self.spec["x-arcampe"]["operationId"]:
                    return op
        raise SpecError("operation vanished")

    def fetch(self) -> dict:
        if self._payload is not None:
            return self._payload
        return self._operation()["responses"]["200"]["content"]["application/json"]["example"]

    def records(self, raw) -> Iterator[dict]:
        x = self.spec["x-arcampe"]
        for item in _dig(raw, x["records"]):
            yield {"kind": x["kind"], "subject": str(_dig(item, x["subject"])),
                   "observed_at": str(_dig(item, x["observed_at"])) if "observed_at" in x else self.as_of,
                   "attributes": {k: _dig(item, v) for k, v in x.get("attributes", {}).items()},
                   "control_hints": tuple(x.get("control_hints", ()))}


def load_spec(name: str) -> dict:
    return json.loads((DATA / "openapi" / f"{name}.json").read_text())


def available_specs() -> list[str]:
    return sorted(p.stem for p in (DATA / "openapi").glob("*.json"))
