"""Custom risk module builder: define a risk module in YAML, validate it, run it.

Required keys: name, scale, appetite, assets, threats, scenarios. Optional: treatments, description.
The bundled cyber module (data/risk/modules/cyber.yaml) uses the same format.
"""
from __future__ import annotations

import pathlib

import yaml

from .. import DATA, catalog

REQUIRED = ("name", "scale", "appetite", "assets", "threats", "scenarios")
DECISIONS = ("mitigate", "transfer", "accept", "avoid")


class ModuleError(ValueError):
    pass


def validate(m: dict) -> list[str]:
    errs = [f"missing {k}" for k in REQUIRED if k not in m]
    if errs:
        return errs
    ids = catalog.by_id()
    assets = {a["id"] for a in m["assets"]}
    threats = {t["id"]: t for t in m["threats"]}
    L, I = m["scale"]["likelihood"], m["scale"]["impact"]
    for t in m["threats"]:
        for c in t.get("controls", []):
            if c not in ids:
                errs.append(f"{t['id']}: unknown control {c}")
        lo, ml, hi = t["tef"]
        if not lo <= ml <= hi:
            errs.append(f"{t['id']}: tef must be min<=ml<=max")
        lo, ml, hi = t["loss_usd"]
        if not 0 <= lo <= ml <= hi:
            errs.append(f"{t['id']}: loss must be 0<=min<=ml<=max")
        if not 0 <= t["vuln"] <= 1:
            errs.append(f"{t['id']}: vuln must be a probability")
    for s in m["scenarios"]:
        if s["asset"] not in assets:
            errs.append(f"{s['id']}: unknown asset {s['asset']}")
        if s["threat"] not in threats:
            errs.append(f"{s['id']}: unknown threat {s['threat']}")
        if not (1 <= s["likelihood"] <= L and 1 <= s["impact"] <= I):
            errs.append(f"{s['id']}: score outside scale")
    sids = {s["id"] for s in m["scenarios"]}
    for t in m.get("treatments", []):
        if t["scenario"] not in sids:
            errs.append(f"treatment for unknown scenario {t['scenario']}")
        if t["decision"] not in DECISIONS:
            errs.append(f"bad decision {t['decision']}")
        if not 0 <= t["effectiveness"] <= 1:
            errs.append("effectiveness must be 0..1")
    return errs


def load(path: str | pathlib.Path | None = None, text: str | None = None) -> dict:
    m = yaml.safe_load(text) if text is not None else yaml.safe_load(
        pathlib.Path(path or DATA / "risk" / "modules" / "cyber.yaml").read_text())
    errs = validate(m)
    if errs:
        raise ModuleError("; ".join(errs))
    return m


def available() -> list[str]:
    return sorted(p.stem for p in (DATA / "risk" / "modules").glob("*.yaml"))
