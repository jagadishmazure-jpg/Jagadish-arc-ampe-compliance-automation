"""Business units (workspaces): each unit owns a slice of the control library, its own owners, its own
exceptions and its own readiness score.

Assignment is by control family so every AE control lands in exactly one unit. Readiness counts only
controls that something actually tested (a pass or a fail); untested controls are shown separately.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from .. import TODAY, catalog


@dataclass(frozen=True)
class BusinessUnit:
    id: str
    name: str
    lead: str
    families: tuple[str, ...]


UNITS = (
    BusinessUnit("BU-MKT", "Marketplace Platform", "platform-director", ("AC", "AU", "CM", "IA", "SC", "SI")),
    BusinessUnit("BU-CSO", "Consumer Services", "consumer-services-director", ("AT", "IR", "PS", "PT")),
    BusinessUnit("BU-INF", "Infrastructure and Facilities", "it-ops-manager", ("CP", "MA", "MP", "PE")),
    BusinessUnit("BU-PMO", "Program Office", "ciso", ("CA", "PL", "PM", "RA", "SA", "SR")),
)

# Approved exceptions (risk acceptances) per unit. Synthetic.
EXCEPTIONS = (
    {"id": "EXC-01", "unit": "BU-MKT", "control": "SC-08", "reason": "Legacy SFTP partner link until cut-over",
     "approved_by": "ciso", "expires": "2026-12-15"},
    {"id": "EXC-02", "unit": "BU-INF", "control": "CP-04", "reason": "Failover test moved after data-center move",
     "approved_by": "ciso", "expires": "2026-10-01"},
    {"id": "EXC-03", "unit": "BU-CSO", "control": "AT-02", "reason": "Seasonal staff train in week one",
     "approved_by": "isso", "expires": "2027-01-31"},
    {"id": "EXC-04", "unit": "BU-PMO", "control": "SR-03", "reason": "Analytics vendor contract renegotiation",
     "approved_by": "ciso", "expires": "2026-11-20"},
)


def unit(uid: str) -> BusinessUnit:
    for u in UNITS:
        if u.id == uid:
            return u
    raise KeyError(uid)


def unit_for_family(family: str) -> BusinessUnit:
    for u in UNITS:
        if family in u.families:
            return u
    raise KeyError(family)


def assign(baseline: str = "ae") -> dict[str, list[str]]:
    out: dict[str, list[str]] = {u.id: [] for u in UNITS}
    for c in catalog.baseline(baseline):
        out[unit_for_family(c.family).id].append(c.id)
    return out


def active_exceptions(uid: str | None = None, today: str = TODAY) -> list[dict]:
    t = dt.date.fromisoformat(today)
    return [e for e in EXCEPTIONS if (uid is None or e["unit"] == uid) and dt.date.fromisoformat(e["expires"]) >= t]


def expired_exceptions(today: str = TODAY) -> list[dict]:
    t = dt.date.fromisoformat(today)
    return [e for e in EXCEPTIONS if dt.date.fromisoformat(e["expires"]) < t]


def readiness(by_control: dict | None = None, baseline: str = "ae") -> list[dict]:
    """Per unit: controls, tested, passing, failing, untested, readiness % of tested controls."""
    if by_control is None:
        from .. import assess
        by_control = assess.by_control()
    rows = []
    for u in UNITS:
        ids = assign(baseline)[u.id]
        st = [by_control.get(c, {}).get("status", "not_tested") for c in ids]
        passing, failing = st.count("pass"), st.count("fail")
        tested = passing + failing
        exc = {e["control"] for e in active_exceptions(u.id)}
        rows.append({"unit": u.id, "name": u.name, "lead": u.lead, "controls": len(ids), "tested": tested,
                     "passing": passing, "failing": failing, "untested": len(ids) - tested,
                     "readiness_pct": round(100 * passing / tested, 1) if tested else 0.0,
                     "exceptions": len(exc)})
    return rows


def table() -> str:
    lines = ["| Unit | Lead | Controls | Tested | Passing | Failing | Readiness | Active exceptions |",
             "|---|---|---:|---:|---:|---:|---:|---:|"]
    for r in readiness():
        lines.append(f"| {r['name']} | {r['lead']} | {r['controls']} | {r['tested']} | {r['passing']} | "
                     f"{r['failing']} | {r['readiness_pct']}% | {r['exceptions']} |")
    return "\n".join(lines)
