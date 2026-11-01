"""Label every control automated, hybrid or attestation.

- automated:   a checker in this repo decides pass/fail from machine data (configs or connector
               evidence) with no human input. The set is computed from the checker registries, so a
               control is only called automated if code for it exists and is tested.
- hybrid:      machine evidence exists (logs, scans, tickets) but a person must judge it.
- attestation: a person signs a dated statement; the repo tracks freshness and reminders.
"""
from __future__ import annotations

import functools

from .ids import canonical

# Families that are mostly paperwork, people or buildings.
ATTESTATION_FAMILIES = {"AT", "MA", "MP", "PE", "PL", "PM", "PS"}

# Procedural controls inside otherwise technical families.
ATTESTATION_EXTRA = {
    "CA-02(01)", "CA-06", "CA-08(01)", "CP-02", "CP-02(01)", "CP-02(03)", "CP-02(08)", "CP-03",
    "CP-04", "CP-04(01)", "IR-02", "IR-02(03)", "IR-03", "IR-03(02)", "IR-08", "IR-08(01)",
    "PT-01", "PT-02", "PT-03", "RA-09", "SA-02", "SA-03", "SA-03(01)", "SA-03(02)", "SA-04",
    "SA-04(01)", "SA-04(02)", "SA-04(09)", "SA-05", "SA-08", "SR-02", "SR-02(01)",
}

# Inside paperwork families, these have real machine evidence (e.g. inventories, HR feeds).
HYBRID_EXTRA = {"AT-02", "AT-02(02)", "PM-05", "PM-05(01)", "PS-05", "MA-02", "MA-04", "MP-06", "PL-02"}


@functools.lru_cache(maxsize=1)
def automated_ids() -> frozenset[str]:
    from .checks import evidence_checks as ev
    from .checks import registry as cfg

    ids: set[str] = set()
    for chk in list(cfg.all_checks()) + list(ev.all_checks()):
        ids.update(canonical(c) for c in chk.controls)
    return frozenset(ids)


def label_for(cid: str) -> str:
    c = canonical(cid)
    if c in automated_ids():
        return "automated"
    if c.endswith("-01") or c in ATTESTATION_EXTRA:
        return "attestation"
    if c[:2] in ATTESTATION_FAMILIES and c not in HYBRID_EXTRA:
        return "attestation"
    return "hybrid"


def checks_for(cid: str) -> list[str]:
    """IDs of every automated check that maps to this control."""
    from .checks import evidence_checks as ev
    from .checks import registry as cfg

    c = canonical(cid)
    return sorted(chk.id for chk in list(cfg.all_checks()) + list(ev.all_checks())
                  if c in {canonical(x) for x in chk.controls})
