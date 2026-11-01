"""Industry packs: approximate framework bundles for regulated industries, plus multi-org mode.

Packs (all mappings **approximate**, author-built at NIST 800-53 family level from the public structure of each
rule, never official, and they need an expert before real use):

* banking_credit_union: FFIEC CAT / NCUA ACET domains D1-D5 (the FFIEC retired its CAT tool in 2025; the NCUA
  ACET with the same five domains is still published), NYDFS Part 500, SEC Regulation S-P
* defense: CMMC 2.0 Level 2 and NIST SP 800-171
* legal: ABA Model Rule 1.6(c) with Formal Opinions 477R (securing communications) and 483 (breach duties)
* broker_dealer_adviser: SEC Regulation S-P (2024 amendments: incident response program, 30-day customer notice,
  service-provider oversight) and SOX ITGC

Multi-org mode keeps each organisation's results, evidence and audit log apart. A service key is scoped to one
org; reading another org's data raises TenantIsolationError and is logged.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .. import TODAY, catalog
from ..platform.audit_log import AuditLog
from . import frameworks
from .frameworks import _m

PACK_MAP: dict[str, dict[str, tuple[str, ...]]] = {
    "FFIEC_ACET": _m(  # D1 governance, D2 threat intel, D3 controls, D4 external dependencies, D5 incident/resilience
        AC="D3.PC", AT="D1.TC", AU="D3.DC", CA="D1.G", CM="D3.PC", CP="D5.ER", IA="D3.PC", IR=("D5.IR", "D5.DR"),
        MA="D3.PC", MP="D3.PC", PE="D3.PC", PL="D1.G", PM=("D1.G", "D1.RM"), PS="D1.TC", RA=("D1.RM", "D2.TI"),
        SA="D4.RM", SC="D3.PC", SI=("D2.MA", "D3.DC"), SR=("D4.C", "D4.RM")),
    "ABA_1_6": _m(  # Model Rule 1.6(c) reasonable efforts; Op. 477R communications; Op. 483 breach duties
        AC="1.6(c)", AT="1.6(c) Cmt.18", AU="Op.483 monitoring", CM="Op.477R", IA="1.6(c)", IR="Op.483",
        MP="1.6(c)", PS="5.1/5.3 supervision", RA="Op.477R risk", SA="5.3 vendors", SC="Op.477R", SR="5.3 vendors"),
    "SEC_REG_SP": _m(  # 17 CFR 248.30 as amended in 2024
        AC="248.30(a)(1)", AT="248.30(a)(1)", AU="248.30(d) records", IA="248.30(a)(1)",
        IR=("248.30(a)(3)", "248.30(a)(4)"), MP="248.30(b) disposal", PL="248.30(a)", PM="248.30(a)",
        RA="248.30(a)(3)(i)", SA="248.30(a)(5)", SC="248.30(a)(1)", SI="248.30(a)(3)", SR="248.30(a)(5)"),
}
PACK_INFO = {
    "FFIEC_ACET": ("FFIEC CAT / NCUA ACET", "5 domains"),
    "ABA_1_6": ("ABA Model Rule 1.6 (with Op. 477R, 483)", "1 rule, 2 opinions"),
    "SEC_REG_SP": ("SEC Regulation S-P (2024 amendments)", "17 CFR 248.30"),
}
PACKS = {
    "health_exchange": ("NIST_800_53", "HIPAA"),
    "banking_credit_union": ("FFIEC_ACET", "NYDFS_500", "SEC_REG_SP"),
    "defense": ("CMMC_L2", "NIST_800_171"),
    "legal": ("ABA_1_6",),
    "broker_dealer_adviser": ("SEC_REG_SP", "SOX_ITGC"),
}


def name(fw: str) -> str:
    return PACK_INFO[fw][0] if fw in PACK_INFO else frameworks.info(fw)["name"]


def mapped(fw: str, baseline: str = "ae") -> list[str]:
    if fw in PACK_MAP:
        return [c.id for c in catalog.baseline(baseline) if c.family in PACK_MAP[fw]]
    return frameworks.mapped_controls(fw, baseline)


def readiness(pack: str, by_control: dict | None = None) -> list[dict]:
    if by_control is None:
        from .. import assess
        by_control = assess.by_control()
    rows = []
    for fw in PACKS[pack]:
        ids = mapped(fw)
        st = [by_control.get(c, {}).get("status", "not_tested") for c in ids]
        ready, failing = st.count("pass"), st.count("fail")
        rows.append({"pack": pack, "framework": fw, "name": name(fw), "controls": len(ids), "ready": ready,
                     "failing": failing, "untested": len(ids) - ready - failing,
                     "ready_pct": round(100 * ready / len(ids), 1) if ids else 0.0, "coverage": "approximate"})
    return rows


def all_readiness(by_control: dict | None = None) -> list[dict]:
    return [r for p in PACKS for r in readiness(p, by_control)]


# ---------------------------------------------------------------------------------------------- multi-org mode
class TenantIsolationError(PermissionError):
    pass


@dataclass(frozen=True)
class Org:
    id: str
    name: str
    domain: str
    pack: str


ORGS = (
    Org("lakehaven", "Lakehaven Health Connector", "lakehaven-hx.example", "health_exchange"),
    Org("cedarbrook", "Cedarbrook Community Credit Union", "cedarbrook-cu.example", "banking_credit_union"),
    Org("ironvale", "Ironvale Precision Components", "ironvale-pc.example", "defense"),
    Org("marlow", "Marlow and Teague LLP", "marlowteague.example", "legal"),
    Org("northgate", "Northgate Harbor Advisers", "northgate-ha.example", "broker_dealer_adviser"),
)


def _synthetic_status(org_id: str) -> dict:
    """Lakehaven uses the real synthetic assessment. The other orgs get a deterministic synthetic status per control
    (hash of org + control) so they differ from each other but never change between runs."""
    from .. import assess
    if org_id == "lakehaven":
        return assess.by_control()
    out = {}
    for c in catalog.baseline("ae"):
        h = int(hashlib.sha256(f"{org_id}:{c.id}".encode()).hexdigest()[:4], 16) % 100
        out[c.id] = {"status": "pass" if h < 45 else ("fail" if h < 65 else "not_tested")}
    return out


@dataclass
class MultiOrg:
    keys: dict[str, str] = field(default_factory=dict)  # key id -> org id ("*" = platform admin, read-only summary)
    log: AuditLog = field(default_factory=AuditLog)
    _data: dict[str, dict] = field(default_factory=dict)
    _evidence: dict[str, list] = field(default_factory=dict)

    def org(self, org_id: str) -> Org:
        for o in ORGS:
            if o.id == org_id:
                return o
        raise KeyError(org_id)

    def _scope(self, key: str, org_id: str, action: str) -> None:
        scope = self.keys.get(key)
        if scope is None or (scope != org_id):
            self.log.append(TODAY, org_id, key, "tenant.refused", action, f"key scope={scope}")
            raise TenantIsolationError(f"key {key} cannot access org {org_id}")
        self.log.append(TODAY, org_id, key, "tenant.read", action, "")

    def status(self, key: str, org_id: str) -> dict:
        self._scope(key, org_id, "status")
        self.org(org_id)
        if org_id not in self._data:
            self._data[org_id] = _synthetic_status(org_id)
        return self._data[org_id]

    def add_evidence(self, key: str, org_id: str, item: dict) -> None:
        self._scope(key, org_id, "add_evidence")
        if item.get("tenant") not in (None, org_id):
            raise TenantIsolationError("evidence tenant does not match org")
        self._evidence.setdefault(org_id, []).append({**item, "tenant": org_id})

    def evidence(self, key: str, org_id: str) -> list:
        self._scope(key, org_id, "evidence")
        return list(self._evidence.get(org_id, []))

    def pack_readiness(self, key: str, org_id: str) -> list[dict]:
        return readiness(self.org(org_id).pack, self.status(key, org_id))

    def portfolio(self) -> list[dict]:
        """Cross-org summary with counts only (no control-level data), built by the platform itself."""
        out = []
        for o in ORGS:
            st = self._data.get(o.id) or _synthetic_status(o.id)
            vals = [v["status"] for v in st.values()]
            tested = vals.count("pass") + vals.count("fail")
            out.append({"org": o.id, "name": o.name, "pack": o.pack, "tested": tested, "passing": vals.count("pass"),
                        "readiness_pct": round(100 * vals.count("pass") / tested, 1) if tested else 0.0})
        return out


def demo() -> MultiOrg:
    return MultiOrg(keys={f"k-{o.id}": o.id for o in ORGS})
