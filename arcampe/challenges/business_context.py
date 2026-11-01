"""Challenge: business context. Weigh technical severity by business impact and the risk appetite."""
from __future__ import annotations

from .scoring import band, normalize

# Business impact tiers for the fictional exchange (from the BIA in arcampe/resilience.py).
IMPACT = {"eligibility": 1.5, "enrollment": 1.4, "consumer-portal": 1.3, "call-center": 1.1, "analytics": 0.9,
          "corporate": 0.7}
ASSET_SERVICE = {"sql-lhx-elig": "eligibility", "sql-lhx-enroll": "enrollment", "app-lhx-portal": "consumer-portal",
                 "vm-lhx-app03": "eligibility", "vm-lhx-app04": "enrollment", "vm-lhx-app06": "enrollment",
                 "vm-lhx-app07": "call-center", "stlhxbackup": "enrollment", "stlhxreports": "analytics",
                 "stlhxarchive": "eligibility", "srch-lhx-kb": "call-center", "afd-lhx-public": "consumer-portal",
                 "app-lhx-legacy": "consumer-portal", "aks-lhx-batch": "analytics", "nsg-lhx-jump": "corporate"}
APPETITE = {  # maximum business-weighted score accepted without a formal risk acceptance
    "pii_exposure": 4.0, "availability": 6.0, "compliance": 5.0, "default": 6.0}


def category_of(f) -> str:
    c = " ".join(f.controls)
    if any(x in c for x in ("SC-28", "SC-12", "AC-03", "SA-09", "PT-", "AC-22", "SC-07")):
        return "pii_exposure"
    if any(x in c for x in ("CP-", "SC-05")):
        return "availability"
    if f.check_id.startswith(("AT-ST", "EV-")):
        return "compliance"
    return "default"


def contextualize(f) -> dict:
    base = normalize("internal", f.severity)
    service = ASSET_SERVICE.get(f.resource_name, "corporate")
    weighted = round(min(10.0, base * IMPACT[service]), 2)
    cat = category_of(f)
    limit = APPETITE.get(cat, APPETITE["default"])
    return {"check": f.check_id, "resource": f.resource_name, "service": service, "category": cat,
            "base": base, "weighted": weighted, "band": band(weighted), "appetite": limit,
            "exceeds_appetite": weighted > limit}


def ranked(findings) -> list[dict]:
    return sorted((contextualize(f) for f in findings if not f.passed),
                  key=lambda r: (-r["weighted"], r["check"], r["resource"]))
