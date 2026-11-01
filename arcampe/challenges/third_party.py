"""Challenge: third-party risk. Vendor scores plus connector signals and concentration risk."""
from __future__ import annotations

from .. import supply_chain


def view(vendors=None, evidence=None) -> list[dict]:
    vendors = vendors or supply_chain.load()
    spend = sum(v.annual_spend for v in vendors) or 1
    contract = {}
    for e in evidence or []:
        if e.kind == "vendor":
            contract[e.subject] = e.attributes
    out = []
    for v in vendors:
        s = supply_chain.score(v)
        share = round(100 * v.annual_spend / spend, 1)
        signals = []
        if share >= 30:
            signals.append(f"concentration {share}% of vendor spend")
        c = contract.get(v.id)
        if c and (c.get("contract_breachNotifyHours") or 0) > 1:
            signals.append(f"AP record: breach notice {c['contract_breachNotifyHours']}h")
        out.append({**s, "spend_share_pct": share, "signals": signals})
    return sorted(out, key=lambda r: -r["score"])
