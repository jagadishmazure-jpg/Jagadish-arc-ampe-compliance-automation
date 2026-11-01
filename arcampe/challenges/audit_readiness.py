"""Challenge: audit readiness. A single score and the list of what an assessor will ask for."""
from __future__ import annotations

from .. import attest, catalog
from ..poam import PoamItem


def readiness(findings, poam_items: list[PoamItem], approvals: dict) -> dict:
    ae = catalog.baseline("ae")
    tested = set()
    for f in findings:
        tested.update(f.controls)
    att = attest.load()
    current = sum(a.status() in ("current", "due_soon") for a in att)
    parts = {
        "controls_with_machine_or_attested_evidence": round(100 * sum(c.id in tested for c in ae) / len(ae), 1),
        "attestations_current": round(100 * current / len(att), 1),
        "poam_within_sla": round(100 * sum(i.sla_status != "overdue" for i in poam_items) / max(1, len(poam_items)), 1),
        "statements_approved": round(100 * len(approvals) / len(ae), 1),
    }
    weights = {"controls_with_machine_or_attested_evidence": 0.35, "attestations_current": 0.25,
               "poam_within_sla": 0.25, "statements_approved": 0.15}
    score = round(sum(parts[k] * w for k, w in weights.items()), 1)
    return {"score": score, "parts": parts, "weights": weights}


def assessor_request_list() -> list[str]:
    return ["SSPP workbook (out/sspp.xlsx)", "POA&M (out/poam.csv)", "Evidence binder manifest with SHA-256",
            "Latest vulnerability scans (30 days)", "Pen test report and retest letter", "Contingency plan test",
            "Incident response test and IR-06 reporting log", "Access reviews and termination evidence",
            "Signed attestations for procedural controls", "Interconnection and vendor agreements"]
