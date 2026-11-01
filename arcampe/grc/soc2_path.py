"""SOC 2 guided path: a requirement tree, ordered tasks and "N of M checked".

Requirement IDs are the 2017 Trust Services Criteria common criteria (CC1.1-CC9.2) plus availability A1.1-A1.3.
Summaries are the author's own short words, not AICPA text. Each requirement links to ARC-AMPE controls through
the core crosswalk (reverse map). A requirement is "checked" when every linked control was tested and passed; it
is "in progress" when some passed; otherwise "to do". The next tasks list the failing controls first.
"""
from __future__ import annotations

from .. import crosswalk

REQUIREMENTS = (
    ("CC1.1", "Leadership shows commitment to integrity and ethics"),
    ("CC1.2", "The board oversees internal control"),
    ("CC1.3", "Structures, reporting lines and authority are set"),
    ("CC1.4", "The company hires, trains and keeps competent people"),
    ("CC1.5", "People are held accountable for control duties"),
    ("CC2.1", "Quality information supports internal control"),
    ("CC2.2", "Control information is communicated inside the company"),
    ("CC2.3", "The company communicates with outside parties"),
    ("CC3.1", "Objectives are clear enough to find risks"),
    ("CC3.2", "Risks to objectives are identified and analysed"),
    ("CC3.3", "Fraud risk is considered"),
    ("CC3.4", "Significant changes are identified and assessed"),
    ("CC4.1", "Controls are evaluated on an ongoing or separate basis"),
    ("CC4.2", "Control gaps are reported and fixed"),
    ("CC5.1", "Control activities reduce risk"),
    ("CC5.2", "General technology controls are in place"),
    ("CC5.3", "Policies and procedures put controls into action"),
    ("CC6.1", "Logical access is restricted to protect assets"),
    ("CC6.2", "Users are registered and authorized before access"),
    ("CC6.3", "Access is changed or removed on time"),
    ("CC6.4", "Physical access is restricted"),
    ("CC6.5", "Data and devices are disposed of safely"),
    ("CC6.6", "Threats from outside the boundary are blocked"),
    ("CC6.7", "Data in transit and on media is protected"),
    ("CC6.8", "Unauthorized or malicious software is prevented or found"),
    ("CC7.1", "Configuration and vulnerabilities are monitored"),
    ("CC7.2", "Anomalies and security events are monitored"),
    ("CC7.3", "Security events are evaluated"),
    ("CC7.4", "Incidents are responded to"),
    ("CC7.5", "The company recovers from incidents"),
    ("CC8.1", "Changes are authorized, tested and approved"),
    ("CC9.1", "Business disruption risk is mitigated"),
    ("CC9.2", "Vendor and business partner risk is managed"),
    ("A1.1", "Capacity is planned and monitored"),
    ("A1.2", "Backups and recovery infrastructure are in place"),
    ("A1.3", "Recovery plans are tested"),
)
EXTRA_LINKS = {  # requirements the family-level crosswalk does not reach, linked by the author
    "CC1.2": ("PM-01",), "CC1.3": ("PM-02",), "CC1.5": ("PS-08",), "CC2.1": ("PM-05",), "CC2.3": ("IR-07",),
    "CC3.3": ("RA-03",), "CC3.4": ("CM-04",), "CC5.1": ("PL-02",), "CC5.2": ("CM-02",), "CC6.8": ("SI-03",),
    "CC9.1": ("CP-02",), "A1.1": ("SC-05",),
}


def links() -> dict[str, list[str]]:
    rev = crosswalk.reverse("SOC2")
    out = {}
    for rid, _ in REQUIREMENTS:
        ids = list(rev.get(rid, [])) + [c for c in EXTRA_LINKS.get(rid, ()) if c not in rev.get(rid, [])]
        out[rid] = sorted(set(ids))
    return out


def path(by_control: dict | None = None) -> list[dict]:
    if by_control is None:
        from .. import assess
        by_control = assess.by_control()
    lk = links()
    rows = []
    for rid, text in REQUIREMENTS:
        ids = lk[rid]
        st = [by_control.get(c, {}).get("status", "not_tested") for c in ids]
        if ids and all(s == "pass" for s in st):
            state = "checked"
        elif "pass" in st:
            state = "in_progress"
        else:
            state = "to_do"
        rows.append({"id": rid, "summary": text, "controls": len(ids), "passing": st.count("pass"),
                     "failing": st.count("fail"), "untested": st.count("not_tested"), "state": state,
                     "next": [c for c, s in zip(ids, st) if s == "fail"][:3]})
    return rows


def progress(by_control: dict | None = None) -> dict:
    rows = path(by_control)
    n = sum(r["state"] == "checked" for r in rows)
    return {"checked": n, "of": len(rows), "in_progress": sum(r["state"] == "in_progress" for r in rows),
            "to_do": sum(r["state"] == "to_do" for r in rows), "label": f"{n} of {len(rows)} SOC 2 requirements checked"}


def next_tasks(limit: int = 5, by_control: dict | None = None) -> list[str]:
    """Ordered to-do list: requirements closest to done first (fewest failing linked controls)."""
    rows = [r for r in path(by_control) if r["state"] != "checked"]
    rows.sort(key=lambda r: (r["failing"] + r["untested"], r["id"]))
    return [f"{r['id']} {r['summary']}: fix {', '.join(r['next']) or 'test linked controls'}" for r in rows[:limit]]
