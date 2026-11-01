"""End-to-end use cases, each printed from real code paths in this repo.

Used by docs/USE_CASES.md:

    python -m arcampe.usecases <case>

Cases: first_ato, conmon_public_storage, annual_renewal, new_vendor, privacy_incident, reg_change,
auditor_copilot. Everything is offline and uses the synthetic Lakehaven Health Connector data.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import sys
import zipfile

PUBLIC_STORAGE = "stlhxstaticweb"


def first_ato() -> None:
    """A new state exchange prepares its first authorization package."""
    from . import assess, binder, catalog, poam, sspp
    rows: dict[str, int] = {}
    for c in catalog.baseline("ae"):
        rows[c.label] = rows.get(c.label, 0) + 1
    print("1. Load the AE baseline:", sum(rows.values()), "controls", dict(sorted(rows.items())))
    s = assess.summary()
    print("2. First full assessment:", s["findings"], "findings,", s["passed"], "pass,", s["failed"], "fail")
    print("3. SSPP workbook status per control:", sspp.status_counts(sspp.build()))
    p = poam.summary(poam.build(assess.run_all()))
    print("4. POA&M opened automatically:", p["open"], "items", p["by_severity"])
    blob = binder.build()
    names = zipfile.ZipFile(io.BytesIO(blob)).namelist()
    print("5. Binder:", len(names), "files, verify:", binder.verify(blob) or "intact")
    print("   same input, same bytes:", hashlib.sha256(blob).hexdigest()[:16] ==
          hashlib.sha256(binder.build()).hexdigest()[:16])


def _fixed_estate():
    from .checks.registry import load_estate
    est = copy.deepcopy(load_estate())
    for r in est:
        if r["name"] == PUBLIC_STORAGE:
            r["properties"]["publicNetworkAccess"] = "Disabled"
            r["properties"]["privateEndpointConnections"] = [{"name": "pe-stlhxstaticweb", "status": "Approved"}]
            r["properties"]["x_policy_compliant"] = True
    return est


def conmon_public_storage() -> None:
    """Daily monitoring finds a storage account open to the internet and tracks it to closure."""
    from . import assess, iac, poam
    from .checks import registry
    from .checks.registry import load_estate
    day1 = [f for f in assess.run_all() if f.resource_name == PUBLIC_STORAGE and not f.passed]
    print("Day 1, daily check run, failures on", PUBLIC_STORAGE + ":")
    for f in day1:
        print(f"  {f.check_id} {f.severity:8} {f.detail}  controls={list(f.controls)}")
    hits = [h["policy"] for h in iac.evaluate(load_estate()) if h["resource"] == PUBLIC_STORAGE]
    print("  Azure Policy (offline evaluation) flags it too:", hits)
    for i in poam.build(assess.run_all()):
        if i.resource == PUBLIC_STORAGE:
            print(f"  POA&M {i.id} {i.check_id} {i.severity} owner={i.owner} due={i.due} ({i.sla_status})")
    after = [f for f in registry.run(resources=_fixed_estate()) if f.resource_name == PUBLIC_STORAGE]
    print("After the fix (public access off, private endpoint added), re-test:")
    for cid in sorted({f.check_id for f in day1}):
        r = [f for f in after if f.check_id == cid]
        print(f"  {cid} {'PASS' if all(f.passed for f in r) else 'FAIL'} {r[0].detail}")
    left = [i for i in poam.build(tuple(after)) if i.resource == PUBLIC_STORAGE]
    print("Open POA&M items for", PUBLIC_STORAGE, "after re-test:", len(left), "-> closed")


def annual_renewal() -> None:
    """The yearly authorization renewal package (ATO / Authority to Connect)."""
    from . import attest, binder, conmon
    items = attest.load()
    print("1. Attestations:", attest.summary(items))
    rem = attest.reminders(items)
    print(f"2. Reminder drafts (not sent): {len(rem)}, e.g. to={rem[0]['to_role']} subject={rem[0]['subject']!r}")
    m = conmon.metrics()
    print("3. CONMON: findings", m["assessment"]["passed"], "pass /", m["assessment"]["failed"], "fail;",
          "POA&M open", m["poam"]["open"], "overdue", m["poam"]["by_sla"]["overdue"], "| readiness score",
          m["readiness"]["score"])
    blob = binder.build()
    z = zipfile.ZipFile(io.BytesIO(blob))
    print("4. Binder contents:")
    for n in z.namelist():
        print(f"   {n}")
    man = json.loads(z.read("manifest.json")) if "manifest.json" in z.namelist() else {}
    print("5. Manifest entries:", len(man.get("files", man)), "| verify:", binder.verify(blob) or "intact")


NEW_VENDOR = {  # fictional vendor being onboarded
    "id": "V-007", "name": "Lumenfield Translation Services", "service": "Translate consumer notices",
    "pii_access": True, "annual_spend": 180_000, "data_location": "US",
    "answers": {"Q1": True, "Q2": True, "Q3": True, "Q4": False, "Q5": False, "Q6": False, "Q7": True},
    "last_assessed": None, "contract": {"breach_notify_hours": 48, "flowdown_45cfr155260": False},
}


def new_vendor() -> None:
    """Onboarding a new vendor that will see consumer PII (SR family)."""
    from . import supply_chain as S
    v = S.Vendor(**NEW_VENDOR)
    print("Vendor:", v.name, "| PII:", v.pii_access, "| spend: $" + f"{v.annual_spend:,}", "| tier:", v.tier())
    print("Questionnaire gaps:", [f"{q} {S.QUESTIONS[q][0]}" for q in S.questionnaire_gaps(v)])
    s = S.score(v)
    print("Risk score (0-100):", s["score"], s["band"], s["factors"])
    for f in S.findings([v]):
        print(f"  {f['id']:9} {f['control']:9} {'PASS' if f['passed'] else 'FAIL'}  {f['detail']}")
    v2 = S.Vendor(**{**NEW_VENDOR, "answers": {q: True for q in S.QUESTIONS}, "last_assessed": "2026-10-20",
                     "contract": {"breach_notify_hours": 1, "flowdown_45cfr155260": True}})
    s2 = S.score(v2)
    print("After contract fixes and an assessment:", s2["score"], s2["band"], s2["factors"])


def privacy_incident() -> None:
    """Misdirected mail with consumer PII: classify, playbook, CMS 1-hour clock, chain of custody."""
    from . import privacy
    from .incident import Incident
    inc = Incident("INC-2026-031", "Renewal notices mailed to wrong addresses", "2026-10-29T09:12:00",
                   "pii-misdirected-mail", pii=True)
    print("Severity:", inc.classify(records_affected=820, systems_down=False))
    print("Playbook:", inc.playbook())
    print("Deadlines:", inc.deadlines())
    inc.log("2026-10-29T09:58:00", "cms_report")
    print("CMS report sent 09:58, met 1-hour clock:", inc.met("cms_report"))
    print("Post-incident review done yet:", inc.met("post_incident_review"))
    letter = b"Batch 4471 print file, 820 notices"
    log = b"Mailroom scan log 2026-10-28"
    inc.add_artifact("print_file.txt", letter, "Dana Orwell", "2026-10-29T10:05:00")
    inc.add_artifact("mail_log.txt", log, "Riley Quist", "2026-10-29T10:20:00")
    print("Chain of custody intact:", inc.custody_intact({"print_file.txt": letter, "mail_log.txt": log}))
    print("After editing one artifact:", inc.custody_intact({"print_file.txt": letter + b" ", "mail_log.txt": log}))
    notes = "Consumer SSN 123-45-6789 was printed."
    shared = privacy.mask_ssn(notes)
    print("Full SSNs left in the notes after masking:", len(privacy.find_ssns(shared)),
          "(before:", str(len(privacy.find_ssns(notes))) + ")")


def reg_change() -> None:
    """A new or proposed rule lands: which controls does it touch, and what work opens?"""
    from . import regchange
    for r in regchange.run():
        print(f"{r['change']} {r['title']}: {r['count']} controls {r['by_label']}")
        print(f"   first controls: {r['controls'][:6]}")
        print(f"   first task: {r['tasks'][0] if r['tasks'] else 'none'}")


def auditor_copilot() -> None:
    """An assessor plans the audit, the AI copilot pre-scores evidence, people decide."""
    from . import agent, assess, audit, catalog
    from .automation import ai_auditor
    from .integrations.connectors import collect_all
    from .platform.rbac import AccessDenied, Principal
    fams = {c.family: c.family_name for c in catalog.load()}
    plan = audit.audit_plan(assess.by_control(), fams)
    print("1. Risk-based audit plan (first 5 of", len(plan), "families,", sum(p["days"] for p in plan), "days):")
    for p in plan[:5]:
        print(f"   {p['family']} {p['name']:40} fail rate {p['fail_rate']:.3f} -> {p['days']} days ({p['priority']})")
    ev = collect_all()
    r = ai_auditor.run(ev)
    print(f"2. Copilot pre-scores {r['reviewed']} evidence records: {r['ready']} ready for sign-off, "
          f"{r['needs_work']} need better evidence, {r['signed_off']} signed off by AI")
    weak = sorted(r["rows"], key=lambda x: x["score"])[0]
    print(f"   weakest: {weak['source']} {weak['subject']} score {weak['score']} reasons {weak['reasons']}")
    best = sorted(r["rows"], key=lambda x: -x["score"])[0]
    bot = Principal("agent:copilot", "lakehaven", ("isso",), mfa=True, phishing_resistant=True, is_agent=True)
    isso = Principal("Riley Quist", "lakehaven", ("isso",), mfa=True, phishing_resistant=True)
    print("3. Human sign-off rules:")
    for who in (bot, isso):
        try:
            ai_auditor.sign_off(best, who, "accepted", "Matches source export.", uploader=who.id)
        except AccessDenied as e:
            print(f"   sign-off by {who.id} on its own upload: refused - {e}")
    so = ai_auditor.sign_off(best, isso, "accepted", "Matches source export.", uploader="connector:entra_id")
    print(f"   sign-off by {so.reviewer} on evidence uploaded by a connector: {so.decision}")
    d = agent.draft("AC-02", notes="Quarterly access review completed by identity team.")
    print("4. Copilot drafts the AC-02 answer:", d.status, "| citations:", list(d.citations)[:3])
    f = audit.AuditFinding("AF-01", "Guest in PII group", "AC-02", "high", owner="identity-team")
    f.advance("identity-team")
    try:
        f.advance("identity-team")
    except PermissionError as e:
        print("5. Finding AF-01 validation by its owner: refused -", e)
    f.advance("internal-audit")
    print("   validated by internal-audit, then:", f.advance("internal-audit"))


CASES = {f.__name__: f for f in (first_ato, conmon_public_storage, annual_renewal, new_vendor, privacy_incident,
                                 reg_change, auditor_copilot)}

if __name__ == "__main__":
    for name in sys.argv[1:] or list(CASES):
        print(f"== {name} ==") if len(sys.argv) < 2 else None
        CASES[name]()
