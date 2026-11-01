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
import pathlib
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


def leadership_report() -> None:
    """Daily and weekly leadership emails: built from the synthetic data, written as previews, never sent."""
    import tempfile

    from .grc import reporting
    m = reporting.metrics()
    print("1. Headline KPIs (every value is computed from the synthetic data):")
    for k, v, basis in reporting.headline(m):
        print(f"   {k:34} {v:38} [{basis}]")
    print("2. Framework readiness rings (tested-pass controls / mapped controls), top 5:")
    for r in sorted(m["frameworks"], key=lambda r: -r["ready_pct"])[:5]:
        print(f"   {r['name']:34} {r['ready_pct']:5}%  ({r['ready']}/{r['controls']}, {r['coverage']})")
    print("3. AI Governance & Accountability (weekly section):")
    for k in m["ai_governance"]:
        print(f"   {k['kpi']:40} {k['value']}  [{k['basis']}]")
    idk = m["identity"]
    print(f"4. Identity recovery: measured {idk['measured_rto_hours']}h vs target {idk['target_rto_hours']}h, "
          f"{idk['days_since_drill']} days since drill, checks {idk['checks_passed']}/{idk['checks']}")
    with tempfile.TemporaryDirectory() as d:
        files = sorted(pathlib.Path(f).name for k in ("daily", "weekly") for f in reporting.write_previews(d, k))
    print("5. Previews written to out/reports/:", ", ".join(files))
    try:
        reporting.send(reporting.to_eml(m, "weekly"))
    except reporting.SendRefused as e:
        print("6. Send attempt without config and approval: refused -", e)


def bu_workspaces_and_frameworks() -> None:
    """A CISO asks: which business unit is least ready, and how ready are we for each framework?"""
    from .grc import frameworks, workspaces
    print("1. Readiness per business unit (tested-pass / tested):")
    for r in workspaces.readiness():
        print(f"   {r['unit']:7} {r['name']:28} {r['readiness_pct']:5}%  pass {r['passing']}, fail {r['failing']},"
              f" untested {r['untested']}, exceptions {r['exceptions']}")
    print("2. Framework registry:", frameworks.summary())
    low = sorted(frameworks.readiness(), key=lambda r: r["ready_pct"])[:3]
    print("3. Three least-ready frameworks:", [(r["name"], r["ready_pct"]) for r in low])


def control_drift_review() -> None:
    """A control marked compliant is edited later; it goes back to expert review automatically."""
    from .grc import review
    d = review.demo()
    print("1. Review board:", d["board"])
    for f in d["drift"]:
        print(f"2. Drift: {f['control']} (owner {f['owner']}) approved {f['approved_hash']}, now {f['current_hash']}"
              " -> needs_review")
    r = review.ControlReview("AC-02", owner="owner-1")
    r.start("owner-1")
    try:
        r.submit("owner-1")
    except review.ReviewError as e:
        print("3. Submit with no evidence: refused -", e)


def pr_gate_and_audit_package() -> None:
    """A pull request adds an RDP-open network rule; the pipeline gate blocks it; the auditor gets a sealed package."""
    from .grc import auditor, cac
    from .integrations.connectors import collect_all
    d = cac.demo()
    print("1. Fix suggestions for current findings:", d["suggestions"])
    print("2. Pipeline gate on the PR:", d["gate"])
    ev = collect_all()
    st = auditor.AuditStore()
    st.put("AC-02", "evidence v1", actor="owner-1")
    st.freeze("isso")
    try:
        st.put("AC-02", "evidence v2", actor="owner-1")
    except auditor.AuditModeError as e:
        print("3. Write during audit mode: refused -", e)
    plan = auditor.plan(ev)
    print("4. Sampling plan:", len(plan), "groups,", sum(p["sample"] for p in plan), "items sampled")
    blob = auditor.package(ev[:20])
    print("5. Package verify:", auditor.verify(blob) or "intact")


def ai_accountability() -> None:
    """A board member asks: can we explain and replay what our AI agents decided, and who approved it?"""
    from .grc import ai_governance as g
    from .grc import mcp_server
    s = mcp_server.demo_server()
    r = s.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "propose_status_change",
        "arguments": {"control_id": "AC-02", "status": "passing", "reason": "Q3 review complete"}}}, "k-copilot")
    print("1. Copilot proposes a change through MCP:", r["result"]["status"], r["result"]["change_id"])
    try:
        s.approve(r["result"]["change_id"], "agent:copilot", "isso", is_agent=True, note="ok")
    except mcp_server.McpError as e:
        print("2. Agent tries to approve it: refused -", e)
    print("3. Human approves:", s.approve(r["result"]["change_id"], "Riley Quist", "isso", note="checked")["status"])
    print("4. Decision rights gaps:", g.decision_rights_gaps(), "coverage", g.decision_rights_coverage(), "%")
    print("5. Replay audit of agent decisions:", g.replay_audit())
    print("6. Shadow AI:", [(x["tool"], x["owner"], x["status"]) for x in g.shadow_ai()])
    print("7. Approved model and app register:", g.register_summary())
    for c in g.register_checks():
        if not c["passed"]:
            print(f"   {c['user']:22} {c['name']:34} {'; '.join(c['problems'])}")


def identity_recovery() -> None:
    """Identity (AD + Entra) is the first dependency of every critical service; prove it can be restored."""
    from . import resilience
    print("1. Dependency concentration:", resilience.dependency_concentration())
    for c in resilience.identity_checks():
        print(f"2. {c['id']:22} {c['control']:6} {'PASS' if c['passed'] else 'FAIL'}  {c['detail']}")
    print("3. KPIs:", resilience.identity_kpis())


def industry_packs_multi_org() -> None:
    """A compliance team serves five organisations in different industries from one install, kept apart."""
    from .grc import industry_packs as ip
    mo = ip.demo()
    for o in ip.ORGS:
        rows = mo.pack_readiness(f"k-{o.id}", o.id)
        print(f"1. {o.name:34} pack {o.pack:22}", [(r["framework"], r["ready_pct"]) for r in rows])
    try:
        mo.status("k-cedarbrook", "ironvale")
    except ip.TenantIsolationError as e:
        print("2. Credit union key reads the defense org: refused -", e)
    print("3. Portfolio (counts only):", [(r["org"], r["readiness_pct"]) for r in mo.portfolio()])
    print("4. Audit log:", mo.log.verify())


def scanner_evidence() -> None:
    """The monthly vulnerability scan export becomes RA-5 and SI-2 evidence and POA&M rows."""
    from .grc import scanner_import as s
    rows = s.load()
    print("1. Imported", len(rows), "rows from data/grc/scanner/scan_2026-10.csv;",
          sum(r["quarantined"] for r in rows), "quarantined for injection-like text")
    ev = s.to_evidence(rows)
    print("2. Evidence:", {k: sum(e.kind == k for e in ev) for k in ("vuln_scan", "flaw_remediation")})
    for c in s.checks(rows):
        print(f"3. {c['id']:18} {c['control']:9} {'PASS' if c['passed'] else 'FAIL'}  {c['detail']}")
    for i in s.open_items(rows)[:3]:
        print(f"4. {i['id']:28} {i['severity']:8} kev={i['kev']!s:5} due {i['due']} {i['sla_status']}")


def control_readiness_and_audit() -> None:
    """Before fieldwork, the ISSO signs off ready controls, the auditor's requests are mapped, and AI-drafted tests
    wait for a human reviewer."""
    from .grc import ai_tests, audit_hub, readiness_approval
    ctx = readiness_approval._context()
    print("1. Readiness board:", readiness_approval.board(ctx=ctx))
    s = readiness_approval.sign_off("IA-02(01)", "maya.isso", "isso", ctx=ctx)
    print("2. Signed IA-02(01) by", s.approver, "covering", len(s.evidence_hashes), "evidence records")
    try:
        readiness_approval.sign_off("AC-02", "maya.isso", "isso", ctx=ctx)
    except readiness_approval.ReadinessError as e:
        print("3. AC-02 refused:", e)
    print("4. Auditor requests:", audit_hub.request_summary())
    print("5. Independence:", [(r["audit"], r["independent"]) for r in audit_hub.check_independence()])
    print("6. AI-drafted tests:", ai_tests.summary())


def leadership_scorecards() -> None:
    """The CISO wants the weekly scorecards: efficiency, risk with loss ranges, and trust."""
    from .grc import insights, risk_program, scorecards
    i = insights.summary()
    print("1. Flipped pass->fail 24h/7d/14d:", i["flipped"], "MTTR", i["mttr_hours"], "h (synthetic history)")
    for r in risk_program.board_view():
        print(f"2. {r['register']:7} {r['sentence']} (SIMULATED)")
    s = risk_program.sla()
    print("3. Risk SLA adherence", s["adherence_pct"], "%; invalid acceptances", s["invalid_acceptances"])
    sc = scorecards.build()
    for card in ("efficiency", "risk", "trust"):
        print(f"4. {card}: {len(sc[card])} KPIs, e.g. {sc[card][1][0]} = {sc[card][1][1]} [{sc[card][1][2]}]")


CASES = {f.__name__: f for f in (first_ato, conmon_public_storage, annual_renewal, new_vendor, privacy_incident,
                                 reg_change, auditor_copilot, leadership_report, bu_workspaces_and_frameworks,
                                 control_drift_review, pr_gate_and_audit_package, ai_accountability,
                                 identity_recovery, industry_packs_multi_org, scanner_evidence,
                                 control_readiness_and_audit, leadership_scorecards)}

if __name__ == "__main__":
    for name in sys.argv[1:] or list(CASES):
        print(f"== {name} ==") if len(sys.argv) < 2 else None
        CASES[name]()
