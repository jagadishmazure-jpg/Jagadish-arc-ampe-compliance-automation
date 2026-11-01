"""Incident, governance, resilience, audit, automation, challenges, reporting, CLI and IaC parity."""
import io
import json
import zipfile

import pytest

from arcampe import (
    assess,
    audit,
    binder,
    catalog,
    conmon,
    custom,
    governance,
    iac,
    incident,
    internal_audit,
    regchange,
    resilience,
)
from arcampe.__main__ import main
from arcampe.automation import ai_auditor, scheduler
from arcampe.challenges import audit_readiness, business_context, response, scoring, third_party, visibility
from arcampe.checks.registry import load_estate
from arcampe.platform.rbac import AccessDenied, Principal


# ---------- incident (IR-06: PII incidents to CMS within 1 hour) ----------
def _inc(pii=True):
    return incident.Incident("INC-1", "Lost laptop", "2026-10-30T09:00:00", "lost_device", pii)


def test_cms_report_deadline_is_one_hour():
    assert _inc().deadlines()["cms_report"] == "2026-10-30T10:00:00"
    assert "cms_report" not in _inc(pii=False).deadlines()


@pytest.mark.parametrize("at,met", [("2026-10-30T09:59:00", True), ("2026-10-30T10:00:00", True),
                                    ("2026-10-30T10:01:00", False)])
def test_cms_report_met(at, met):
    i = _inc()
    i.log(at, "cms_report")
    assert i.met("cms_report") is met


def test_no_report_logged_is_missed():
    assert _inc().met("cms_report") is False and _inc(pii=False).met("cms_report") is None


@pytest.mark.parametrize("pii,records,down,sev", [(True, 600, False, "high"), (False, 0, True, "high"),
                                                  (True, 10, False, "moderate"), (False, 0, False, "low")])
def test_classify(pii, records, down, sev):
    assert _inc(pii).classify(records, down) == sev


def test_custody_chain():
    i = _inc()
    arts = {"disk.img": b"image", "log.txt": b"log"}
    for n, b in arts.items():
        i.add_artifact(n, b, "a.chen", "2026-10-30T09:30:00")
    assert i.custody_intact(arts)
    assert not i.custody_intact({**arts, "disk.img": b"changed"})
    i.custody[0]["handler"] = "someone"
    assert not i.custody_intact(arts)


def test_playbook_fallback():
    assert _inc().playbook() and incident.Incident("x", "t", "2026-10-30T00:00:00", "unknown", False).playbook()


# ---------- governance ----------
def _policy():
    p = governance.Policy("POL-AC", "Access control policy", "k.osei", ("AC-01",))
    return governance.transition(governance.new_version(p, "v1 text"), "in_review")


def test_policy_lifecycle_and_acks():
    p = governance.approve(_policy(), "r.alvarez", "2026-01-15")
    p = governance.acknowledge(p, "u1")
    assert governance.ack_rate(p, ["u1", "u2"]) == 50.0
    p2 = governance.approve(governance.transition(governance.new_version(p, "v2"), "in_review"), "r.alvarez")
    assert governance.ack_rate(p2, ["u1", "u2"]) == 0.0   # new version needs new acknowledgment


def test_owner_cannot_approve_own_policy():
    with pytest.raises(PermissionError):
        governance.approve(_policy(), "k.osei")


def test_illegal_transition():
    with pytest.raises(ValueError):
        governance.transition(governance.Policy("P", "t", "o", ()), "approved")


@pytest.mark.parametrize("approved_on,status", [("2025-10-01", "overdue"), ("2025-11-15", "due_soon"),
                                                ("2026-06-01", "ok")])
def test_review_due(approved_on, status):
    assert governance.review_due(governance.approve(_policy(), "r", approved_on))["status"] == status


# ---------- resilience ----------
def test_rpo_status_is_honest(evidence):
    got = sorted(r["rpo_status"].split(" ")[0] for r in resilience.coverage(evidence))
    assert got == ["met", "missed", "unproven", "unproven"]


def test_exercise_status():
    s = resilience.exercise_status()
    assert s["cp04_met"] and s["age_days"] == 200


# ---------- audit ----------
def test_evidence_repo_versions():
    r = audit.EvidenceRepo()
    r.put("scan.csv", b"v1", "a")
    r.put("scan.csv", b"v2", "a")
    assert r.latest("scan.csv")["version"] == 2 and len(r.history("scan.csv")) == 2
    assert r.verify("scan.csv", b"v1", version=1) and not r.verify("scan.csv", b"v1")


def test_audit_plan_ranks_by_fail_rate(findings):
    plan = audit.audit_plan(assess.by_control(findings), {c.family: c.family for c in catalog.baseline("ae")})
    assert [p["family"] for p in plan[:4]] == ["AT", "SI", "CM", "SR"]
    assert plan[0]["fail_rate"] == 0.857


def test_audit_finding_flow():
    f = audit.AuditFinding("AF-1", "t", "AC-02", "high", "k.osei")
    f.advance("k.osei")
    with pytest.raises(PermissionError):
        f.advance("k.osei")
    assert f.advance("auditor") == "validated" and f.advance("auditor") == "closed"
    with pytest.raises(ValueError):
        f.advance("auditor")


# ---------- internal audit (module import keeps pytest from collecting test_effectiveness) ----------
def test_internal_audit_sampling():
    c = internal_audit.CONTROLS[0]
    pop = [True] * 100
    assert internal_audit.test_effectiveness(c, pop)["conclusion"] == "effective"
    assert internal_audit.test_effectiveness(c, [False] * 100)["conclusion"] == "deficiency"
    assert internal_audit.test_effectiveness(c, pop) == internal_audit.test_effectiveness(c, pop)


def test_internal_audit_self_assessment_and_kcis():
    sa = internal_audit.self_assessment({"FC-01": {"designed": 1, "operating": 1, "evidence": 1}})
    assert not sa[0]["gaps"] and sa[1]["gaps"]
    k = internal_audit.kcis([internal_audit.test_effectiveness(c, [True] * 50) for c in internal_audit.CONTROLS])
    assert k["effective_pct"] == 100.0 and sorted(k["coso_coverage"]) == sorted(internal_audit.COSO)


# ---------- regulatory change and custom frameworks ----------
def test_regchange_impact_measured():
    assert [(r["change"], r["count"]) for r in regchange.run()] == [("RC-01", 1), ("RC-02", 10), ("RC-03", 74)]


def test_custom_framework_score(findings):
    assert custom.score(custom.load(), assess.by_control(findings))["score_pct"] == 16.7


@pytest.mark.parametrize("bad", [custom.EXAMPLE.replace("SR-08", "SR-99"),
                                 custom.EXAMPLE.replace("scoring: weighted", "scoring: vibes")])
def test_custom_framework_rejects_bad_yaml(bad):
    assert bad != custom.EXAMPLE
    with pytest.raises(ValueError):
        custom.load(bad)


# ---------- automation ----------
def test_scheduler_30_days(poam_items):
    runs = scheduler.simulate(30, poam_items=poam_items)["runs"]
    assert runs["run_config_checks"] == 30 and runs["weekly_log_review_reminder"] == 4
    assert runs["monthly_conmon_report"] == 1


def test_ai_auditor_measured(evidence):
    r = ai_auditor.run(evidence)
    assert (r["reviewed"], r["ready"], r["needs_work"], r["signed_off"]) == (153, 101, 52, 0)


ISSO = Principal("r.alvarez", "t-lhx", ("isso",), mfa=True, phishing_resistant=True)


def test_signoff_rules(evidence):
    rows = ai_auditor.run(evidence)["rows"]
    good = next(r for r in rows if r["recommendation"] == "ready for sign-off")
    weak = next(r for r in rows if r["recommendation"] != "ready for sign-off")
    assert ai_auditor.sign_off(good, ISSO, "accepted", "looks right", uploader="k.osei").decision == "accepted"
    with pytest.raises(AccessDenied):
        ai_auditor.sign_off(weak, ISSO, "accepted", "fine", uploader="k.osei")
    ai_auditor.sign_off(weak, ISSO, "accepted", "Override: compensating evidence in ticket", uploader="k.osei")
    with pytest.raises(AccessDenied):
        ai_auditor.sign_off(good, ISSO, "accepted", "mine", uploader="r.alvarez")
    with pytest.raises(AccessDenied):
        ai_auditor.sign_off(good, Principal("x", "t-lhx", ("isso",)), "accepted", "no mfa", uploader="k.osei")


# ---------- challenges ----------
def test_readiness_measured(findings, poam_items):
    approvals = json.loads((catalog.DATA / "approvals.json").read_text()) if hasattr(catalog, "DATA") else None
    if approvals is None:
        from arcampe import DATA
        approvals = json.loads((DATA / "approvals.json").read_text())
    r = audit_readiness.readiness(findings, poam_items, approvals)
    assert r["score"] == 57.5 and r["parts"]["statements_approved"] == 3.0
    assert abs(sum(r["weights"].values()) - 1) < 1e-9


@pytest.mark.parametrize("score,band", [(9.0, "critical"), (7.0, "high"), (4.0, "moderate"), (0.1, "low"),
                                        (0.0, "none")])
def test_scoring_bands(score, band):
    assert scoring.band(score) == band


def test_response_metrics(poam_items):
    m = response.metrics(poam_items)
    assert (m["open"], m["overdue"], m["pct_within_sla"]) == (103, 22, 78.6)


def test_business_context_top_risk(findings):
    top = business_context.ranked(findings)[0]
    assert (top["check"], top["resource"], top["exceeds_appetite"]) == ("AZ-03", "stlhxarchive", True)


def test_visibility_and_third_party(findings):
    assert visibility.unified_view(findings)["sources"] == 6
    v = third_party.view()
    assert len(v) == 6 and v[0]["score"] == 81


# ---------- reporting ----------
def test_conmon_html_is_escaped(findings):
    m = conmon.metrics(findings)
    html = conmon.to_html(m)
    assert "Content-Security-Policy" in html and "<script" not in html
    assert conmon.to_markdown(m).startswith("#")


def test_binder_deterministic_and_verifiable(findings):
    a, b = binder.build(findings), binder.build(findings)
    assert a == b and binder.verify(a) == []
    z = zipfile.ZipFile(io.BytesIO(a))
    files = {n: z.read(n) for n in z.namelist()}
    files["02_poam/poam.csv"] += b"tampered"
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as w:
        for n, d in files.items():
            w.writestr(n, d)
    assert binder.verify(out.getvalue()) == ["02_poam/poam.csv"]


@pytest.mark.parametrize("cmd", ["catalog", "assess", "poam", "attest", "trust", "integrations", "schedule",
                                 "audit", "conmon"])
def test_cli_commands(cmd, tmp_path, capsys):
    assert main([cmd, "--out", str(tmp_path)]) == 0
    assert capsys.readouterr().out.strip()


# ---------- IaC parity ----------
def test_policy_parity_with_python_checks(findings):
    p = iac.parity(load_estate(), findings)
    assert p["policy_hits"] == p["python_fails"] == p["both"] == 6
    assert not p["policy_only"] and not p["python_only"]
