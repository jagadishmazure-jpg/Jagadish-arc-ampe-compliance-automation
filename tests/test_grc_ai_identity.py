import copy
import dataclasses

import pytest

from arcampe import resilience
from arcampe.grc import ai_governance as g
from arcampe.integrations import schema


# ---------------------------------------------------------------- shadow AI
def test_shadow_ai_measured():
    s = {x["tool"]: x for x in g.shadow_ai()}
    assert len(s) == 4
    assert s["Slide generator plug-in"]["status"] == "overdue"
    assert s["Browser AI extension"]["status"] == "open"
    assert s["Meeting transcriber app"]["within_sla"] is False


def test_approved_tools_not_flagged():
    assert not set(x["tool"] for x in g.shadow_ai()) & set(g.APPROVED_AI_TOOLS)


@pytest.mark.parametrize("row", g.shadow_ai(), ids=lambda r: r["tool"])
def test_shadow_routed_to_owner(row):
    assert row["owner"] and not row["owner"].startswith("agent:")


def test_shadow_open_becomes_overdue_later():
    s = {x["tool"]: x for x in g.shadow_ai("2026-11-30")}
    assert s["Browser AI extension"]["status"] == "overdue"


# ---------------------------------------------------------------- decision rights
def test_decision_rights_gap_is_vendor():
    assert g.decision_rights_gaps() == ["AI-VENDOR"] and g.decision_rights_coverage() == 80.0


@pytest.mark.parametrize("cid", sorted(g.AI_CONTROLS))
def test_decision_rights_have_proposer_and_human_approver(cid):
    r = g.AI_CONTROLS[cid]
    assert r["proposes"] and r["approves"] and not r["approves"].startswith("agent:")


def test_agent_approver_is_a_gap(monkeypatch):
    rights = copy.deepcopy(g.AI_CONTROLS)
    rights["AI-SHADOW"]["approves"] = "agent:discovery"
    monkeypatch.setattr(g, "AI_CONTROLS", rights)
    assert "AI-SHADOW" in g.decision_rights_gaps()


# ---------------------------------------------------------------- decision records and replay
@pytest.fixture(scope="module")
def log():
    return g.decision_log()


def test_log_size_and_kind(log):
    assert len(log) == 60 and all(r.kind == "ai_decision_record" for r in log)
    assert all(schema.verify(r) for r in log)


def test_explainability_measured(log):
    assert sum(map(g.complete, log)) == 58


@pytest.mark.parametrize("field", g.REQUIRED_FIELDS)
def test_record_has_field(log, field):
    assert field in log[0].attributes


def test_record_hints():
    r = g.decision_record("agent:x", "m", "1", "text", {"item": "i"}, ["g"], ["c"], "Riley", "accepted")
    assert "AI-DECISION-RECORD" in r.control_hints and g.complete(r)


def test_incomplete_without_approver():
    r = g.decision_record("agent:x", "m", "1", "text", {"item": "i"}, ["g"], ["c"], "", "accepted")
    assert not g.complete(r)


def test_replay_good(log):
    assert g.replay(log[0])


def test_replay_detects_tampered_output(log):
    assert not g.replay(log[17])


def test_replay_detects_changed_input(log):
    a = dict(log[0].attributes, input=log[0].attributes["input"] + " extra")
    assert not g.replay(dataclasses.replace(log[0], attributes=a))


def test_replay_audit_measured(log):
    r = g.replay_audit(log)
    assert (r["sampled"], r["reproduced"], r["pass_rate"]) == (25, 24, 96.0)


def test_replay_audit_full_population(log):
    r = g.replay_audit(log, n=100)
    assert r["sampled"] == 60 and r["reproduced"] == 59


def test_replay_audit_empty():
    assert g.replay_audit([], n=5)["pass_rate"] == 0.0


# ---------------------------------------------------------------- KPIs
def test_monitoring_coverage():
    m = g.monitoring_coverage()
    assert m["pct"] == 83.3 and m["unmonitored"] == ["agent:copilot"]


def test_autonomy_levels_valid():
    assert all(a["autonomy"] in g.AUTONOMY_LEVELS for a in g.AGENTS)
    assert not any(a["autonomy"] == "act_then_notify" for a in g.AGENTS)


def test_vendor_concentration():
    assert g.vendor_concentration() == {"top1_provider": "Provider A", "top1_share_pct": 60.0, "top2_share_pct": 80.0,
                                        "with_fallback_pct": 60.0}


def test_legal_risk_blocks():
    r = g.legal_risk_blocks()
    assert r["blocked"] == 6 and r["by_severity"] == {"critical": 3, "high": 2, "moderate": 1}


def test_approvals(log):
    a = g.approvals(log)
    assert a["override_rate_pct"] == 11.7 and a["median_hours_to_approve"] == 9.0


def test_twelve_kpis():
    k = g.kpis()
    assert len(k) == 12 and len({x["kpi"] for x in k}) == 12


@pytest.mark.parametrize("name", ["explainability", "Decision-audit", "monitoring coverage", "override",
                                  "Autonomy", "decision-rights", "Shadow AI", "concentration", "regulatory",
                                  "legal-risk", "ROI", "outage"])
def test_kpi_present(name):
    assert any(name.lower() in x["kpi"].lower() for x in g.kpis())


def test_roi_labeled_simulated():
    roi = next(x for x in g.kpis() if "ROI" in x["kpi"])
    assert roi["basis"] == "SIMULATED"


# ---------------------------------------------------------------- identity resilience
def test_identity_in_every_bia_row():
    assert all(resilience.IDENTITY in b["depends_on"] for b in resilience.BIA)


def test_identity_top_dependency():
    dc = resilience.dependency_concentration()
    assert max(dc, key=dc.get) == resilience.IDENTITY and dc[resilience.IDENTITY] == len(resilience.BIA)


def test_identity_evidence_kinds_and_controls():
    ev = resilience.identity_evidence()
    kinds = {e.kind for e in ev}
    assert kinds == {"identity_backup_job", "identity_restore_drill"} and all(schema.verify(e) for e in ev)
    hints = {c for e in ev for c in e.control_hints}
    assert {"CP-04", "CP-09", "CP-10"} <= hints


@pytest.mark.parametrize("cid,passed", [
    ("IDR-BK-ad_forest", True), ("IDR-IMM-ad_forest", True), ("IDR-ISO-ad_forest", True),
    ("IDR-BK-entra_tenant", True), ("IDR-IMM-entra_tenant", True), ("IDR-ISO-entra_tenant", False),
    ("IDR-ENTRA-COVER", False), ("IDR-DRILL-365", True), ("IDR-RTO", False), ("IDR-KRBTGT", True),
    ("IDR-ORDER", True)])
def test_identity_checks(cid, passed):
    r = {x["id"]: x for x in resilience.identity_checks()}
    assert r[cid]["passed"] is passed


def test_identity_checks_map_controls():
    assert {r["control"] for r in resilience.identity_checks()} == {"CP-04", "CP-09", "CP-10"}


def test_identity_backup_goes_stale():
    r = {x["id"]: x for x in resilience.identity_checks(today="2026-11-10")}
    assert not r["IDR-BK-ad_forest"]["passed"]


def test_identity_drill_goes_stale():
    r = {x["id"]: x for x in resilience.identity_checks(today="2027-06-01")}
    assert not r["IDR-DRILL-365"]["passed"]


def test_identity_no_evidence_fails_everything():
    assert not any(r["passed"] for r in resilience.identity_checks([]))


def test_identity_kpis():
    k = resilience.identity_kpis()
    assert k == {"measured_rto_hours": 11.5, "target_rto_hours": 8, "rto_met": False, "days_since_drill": 172,
                 "backup_age_hours": 24, "entra_object_coverage_pct": 75.0, "checks_passed": 8, "checks": 11}


def test_report_has_ai_and_identity_sections():
    from arcampe.grc import reporting
    m = reporting.metrics()
    w, d = reporting.to_html(m, "weekly"), reporting.to_html(m, "daily")
    assert "AI Governance &amp; Accountability" in w and "Identity recovery" in w
    assert w.count("<tr>") > d.count("<tr>")
    assert "Decision-audit pass rate" in w and "Decision-audit pass rate" not in d


# ---------------------------------------------------------------- approved model and app register
def test_register_summary():
    assert g.register_summary() == {"entries": 5, "by_status": {"approved": 3, "conditional": 1, "retired": 1},
                                    "uses": 7, "uses_compliant": 3, "inventory_coverage_pct": 83.3}


@pytest.mark.parametrize("user,name,problem", [
    ("BU-MKT", "Code assistant (enterprise tier)", "data class pii not allowed"),
    ("agent:tprm", "Summarizer v0 (retired)", "retired entry still in use"),
    ("agent:copilot", "Foundry-hosted drafter", "tool assign_owner not allowed"),
    ("BU-MKT", "Browser AI extension", "not in register")])
def test_register_problem(user, name, problem):
    r = next(x for x in g.register_checks() if x["user"] == user and x["name"] == name)
    assert problem in r["problems"] and not r["passed"]


@pytest.mark.parametrize("entry", g.MODEL_REGISTER, ids=lambda e: e["id"])
def test_register_entry_fields(entry):
    assert entry["owner"] and not entry["owner"].startswith("agent:")
    assert entry["status"] in ("approved", "conditional", "retired")
    assert any(m.startswith(("ISO42001", "NIST_AI_RMF")) for m in entry["maps_to"])


def test_register_evaluation_ages_out():
    r = {x["register_id"]: x for x in g.register_checks("2027-06-01") if x["register_id"]}
    assert "evaluation older than 180 days" in r["AIM-03"]["problems"]


def test_register_unknown_lookup():
    assert g.register_entry("nope") is None


def test_register_in_weekly_report_only():
    from arcampe.grc import reporting
    m = reporting.metrics()
    assert "Approved AI model and app register" in reporting.to_html(m, "weekly")
    assert "Approved AI model and app register" not in reporting.to_html(m, "daily")
    assert "ai_register,uses_compliant" in reporting.to_csv(m)
