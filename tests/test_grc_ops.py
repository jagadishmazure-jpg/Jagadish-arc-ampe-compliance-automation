import copy
import dataclasses

import pytest

from arcampe import catalog
from arcampe.grc import access_review_import as ar
from arcampe.grc import evidence_status as es
from arcampe.grc import ownership as ow
from arcampe.grc import vendor_requests as vr
from arcampe.integrations import schema
from arcampe.integrations.connectors import collect_all


@pytest.fixture(scope="module")
def ev():
    return collect_all()


def _e(kind, observed):
    return schema.make("lakehaven", "test", "platform", kind, "s", observed, {"a": 1}, ("AC-02",))


# ---------------------------------------------------------------- evidence status
def test_statuses_named():
    assert es.STATUSES == ("Needs Artifact", "Needs Renewal", "Upcoming Renewal", "Ready", "Error")


@pytest.mark.parametrize("kind,observed,status", [
    ("account", "2026-10-30", "Ready"), ("account", "2026-10-10", "Upcoming Renewal"),
    ("account", "2026-09-01", "Needs Renewal"), ("training", "2026-01-01", "Ready"),
    ("training", "2025-11-10", "Upcoming Renewal"), ("training", "2025-06-01", "Needs Renewal"),
    ("backup_job", "2026-10-20", "Needs Renewal"), ("unknown_kind", "2026-09-01", "Ready"),
    ("unknown_kind", "2026-08-10", "Upcoming Renewal")])
def test_classify(kind, observed, status):
    assert es.classify(_e(kind, observed))["status"] == status


def test_tampered_is_error():
    e = dataclasses.replace(_e("account", "2026-10-30"), attributes={"a": 2})
    assert es.classify(e)["status"] == "Error"


def test_bad_date_is_error():
    e = dataclasses.replace(_e("account", "2026-10-30"), observed_at="not-a-date")
    assert es.classify(e)["status"] == "Error"


def test_renew_by():
    assert es.classify(_e("account", "2026-10-01"))["renew_by"] == "2026-10-31"


def test_needs_artifact():
    assert es.needs_artifact([_e("account", "2026-10-30")], ["AC-02", "PE-03"]) == ["PE-03"]


def test_summary_measured(ev):
    s = es.summary(ev)
    assert s["counts"] == {"Needs Artifact": 0, "Needs Renewal": 24, "Upcoming Renewal": 11, "Ready": 118, "Error": 0}
    assert s["fresh_pct"] == 84.3 and s["records"] == 153


def test_summary_with_controls(ev):
    s = es.summary(ev, ["AC-02", "PE-17"])
    assert s["counts"]["Needs Artifact"] == len(s["missing"])


def test_summary_empty():
    assert es.summary([])["fresh_pct"] == 0.0


def test_freshness_drops_with_time(ev):
    assert es.summary(ev, today="2027-06-01")["fresh_pct"] < es.summary(ev)["fresh_pct"]


# ---------------------------------------------------------------- ownership
@pytest.mark.parametrize("due,level,notify", [
    ("2026-11-05", "none", None), ("2026-10-31", "owner", "isso"), ("2026-10-20", "owner", "isso"),
    ("2026-10-16", "manager", "ciso"), ("2026-10-01", "ciso", "ciso"), ("2026-06-01", "ciso", "ciso")])
def test_escalation_isso(due, level, notify):
    e = ow.escalation("isso", due)
    assert (e["level"], e["notify"]) == (level, notify)


def test_escalation_manager_lookup():
    assert ow.escalation("cloud-platform", "2026-10-10")["notify"] == "platform-manager"


def test_escalation_unknown_owner_manager_is_ciso():
    assert ow.escalation("nobody", "2026-10-10")["notify"] == "ciso"


def test_days_late_never_negative():
    assert ow.escalation("isso", "2027-01-01")["days_late"] == 0


def test_ladder_counts_measured():
    assert ow.ladder_counts() == {"owner": 6, "manager": 2, "ciso": 14}


def test_overdue_tasks_have_items():
    t = ow.overdue_tasks()
    assert len(t) == 22 and all(x["item"].startswith("POAM-") for x in t)


def test_suggest_default_owner():
    b = ow.OwnershipBoard()
    s = b.suggest([catalog.by_id()["PE-03"]])
    assert s[0]["owner"] == "facilities-security" and s[0]["status"] == "suggested"


def test_suggest_learns_from_family():
    b = ow.OwnershipBoard(owners={"PE-02": "site-lead", "PE-06": "site-lead"})
    s = b.suggest([catalog.by_id()["PE-03"]])
    assert s[0]["owner"] == "site-lead" and "owns 2" in s[0]["why"]


def test_suggest_skips_owned():
    b = ow.OwnershipBoard(owners={"PE-03": "x"})
    assert b.suggest([catalog.by_id()["PE-03"]]) == []


def test_agent_cannot_approve():
    b = ow.OwnershipBoard()
    b.suggest([catalog.by_id()["PE-03"]])
    with pytest.raises(PermissionError):
        b.approve("PE-03", "agent:ownership")
    assert "PE-03" not in b.owners


def test_approve_and_edit_and_reject():
    b = ow.OwnershipBoard()
    b.suggest([catalog.by_id()[c] for c in ("PE-03", "PE-06", "MA-02")])
    b.approve("PE-03", "Riley")
    b.approve("PE-06", "Riley", owner="site-lead")
    b.reject("MA-02", "Riley", "wrong team")
    assert b.owners == {"PE-03": "facilities-security", "PE-06": "site-lead"}
    assert b.acceptance_rate() == round(1 / 3, 3)


def test_acceptance_rate_empty():
    assert ow.OwnershipBoard().acceptance_rate() == 0.0


def test_suggestions_never_assign():
    b = ow.OwnershipBoard()
    b.suggest(catalog.baseline("ae"))
    assert b.owners == {} and len(b.suggestions) == len(catalog.baseline("ae"))


# ---------------------------------------------------------------- vendor requests
def _req():
    return vr.VendorRequest("VR-1", "Testco", "svc", "pat")


def test_demo_measured():
    d = {r["id"]: r for r in vr.demo()}
    assert d["VR-101"]["state"] == "approved" and d["VR-102"]["breached"] is True
    assert d["VR-103"]["state"] == "rejected" and d["VR-103"]["score"] == 50


def test_questionnaire_simulated():
    r = _req()
    r.intake("proc", True, 10)
    msg = r.send_questionnaire("proc", "sec@testco.example")
    assert msg["sent"] is False and msg["mode"] == "simulated" and len(msg["questions"]) == 7


@pytest.mark.parametrize("pii,spend,tier", [(True, 300_000, "critical"), (True, 10, "high"), (False, 150_000, "moderate"),
                                            (False, 10, "low")])
def test_intake_tier(pii, spend, tier):
    assert _req().intake("proc", pii, spend) == tier


def test_negative_spend():
    with pytest.raises(vr.RequestError):
        _req().intake("proc", False, -1)


def test_bad_contact():
    r = _req()
    r.intake("proc", False, 1)
    with pytest.raises(vr.RequestError):
        r.send_questionnaire("proc", "not-an-email")


def test_skip_steps_refused():
    with pytest.raises(vr.RequestError):
        _req().send_questionnaire("proc", "a@b.example")


def _answered(answers=None):
    r = _req()
    r.intake("proc", True, 10)
    r.send_questionnaire("proc", "a@b.example")
    r.record_answers("proc", answers or {q: True for q in vr.QUESTIONS})
    return r


@pytest.mark.parametrize("answers", [{"Q99": True}, {"Q1": "yes"}])
def test_bad_answers(answers):
    r = _req()
    r.intake("proc", True, 10)
    r.send_questionnaire("proc", "a@b.example")
    with pytest.raises(vr.RequestError):
        r.record_answers("proc", answers)


def test_review_routes_approver():
    r = _answered()
    res = r.review("agent:tprm")
    assert res["approver_role"] == "procurement-lead" and res["gaps"] == []


def test_review_high_band_needs_ciso():
    r = _answered({q: False for q in vr.QUESTIONS})
    assert r.review("agent:tprm")["approver_role"] == "ciso"


@pytest.mark.parametrize("actor,role,note", [("agent:tprm", "ciso", "x"), ("pat", "ciso", "x"),
                                             ("Dana", "engineer", "x"), ("Dana", "procurement-lead", " ")])
def test_decide_guards(actor, role, note):
    r = _answered()
    r.review("agent:tprm")
    with pytest.raises(vr.RequestError):
        r.decide(actor, role, True, note)


def test_ciso_can_always_decide():
    r = _answered()
    r.review("agent:tprm")
    r.decide("Morgan", "ciso", True, "fine")
    assert r.state == "approved"


def test_sla_done_never_breached():
    r = _answered()
    r.opened = "2026-01-01"
    r.review("x")
    r.decide("Morgan", "ciso", False, "no")
    assert r.sla()["breached"] is False


# ---------------------------------------------------------------- access review import
@pytest.fixture(scope="module")
def export():
    return ar.load()


def test_fixture_valid(export):
    assert ar.validate(export) == [] and len(export["rows"]) == 48


def test_access_summary_measured(export):
    s = ar.summarize(export)
    assert s["reviewed"] == 47 and s["complete_pct"] == 97.9 and s["late"] is True
    assert s["issues"] == {"pending": 1, "self_review": 1, "terminated_not_revoked": 2, "stale_admin_kept": 5}


@pytest.mark.parametrize("key", ["campaign", "period", "due", "apps", "rows"])
def test_validate_missing(export, key):
    e = copy.deepcopy(export)
    e.pop(key)
    assert any(key in x for x in ar.validate(e))


def test_validate_bad_rows(export):
    e = copy.deepcopy(export)
    e["rows"][0]["app"] = "APP-NOPE"
    e["rows"][1]["decision"] = "maybe"
    e["rows"][2].update(decision="modify")
    e["rows"][2].pop("new_role", None)
    errs = ar.validate(e)
    assert len(errs) == 3


def test_to_evidence(export):
    out = ar.to_evidence(export)
    assert len(out) == 4 and all(schema.verify(x) and x.kind == "access_review" for x in out)
    assert all("AC-02" in x.control_hints for x in out)
    assert all(x.attributes["soc2"] == ["CC6.2", "CC6.3"] for x in out)


def test_to_evidence_rejects_invalid(export):
    e = copy.deepcopy(export)
    e["rows"][0]["app"] = "APP-NOPE"
    with pytest.raises(ValueError):
        ar.to_evidence(e)


def test_controls_exist():
    ids = catalog.by_id()
    assert all(c in ids for c in ("AC-02", "AC-02(03)", "AC-06(07)"))


def test_not_late_before_due(export):
    assert ar.summarize(export, today="2026-10-20")["late"] is False


def test_complete_campaign_not_late(export):
    e = copy.deepcopy(export)
    for r in e["rows"]:
        r["decision"] = r["decision"] or "keep"
    assert ar.summarize(e)["late"] is False
