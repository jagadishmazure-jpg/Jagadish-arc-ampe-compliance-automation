import pytest

from arcampe import catalog
from arcampe.checks.base import Finding
from arcampe.grc import workflows as wf
from arcampe.grc import workspaces as ws


# ---------------------------------------------------------------- workspaces
def test_four_units():
    assert [u.id for u in ws.UNITS] == ["BU-MKT", "BU-CSO", "BU-INF", "BU-PMO"]


def test_every_family_in_exactly_one_unit():
    fams = [f for u in ws.UNITS for f in u.families]
    assert len(fams) == len(set(fams)) == 20


@pytest.mark.parametrize("fam", sorted({c.family for c in catalog.baseline("ae")}))
def test_unit_for_family(fam):
    assert fam in ws.unit_for_family(fam).families


def test_unit_for_unknown_family():
    with pytest.raises(KeyError):
        ws.unit_for_family("ZZ")


def test_unit_lookup_and_unknown():
    assert ws.unit("BU-CSO").name == "Consumer Services"
    with pytest.raises(KeyError):
        ws.unit("BU-NOPE")


def test_assign_covers_baseline_once():
    a = ws.assign()
    ids = [c for v in a.values() for c in v]
    assert sorted(ids) == sorted(c.id for c in catalog.baseline("ae"))


@pytest.mark.parametrize("uid", [u.id for u in ws.UNITS])
def test_assigned_controls_match_unit_families(uid):
    fams = ws.unit(uid).families
    assert all(catalog.by_id()[c].family in fams for c in ws.assign()[uid])


def test_expired_exception_is_exc02():
    assert [e["id"] for e in ws.expired_exceptions()] == ["EXC-02"]


def test_active_exceptions_exclude_expired():
    assert "EXC-02" not in [e["id"] for e in ws.active_exceptions()]
    assert len(ws.active_exceptions()) == 3


@pytest.mark.parametrize("uid,n", [("BU-MKT", 1), ("BU-CSO", 1), ("BU-INF", 0), ("BU-PMO", 1)])
def test_active_exceptions_per_unit(uid, n):
    assert len(ws.active_exceptions(uid)) == n


def test_exceptions_expire_later():
    assert len(ws.active_exceptions(today="2027-06-01")) == 0


@pytest.mark.parametrize("e", ws.EXCEPTIONS, ids=lambda e: e["id"])
def test_exception_controls_exist_and_in_unit(e):
    c = catalog.by_id()[e["control"]]
    assert c.family in ws.unit(e["unit"]).families


def test_readiness_rows_measured():
    r = {x["unit"]: x for x in ws.readiness()}
    assert r["BU-MKT"]["readiness_pct"] == 23.3
    assert r["BU-MKT"]["passing"] == 14 and r["BU-MKT"]["tested"] == 60


@pytest.mark.parametrize("uid", [u.id for u in ws.UNITS])
def test_readiness_arithmetic(uid):
    r = next(x for x in ws.readiness() if x["unit"] == uid)
    assert r["passing"] + r["failing"] == r["tested"]
    assert r["tested"] + r["untested"] == r["controls"]
    assert 0 <= r["readiness_pct"] <= 100


def test_readiness_with_custom_status():
    by = {c: {"status": "pass"} for c in ws.assign()["BU-INF"]}
    r = next(x for x in ws.readiness(by) if x["unit"] == "BU-INF")
    assert r["readiness_pct"] == 100.0


def test_readiness_empty_is_zero():
    assert all(r["readiness_pct"] == 0.0 for r in ws.readiness({}))


def test_table_has_all_units():
    t = ws.table()
    assert all(u.name in t for u in ws.UNITS)


# ---------------------------------------------------------------- workflows
def _w(**kw):
    d = {"id": "WF-X", "name": "x", "trigger": "control.not_ready",
         "actions": [{"type": "ticket", "target": "itsm:X", "template": "{control}"}]}
    d.update(kw)
    return d


def test_defaults_valid():
    assert all(not wf.validate(wf.build(d)) for d in wf.DEFAULT)


def test_unknown_trigger():
    with pytest.raises(wf.WorkflowError):
        wf.build(_w(trigger="nope"))


def test_no_actions():
    with pytest.raises(wf.WorkflowError):
        wf.build(_w(actions=[]))


def test_unknown_action_type():
    with pytest.raises(wf.WorkflowError):
        wf.build(_w(actions=[{"type": "email", "target": "x", "template": "x"}]))


@pytest.mark.parametrize("field", ["password", "__class__", "token", "attributes"])
def test_template_field_whitelist(field):
    with pytest.raises(wf.WorkflowError):
        wf.build(_w(actions=[{"type": "ticket", "target": "x", "template": "{" + field + "}"}]))


@pytest.mark.parametrize("url", ["http://hooks.lakehaven-hx.example/x", "https://evil.example/x",
                                 "https://hooks.lakehaven-hx.example.evil.example/x", "ftp://hooks.lakehaven-hx.example"])
def test_webhook_rejected(url):
    with pytest.raises(wf.WorkflowError):
        wf.build(_w(actions=[{"type": "webhook", "target": url, "template": "x"}]))


@pytest.mark.parametrize("url", ["https://hooks.lakehaven-hx.example/a", "https://itsm.lakehaven-hx.example/b"])
def test_webhook_allowed(url):
    assert wf.build(_w(actions=[{"type": "webhook", "target": url, "template": "x"}]))


def test_unknown_operator():
    with pytest.raises(wf.WorkflowError):
        wf.build(_w(conditions=[{"field": "severity", "op": "regex", "value": "x"}]))


@pytest.mark.parametrize("op,val,event_val,expected", [
    ("eq", "a", "a", True), ("eq", "a", "b", False), ("ne", "a", "b", True), ("in", ["a", "b"], "b", True),
    ("in", ["a"], "c", False), ("contains", "pub", "public", True), ("contains", "x", 5, False),
    ("gte", 15, 20, True), ("gte", 15, 3, False), ("lte", 5, 3, True), ("gte", 1, None, False)])
def test_condition_ops(op, val, event_val, expected):
    assert wf.Condition("f", op, val).holds({"f": event_val}) is expected


@pytest.mark.parametrize("sev,expected", [("critical", True), ("high", True), ("moderate", False), ("low", False)])
def test_severity_rank(sev, expected):
    assert wf.Condition("severity", "gte", "high").holds({"severity": sev}) is expected


def test_severity_lte():
    assert wf.Condition("severity", "lte", "moderate").holds({"severity": "low"})


def test_emit_unknown_event():
    with pytest.raises(wf.WorkflowError):
        wf.default_engine().emit({"event": "bogus"})


def test_emit_high_fires_three_actions_not_sent():
    out = wf.default_engine().emit({"event": "control.not_ready", "control": "AC-02", "severity": "high"})
    assert [r["action"] for r in out] == ["ticket", "slack", "webhook"]
    assert all(r["sent"] is False and r["status"] == "simulated" for r in out)


def test_emit_moderate_fires_nothing():
    assert wf.default_engine().emit({"event": "control.not_ready", "control": "AC-02", "severity": "moderate"}) == []


def test_template_missing_field_dash():
    out = wf.default_engine().emit({"event": "control.edited_after_compliant"})
    assert out[0]["body"] == "Re-review -: edited after compliant"


def test_disabled_workflow_skips():
    e = wf.Engine([wf.build(_w(enabled=False))])
    assert e.emit({"event": "control.not_ready", "control": "X"}) == []


def test_fanout_cap():
    acts = [{"type": "ticket", "target": f"itsm:{i}", "template": "x"} for i in range(15)]
    e = wf.Engine([wf.build(_w(actions=acts))])
    assert len(e.emit({"event": "control.not_ready"})) == wf.MAX_ACTIONS_PER_EVENT
    assert any(x.action == "fanout.blocked" for x in e.log.entries())


def test_overdue_escalation_threshold():
    e = wf.default_engine()
    assert e.emit({"event": "poam.overdue", "control": "SI-02", "days_overdue": 10}) == []
    assert len(e.emit({"event": "poam.overdue", "control": "SI-02", "days_overdue": 20})) == 2


def test_log_chain_verifies():
    e = wf.default_engine()
    e.emit({"event": "vendor.requested", "resource": "Acme", "owner": "pat"})
    assert e.log.verify()[0]


def test_events_from_findings_only_failures():
    f = [Finding("AZ-01", "r1", "n1", False, "high", ("SC-07",), "d"),
         Finding("AZ-01", "r2", "n2", True, "high", ("SC-07",), "d")]
    ev = wf.events_from_findings(f)
    assert len(ev) == 1 and ev[0]["owner"] == "cloud-platform" and ev[0]["control"] == "SC-07"


def test_run_on_findings_measured(findings):
    r = wf.run_on_findings(findings)
    assert r["events"] == 103 and r["actions"] == 129 and r["sent"] == 0
    assert r["by_action"] == {"ticket": 43, "slack": 43, "webhook": 43}
    assert "BROKEN" not in r["log"]
