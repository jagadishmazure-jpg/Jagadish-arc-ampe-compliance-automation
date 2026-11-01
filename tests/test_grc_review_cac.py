import copy

import pytest

from arcampe.checks import registry
from arcampe.checks.base import Finding
from arcampe.grc import cac
from arcampe.grc import review as rv


def _ready():
    r = rv.ControlReview("AC-02", "olive", {"statement": "s", "evidence": ["ev-1"]})
    r.start("olive")
    r.submit("olive")
    return r


# ---------------------------------------------------------------- review
def test_states_listed():
    assert set(rv.ALLOWED) <= set(rv.STATES)


def test_happy_path():
    r = _ready()
    r.approve("Riley", "isso", "looks right")
    assert r.state == "passing" and r.approved_hash == rv.content_hash(r.content)


@pytest.mark.parametrize("who,role,note,msg", [
    ("agent:copilot", "isso", "ok", "AI agent"), ("Riley", "engineer", "ok", "not an expert"),
    ("olive", "isso", "ok", "separation"), ("Riley", "isso", "  ", "note")])
def test_approve_guards(who, role, note, msg):
    r = _ready()
    with pytest.raises(rv.ReviewError, match=msg):
        r.approve(who, role, note)


@pytest.mark.parametrize("role", sorted(rv.EXPERT_ROLES))
def test_expert_roles(role):
    r = _ready()
    r.approve("Riley", role, "ok")
    assert r.state == "passing"


def test_submit_only_owner():
    r = rv.ControlReview("AC-02", "olive", {"evidence": ["x"]})
    r.start("olive")
    with pytest.raises(rv.ReviewError):
        r.submit("someone")


def test_submit_needs_evidence():
    r = rv.ControlReview("AC-02", "olive", {"evidence": []})
    r.start("olive")
    with pytest.raises(rv.ReviewError):
        r.submit("olive")


def test_return_needs_note():
    r = _ready()
    with pytest.raises(rv.ReviewError):
        r.return_("Riley", "")


def test_return_then_resubmit():
    r = _ready()
    r.return_("Riley", "older than 90 days")
    r.start("olive")
    r.submit("olive")
    assert r.state == "submitted"


@pytest.mark.parametrize("bad", ["submitted", "passing", "returned", "needs_review"])
def test_illegal_from_not_started(bad):
    r = rv.ControlReview("X", "o")
    with pytest.raises(rv.ReviewError):
        r._go(bad, "o")


def test_edit_after_compliant_flags():
    r = _ready()
    r.approve("Riley", "isso", "ok")
    assert r.edit("olive", statement="changed") is True
    assert r.state == "needs_review"
    assert "edited after compliant" in r.history[-1]["note"]


def test_edit_same_content_no_flag():
    r = _ready()
    r.approve("Riley", "isso", "ok")
    assert r.edit("olive", statement="s") is False and r.state == "passing"


def test_edit_before_approval_no_flag():
    r = _ready()
    assert r.edit("olive", statement="x") is False


def test_needs_review_resubmit():
    r = _ready()
    r.approve("Riley", "isso", "ok")
    r.edit("olive", evidence=["ev-2"])
    r._go("submitted", "olive")
    r.approve("Riley", "isso", "re-checked")
    assert r.state == "passing"


def test_history_records_transitions():
    r = _ready()
    assert [h["to"] for h in r.history] == ["in_progress", "submitted"]


def test_drift_flags_and_board():
    d = rv.demo()
    assert d["board"] == {"not_started": 0, "in_progress": 1, "submitted": 1, "passing": 5, "returned": 2,
                          "needs_review": 1}
    assert [x["control"] for x in d["drift"]] == ["AU-06"]


def test_content_hash_order_independent():
    assert rv.content_hash({"a": 1, "b": 2}) == rv.content_hash({"b": 2, "a": 1})


# ---------------------------------------------------------------- compliance as code
def _f(cid, rid, passed, sev="high"):
    return Finding(cid, rid, rid, passed, sev, ("SC-07",), "d")


@pytest.mark.parametrize("cid", sorted(cac.FIXES))
def test_fix_patch_per_check(cid):
    s = cac.suggest([_f(cid, "r1", False)])
    assert s[0]["kind"] == "patch" and s[0]["applied"] is False and cac.FIXES[cid][0] in s[0]["patch"]


@pytest.mark.parametrize("cid", sorted(cac.MANUAL))
def test_manual_fix(cid):
    assert cac.suggest([_f(cid, "r1", False)])[0]["kind"] == "manual"


def test_passed_findings_no_suggestion():
    assert cac.suggest([_f("AZ-01", "r1", True)]) == []


def test_unknown_check_no_suggestion():
    assert cac.suggest([_f("EV-01", "r1", False)]) == []


def test_fix_ids_exist_in_registry():
    ids = {c.id for c in registry.CHECKS}
    assert set(cac.FIXES) | set(cac.MANUAL) <= ids


def test_suggestions_measured(findings):
    assert len(cac.suggest(findings)) == 47


def test_gate_pass_when_nothing_new():
    b = [_f("AZ-01", "r1", False)]
    assert cac.gate(b, b)["result"] == "pass"


def test_gate_fails_new_high():
    g = cac.gate([], [_f("AZ-01", "r1", False, "high")])
    assert g["result"] == "fail" and g["blocking_ids"] == ["AZ-01:r1"]


@pytest.mark.parametrize("sev,block_at,result", [
    ("critical", "high", "fail"), ("high", "high", "fail"), ("moderate", "high", "pass"), ("low", "high", "pass"),
    ("moderate", "moderate", "fail"), ("high", "critical", "pass"), ("low", "low", "fail")])
def test_gate_thresholds(sev, block_at, result):
    assert cac.gate([], [_f("AZ-01", "r1", False, sev)], block_at)["result"] == result


def test_gate_counts_fixed():
    assert cac.gate([_f("AZ-01", "r1", False)], [_f("AZ-01", "r1", True)])["fixed"] == 1


def test_gate_bad_threshold():
    with pytest.raises(ValueError):
        cac.gate([], [], "urgent")


def test_gate_names_human_override():
    assert "human" in cac.gate([], [])["override"] or "lead" in cac.gate([], [])["override"]


def test_demo_gate_blocks_open_rdp():
    d = cac.demo()
    assert d["gate"]["result"] == "fail" and d["gate"]["blocking_ids"] == ["AZ-13:nsg-lhx-new"]
    assert d["gate"]["fixed"] == 1


def test_demo_does_not_mutate_estate():
    before = copy.deepcopy(registry.load_estate())
    cac.demo()
    assert registry.load_estate() == before
