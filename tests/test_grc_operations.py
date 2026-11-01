"""Tests for the GRC-operations extension (A1-A15). All data synthetic."""
import dataclasses

import pytest

from arcampe import catalog
from arcampe.grc import (
    ai_frameworks,
    ai_tests,
    audit_hub,
    custom_tests,
    insights,
    mapping_eval,
    mcp_server,
    policy_approvals,
    readiness_approval,
    recipes,
    recurring,
    reporting,
    risk_program,
    risk_registers,
    roadmap,
    scorecards,
)
from arcampe.integrations.connectors import collect_all


# ------------------------------------------------------------------ A1 readiness approval
@pytest.fixture(scope="module")
def ctx():
    return readiness_approval._context()


def test_four_parts(ctx):
    p = readiness_approval.parts("AC-02", ctx)
    assert set(p) == set(readiness_approval.PARTS)
    assert all(isinstance(v["ready"], bool) for v in p.values())


def test_board_counts(ctx):
    b = readiness_approval.board(ctx=ctx)
    assert b["controls"] == len(catalog.baseline("ae"))
    assert b["all_four_ready"] <= min(b["ready_by_part"].values())


def test_ready_control_can_be_signed(ctx):
    s = readiness_approval.sign_off("IA-02(01)", "maya.isso", "isso", ctx=ctx)
    assert s.approver == "maya.isso" and s.evidence_hashes
    assert readiness_approval.still_valid(s, collect_all())
    assert len(readiness_approval.evidence_digest(s)) == 16


def test_signoff_void_when_evidence_changes(ctx):
    s = readiness_approval.sign_off("IA-02(01)", "maya.isso", "isso", ctx=ctx)
    ev = collect_all()
    changed = [dataclasses.replace(e, content_sha256="0" * 64) if "IA-02(01)" in e.control_hints else e for e in ev]
    assert not readiness_approval.still_valid(s, changed)


def test_not_ready_control_refused(ctx):
    with pytest.raises(readiness_approval.ReadinessError, match="not ready"):
        readiness_approval.sign_off("AC-02", "maya.isso", "isso", ctx=ctx)


@pytest.mark.parametrize("who,role,agent", [("agent:copilot", "isso", False), ("maya", "isso", True),
                                            ("maya", "analyst", False)])
def test_signoff_needs_human_role(ctx, who, role, agent):
    with pytest.raises(readiness_approval.ReadinessError):
        readiness_approval.sign_off("IA-02(01)", who, role, is_agent=agent, ctx=ctx)


# ------------------------------------------------------------------ A2/A3 recipes
def test_ten_recipes_single_trigger():
    assert len(recipes.RECIPES) == 10
    assert len({r.id for r in recipes.RECIPES}) == 10
    for r in recipes.RECIPES:
        assert recipes.validate(r) == []
        assert isinstance(r.trigger, str)


@pytest.mark.parametrize("bad", [dict(trigger="x"), dict(action="email_everyone"), dict(target=""),
                                 dict(min_days=-1)])
def test_recipe_validation(bad):
    r = dataclasses.replace(recipes.RECIPES[0], **bad)
    assert recipes.validate(r)
    with pytest.raises(recipes.RecipeError):
        recipes.run(events=[], recipes=(r,))


def test_recipes_never_send():
    r = recipes.run()
    assert r["sent"] == 0 and r["actions"] > 0
    assert all(x["mode"] == "simulated" and x["sent"] is False for x in r["log"])


@pytest.mark.parametrize("rid", [r.id for r in recipes.RECIPES])
def test_every_recipe_fires_on_synthetic_data(rid):
    assert recipes.run()["by_recipe"][rid] >= 1


def test_min_days_condition():
    ev = [{"type": "evidence.overdue", "subject": "a", "days": 3},
          {"type": "evidence.overdue", "subject": "b", "days": 9}]
    r = recipes.run(events=ev)
    assert [x["subject"] for x in r["log"]] == ["b"]


@pytest.mark.parametrize("deliver,who", [(False, "maya"), (True, ""), (True, "agent:copilot")])
def test_delivery_needs_flag_and_human(deliver, who):
    with pytest.raises(recipes.RecipeError):
        recipes.approve_delivery({"recipe": "R01"}, who, deliver)


def test_delivery_approved_still_not_sent():
    x = recipes.approve_delivery({"recipe": "R01", "sent": False}, "maya", True)
    assert x["mode"] == "approved_for_delivery" and x["sent"] is False


@pytest.mark.parametrize("due,state", [("2026-12-31", "assigned"), ("2026-11-05", "upcoming"),
                                       ("2026-11-07", "upcoming"), ("2026-10-30", "overdue"),
                                       ("2026-10-31", "upcoming")])
def test_lifecycle(due, state):
    assert recipes.lifecycle(due) == state


def test_lifecycle_done():
    assert recipes.lifecycle("2020-01-01", done=True) == "done"


def test_monday_digest():
    tasks = [{"id": "T1", "owner": "ann", "due": "2026-11-03", "title": "renew"},
             {"id": "T2", "owner": "ann", "due": "2026-12-30", "title": "later"},
             {"id": "T3", "owner": "bob", "due": "2026-10-01", "title": "late"}]
    d = recipes.monday_digest(tasks)
    assert "not sent" in d and "T1" in d and "T3" in d and "T2" not in d
    assert d.index("ann:") < d.index("bob:")


# ------------------------------------------------------------------ A4 insights
@pytest.fixture(scope="module")
def hist():
    return insights.history()


def test_history_shape(hist):
    assert hist and all(len(r["series"]) == insights.HISTORY_DAYS for r in hist)


def test_today_matches_assessment(hist):
    from arcampe import assess
    fails = sum(not f.passed for f in assess.run_all())
    assert sum(not r["series"][-1] for r in hist) == fails


def test_flip_windows_nested(hist):
    a, b, c = (len(insights.flips(hist, w)) for w in ("24h", "7d", "14d"))
    assert a <= b <= c


def test_flips_are_failing_now(hist):
    keys = {r["key"]: r for r in hist}
    for f in insights.flips(hist, "14d"):
        assert keys[f["key"]]["series"][-1] is False


def test_mttr_simple():
    rows = [{"series": [True, False, False, True]}, {"series": [False, True]}]
    assert insights.mttr_hours(rows) == 36.0


def test_mttr_none_when_no_fix():
    assert insights.mttr_hours([{"series": [True, False]}]) is None


def test_summary_deterministic():
    assert insights.summary() == insights.summary()
    assert insights.summary()["label"] == "synthetic history"


def test_as_of():
    assert insights.as_of("2026-10-31", 7) == "2026-10-24"


# ------------------------------------------------------------------ A5 policy approvals
def test_demo_approved():
    d = policy_approvals.demo()
    assert d["status"] == "approved" and d["votes"] == 6


def test_reject_stops():
    w = policy_approvals.start("AC-01", "2.1", policy_approvals.SAMPLE_TIERS)
    policy_approvals.vote(w, "iam-lead", "reject")
    assert w.status == "rejected"
    with pytest.raises(policy_approvals.PolicyApprovalError):
        policy_approvals.vote(w, "isso", "approve")


def test_tiers_in_order():
    w = policy_approvals.start("AC-01", "2.1", policy_approvals.SAMPLE_TIERS)
    with pytest.raises(policy_approvals.PolicyApprovalError, match="not an approver"):
        policy_approvals.vote(w, "isso", "approve")


def test_k_of_n():
    w = policy_approvals.start("X", "1", (policy_approvals.Tier("c", ("a", "b", "c"), "k-of-n", 2),))
    policy_approvals.vote(w, "a", "approve")
    assert w.status == "in_review"
    policy_approvals.vote(w, "c", "approve")
    assert w.status == "approved"


def test_any_rule():
    w = policy_approvals.start("X", "1", (policy_approvals.Tier("c", ("a", "b"), "any"),))
    policy_approvals.vote(w, "b", "approve")
    assert w.status == "approved"


def test_double_vote():
    w = policy_approvals.start("X", "1", (policy_approvals.Tier("c", ("a", "b")),))
    policy_approvals.vote(w, "a", "approve")
    with pytest.raises(policy_approvals.PolicyApprovalError, match="already"):
        policy_approvals.vote(w, "a", "approve")


@pytest.mark.parametrize("tiers,msg", [
    ((), "1 to 6"),
    (tuple(policy_approvals.Tier(f"t{i}", ("a",)) for i in range(7)), "1 to 6"),
    ((policy_approvals.Tier("t", ()),), "no approvers"),
    ((policy_approvals.Tier("t", ("agent:x",)),), "agents"),
    ((policy_approvals.Tier("t", ("a",), "most"),), "unknown rule"),
    ((policy_approvals.Tier("t", ("a",), "k-of-n", 2),), "k must"),
    ((policy_approvals.Tier("t", ("a",)), policy_approvals.Tier("t", ("b",))), "unique"),
])
def test_tier_validation(tiers, msg):
    with pytest.raises(policy_approvals.PolicyApprovalError, match=msg):
        policy_approvals.start("X", "1", tiers)


def test_six_tiers_allowed():
    tiers = tuple(policy_approvals.Tier(f"t{i}", (f"p{i}",)) for i in range(6))
    w = policy_approvals.start("X", "1", tiers)
    for i in range(6):
        policy_approvals.vote(w, f"p{i}", "approve")
    assert w.status == "approved"


@pytest.mark.parametrize("who,dec", [("agent:copilot", "approve"), ("iam-lead", "maybe")])
def test_vote_rules(who, dec):
    w = policy_approvals.start("AC-01", "2.1", policy_approvals.SAMPLE_TIERS)
    with pytest.raises(policy_approvals.PolicyApprovalError):
        policy_approvals.vote(w, who, dec)


def test_diff():
    d = policy_approvals.diff(policy_approvals.SAMPLE_OLD, policy_approvals.SAMPLE_NEW)
    assert "Inactive accounts are disabled after 45 days." in d["added"]
    assert "Inactive accounts are disabled after 60 days." in d["removed"]
    assert 0 < d["similarity"] < 1


def test_change_summary_labeled_and_not_approval():
    s = policy_approvals.change_summary(policy_approvals.SAMPLE_OLD, policy_approvals.SAMPLE_NEW)
    assert s["label"] == policy_approvals.AI_LABEL and s["counts_as_approval"] is False
    assert any("45 days" in p for p in s["points"])
    assert any("phishing-resistant" in p for p in s["points"])


def test_change_summary_wording_only():
    assert policy_approvals.change_summary("Hello team", "Hello all")["points"] == ["Wording changes only"]


# ------------------------------------------------------------------ A6-A8 risk program
def _tracked():
    return risk_program.TrackedRisk(risk_registers.default_risks()[0])


def test_move_with_history():
    t = risk_program.move(_tracked(), "RR-ENT", "isso", "enterprise-wide impact")
    assert t.risk.register == "RR-ENT" and t.history[0]["from"] == "RR-SEC"
    assert t.history[0]["residual_before"] != t.history[0]["residual_after"]


def test_move_target_owner_allowed():
    assert risk_program.move(_tracked(), "RR-ENT", "ciso", "x").risk.register == "RR-ENT"


@pytest.mark.parametrize("by,reason", [("random-user", "x"), ("isso", "")])
def test_move_refused(by, reason):
    with pytest.raises(risk_program.RiskProgramError):
        risk_program.move(_tracked(), "RR-ENT", by, reason)


def test_rollup():
    r = risk_program.rollup()
    assert set(r) == {"RR-ENT", "RR-SEC", "RR-PRV", "RR-AI"}
    assert sum(x["risks"] for x in r.values()) == len(risk_registers.default_risks())
    assert all(0 <= x["max_normalized"] <= 100 for x in r.values())


@pytest.fixture(scope="module")
def fair():
    return risk_program.fair()


def test_fair_percentiles_ordered(fair):
    for x in fair.values():
        assert 0 <= x["p50"] <= x["p90"] <= x["p95"]
        assert x["label"] == "SYNTHETIC" and "95%" in x["sentence"]


def test_fair_deterministic(fair):
    assert risk_program.fair() == fair


def test_fair_seed_changes_result(fair):
    assert risk_program.fair(seed=1) != fair


def test_fair_better_controls_lower_loss():
    r = risk_registers.default_risks()[0]
    weak = dataclasses.replace(r, inputs={**r.inputs, "control_effectiveness": 0.1})
    strong = dataclasses.replace(r, inputs={**r.inputs, "control_effectiveness": 0.9})
    assert risk_program.fair([strong])[r.register]["p95"] < risk_program.fair([weak])[r.register]["p95"]


def test_fair_perfect_controls_zero():
    r = risk_registers.default_risks()[0]
    full = dataclasses.replace(r, inputs={**r.inputs, "control_effectiveness": 1.0})
    assert risk_program.fair([full])[r.register]["p95"] == 0


@pytest.mark.parametrize("role,by", [("ciso", "ann"), ("cro", "agent:x")])
def test_appetite_needs_cro(role, by):
    with pytest.raises(risk_program.RiskProgramError):
        risk_program.sign_appetite(risk_program.Appetite("RR-SEC", 1e6), by, role)


def test_board_view_appetite(fair):
    a = risk_program.sign_appetite(risk_program.Appetite("RR-SEC", 1e12), "lee", "cro")
    b = risk_program.Appetite("RR-AI", 1.0, "lee", "2026-10-31")
    rows = {r["register"]: r for r in risk_program.board_view([a, b])}
    assert rows["RR-SEC"]["appetite"] == "within"
    assert rows["RR-AI"]["appetite"] == "above"
    assert rows["RR-ENT"]["appetite"] == "not signed"
    assert all("color" not in k for r in rows.values() for k in r)


def test_unsigned_appetite_not_used():
    rows = {r["register"]: r for r in risk_program.board_view([risk_program.Appetite("RR-SEC", 1.0)])}
    assert rows["RR-SEC"]["appetite"] == "not signed"


def test_sla_ids_are_real():
    ids = {r.id for r in risk_registers.default_risks()}
    assert set(risk_program.SYNTHETIC_TIMELINE) <= ids


def test_sla_summary():
    s = risk_program.sla()
    assert 0 < s["adherence_pct"] < 100
    assert s["invalid_acceptances"] == ["RR-ENT-07"]


def test_sla_table_shape():
    for d in risk_program.SLA_DAYS.values():
        assert set(d) == {"identify", "remediate", "accept"}
    assert risk_program.SLA_DAYS["high"]["remediate"] < risk_program.SLA_DAYS["low"]["remediate"]


def test_sla_unidentified_counts_until_today():
    row = next(r for r in risk_program.sla()["rows"] if r["id"] == "RR-AI-06")
    assert row["identify_days"] == 11 and row["open"]


# ------------------------------------------------------------------ A9 AI-generated tests
@pytest.fixture(scope="module")
def props():
    return ai_tests.pipeline()


def test_pipeline_statuses(props):
    st = {p.request: p.status for p in props}
    assert st["Q07"] == "invalid" and st["Q04"] == "duplicate" and st["Q06"] == "duplicate"
    assert st["Q03"] == "pending_review"


def test_retries_bounded(props):
    assert all(p.attempts <= ai_tests.MAX_RETRIES + 1 for p in props)


def test_valid_proposals_pass_validator(props):
    for p in props:
        if p.status == "pending_review":
            assert custom_tests.validate(p.rule) == []
            assert p.doc.startswith("For every")


def test_pending_rules_compile_and_run(props):
    for p in props:
        if p.status == "pending_review":
            assert callable(custom_tests.compile_rule(p.rule).fn)


def test_nothing_live_without_review(props):
    assert not any(p.status == "live" for p in ai_tests.pipeline())


@pytest.mark.parametrize("who,role", [("agent:copilot", "auditor"), ("ann", "analyst")])
def test_review_needs_human(props, who, role):
    p = next(x for x in ai_tests.pipeline() if x.status == "pending_review")
    with pytest.raises(ai_tests.ReviewError):
        ai_tests.review(p, who, role, "approve")


def test_review_bad_decision():
    p = next(x for x in ai_tests.pipeline() if x.status == "pending_review")
    with pytest.raises(ai_tests.ReviewError):
        ai_tests.review(p, "ann", "auditor", "ship-it")


def test_cannot_review_invalid():
    p = next(x for x in ai_tests.pipeline() if x.status == "invalid")
    with pytest.raises(ai_tests.ReviewError):
        ai_tests.review(p, "ann", "auditor", "approve")


def test_ai_test_summary():
    s = ai_tests.summary()
    assert s["requests"] == 10 and s["live"] + s["rejected"] == s["reviewed"]
    assert s["acceptance_pct"] == round(100 * s["live"] / s["reviewed"], 1)


@pytest.mark.parametrize("mistake", ["id", "op", "control"])
def test_draft_mistakes_are_caught(mistake):
    q = ai_tests.REQUESTS[2]
    rule = ai_tests._draft(q[0], q[1], q[2], [mistake], 0)
    assert custom_tests.validate(rule)


def test_draft_fixes_after_feedback():
    q = ai_tests.REQUESTS[2]
    assert custom_tests.validate(ai_tests._draft(q[0], q[1], q[2], ["id"], 1)) == []


# ------------------------------------------------------------------ A10 mapping eval
@pytest.fixture(scope="module")
def mev():
    return mapping_eval.run()


def test_eval_types(mev):
    assert set(mev["by_type"]) == set(mapping_eval.TYPES)


def test_exact_matches_mapper(mev):
    assert mev["by_type"]["exact"]["top1"] >= 0.95


def test_harder_types_not_better(mev):
    b = mev["by_type"]
    assert b["keyword"]["mrr"] <= b["exact"]["mrr"]
    assert b["paraphrase"]["mrr"] <= b["exact"]["mrr"]


def test_metric_bounds(mev):
    for r in mev["by_type"].values():
        assert 0 <= r["top1"] <= r["top3"] <= 1 and 0 <= r["mrr"] <= 1


def test_variants():
    v = mapping_eval.variants("Report of user accounts disabled")
    assert v["exact"] == "Report of user accounts disabled"
    assert "identities" in v["paraphrase"] and "turned off" in v["paraphrase"]
    assert v["partial"] == "Report of"
    assert len(v["keyword"].split()) == 3


def test_rank_none_for_nonsense():
    assert mapping_eval.rank("zzzz qqqq", "AC-02") is None


# ------------------------------------------------------------------ A11 audit hub
def test_requests_mapped():
    s = audit_hub.request_summary()
    assert s["requests"] == 12 and s["ready"] <= s["auto_mapped"]


def test_low_confidence_needs_confirmation():
    for r in audit_hub.map_requests():
        if r["confidence"] < 0.6:
            assert r["needs_confirmation"] and not r["ready"]


def test_pre_audit_package_verifies():
    from arcampe.grc import auditor
    blob = audit_hub.pre_audit_package()
    assert auditor.verify(blob) == []


def test_independence():
    rows = {r["audit"]: r["independent"] for r in audit_hub.check_independence()}
    assert rows["IA-Q4"] is False and rows["IA-Q1"] is True


def test_schedule_refuses_conflict():
    with pytest.raises(audit_hub.IndependenceError):
        audit_hub.schedule_internal("X", "AT", "riya.ia")
    assert audit_hub.schedule_internal("X", "CP", "riya.ia")["status"] == "scheduled"


@pytest.fixture(scope="module")
def chain():
    return audit_hub.chain(collect_all())


def test_chain_intact(chain):
    assert audit_hub.verify_chain(chain) == []
    assert chain[0]["prev"] == audit_hub.GENESIS


def test_chain_detects_edit(chain):
    bad = [dict(x) for x in chain]
    bad[5]["body"] = bad[5]["body"].replace("lakehaven", "evil", 1)
    assert "entry 5 body changed" in audit_hub.verify_chain(bad)


def test_chain_detects_deletion(chain):
    bad = chain[:3] + chain[4:]
    assert any("breaks the chain" in p for p in audit_hub.verify_chain(bad))


def test_chain_detects_reorder(chain):
    bad = [chain[1], chain[0]] + chain[2:]
    assert audit_hub.verify_chain(bad)


# ------------------------------------------------------------------ A12 AI frameworks
def test_ai_readiness_rows():
    rows = ai_frameworks.readiness()
    assert [r["framework"] for r in rows] == list(ai_frameworks.AI_FRAMEWORKS)
    assert all(r["coverage"] == "approximate" for r in rows)


def test_aiuc_six_domains():
    rows = ai_frameworks.aiuc_domains()
    assert len(rows) == 6
    for r in rows:
        assert r["pass"] + r["fail"] + r["untested"] == r["controls"]


def test_eu_ai_act_articles():
    a = ai_frameworks.eu_ai_act_articles()
    assert "Art.9" in a and a["Art.12"] == ["AU"]


def test_overlap_is_author_judgement():
    o = ai_frameworks.overlap()
    assert o["topics"] == 25 and "author judgement" in o["label"]
    assert o["reusable"] + o["partial"] + o["ai_specific"] == 25
    assert "Data provenance" in o["ai_specific_topics"]


def test_cra_clock_values():
    assert ai_frameworks.CRA_CLOCKS["early_warning"].total_seconds() == 24 * 3600
    assert ai_frameworks.CRA_CLOCKS["notification"].total_seconds() == 72 * 3600
    assert ai_frameworks.CRA_FINAL["vulnerability"].days == 14


def test_cra_statuses():
    rows = {r["id"]: r for r in ai_frameworks.cra_summary()["rows"]}
    assert rows["CRA-1"]["final"]["status"] == "met"
    assert rows["CRA-2"]["early_warning"]["status"] == "late"
    assert rows["CRA-2"]["notification"]["status"] == "overdue"
    assert rows["CRA-2"]["final"]["status"].startswith("waiting")


def test_cra_open_before_deadline():
    ev = dict(ai_frameworks.SAMPLE_EVENTS[1], early_warning="", aware="2026-10-31T08:00")
    assert ai_frameworks.clocks(ev, "2026-10-31T09:00")["early_warning"]["status"] == "open"


def test_cra_draft_and_approval():
    d = ai_frameworks.draft_cra_report(ai_frameworks.SAMPLE_EVENTS[0], "notification")
    assert d["submitted"] is False
    with pytest.raises(ai_frameworks.CraError):
        ai_frameworks.approve_submission(d, "agent:copilot")
    a = ai_frameworks.approve_submission(d, "ann")
    assert a["status"] == "approved_for_submission" and a["submitted"] is False
    with pytest.raises(ai_frameworks.CraError):
        ai_frameworks.draft_cra_report(ai_frameworks.SAMPLE_EVENTS[0], "tweet")


# ------------------------------------------------------------------ A13 roadmap
@pytest.mark.parametrize("buyer,first", [("defense", {"NIST_800_171", "CMMC_L2"}), ("health", {"HIPAA", "HITRUST"}),
                                         ("regulated_eu", {"ISO27001", "NIS2"}), ("ai_vendor", {"ISO42001", "AIUC_1"})])
def test_roadmap_top(buyer, first):
    r = roadmap.recommend(buyer)
    assert r[0]["framework"] in first and r[0]["rank"] == 1
    assert all(x["decision"] == "suggestion for a person to decide" for x in r)
    assert [x["score"] for x in r] == sorted((x["score"] for x in r), reverse=True)


def test_roadmap_unknown_buyer():
    with pytest.raises(roadmap.RoadmapError):
        roadmap.recommend("pirates")


def test_soc2_overlap_bounds():
    assert 0 <= roadmap.soc2_family_overlap("HIPAA") <= 100


# ------------------------------------------------------------------ A14 recurring
def test_occurrences_weekly():
    r = recurring.DEFAULTS[0]
    occ = recurring.occurrences(r, "2026-09-21")
    assert occ == ["2026-09-07", "2026-09-14", "2026-09-21"]


def test_next_due():
    assert recurring.next_due(recurring.DEFAULTS[0], "2026-10-31") == "2026-11-02"


def test_unknown_cadence():
    with pytest.raises(recurring.RecurringError):
        recurring.occurrences(dataclasses.replace(recurring.DEFAULTS[0], cadence="hourly"))


def test_complete_needs_human():
    with pytest.raises(recurring.RecurringError):
        recurring.complete("RT-01", "2026-09-28", "agent:copilot")
    done = recurring.complete("RT-01", "2026-09-28", "maya")
    row = next(r for r in recurring.status(done=done) if r["id"] == "RT-01")
    assert "2026-09-28" not in row["missed"]


def test_status_and_rate():
    rows = recurring.status()
    assert len(rows) == 5
    assert 0 < recurring.on_time_rate() < 100
    for r in rows:
        assert r["completed"] + len(r["missed"]) <= r["occurrences"]


def test_recurring_controls_exist():
    ids = set(catalog.by_id())
    for r in recurring.DEFAULTS:
        assert set(r.controls) <= ids


# ------------------------------------------------------------------ A15 MCP
def _call(name, args, key="k-readonly"):
    s = mcp_server.demo_server()
    return s.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}},
                    key)


def test_mcp_exec_risk_summary():
    r = _call("exec_risk_summary", {})["result"]
    assert "SIMULATED" in r["label"] and len(r["registers"]) == 4


@pytest.mark.parametrize("lim,exp", [(3, 3), (0, 1), (500, 50)])
def test_mcp_prioritized_failures(lim, exp):
    r = _call("prioritized_test_failures", {"limit": lim})["result"]
    assert len(r["top"]) == min(exp, r["count"])
    order = ["critical", "high", "moderate", "low"]
    sev = [order.index(x["severity"]) for x in r["top"]]
    assert sev == sorted(sev)


def test_mcp_mapping_summary():
    r = _call("control_mapping_summary", {})["result"]
    assert r["precision"] > 0.9 and "keyword" in r["by_type"]


def test_mcp_new_tools_read_only():
    for t in ("exec_risk_summary", "prioritized_test_failures", "control_mapping_summary"):
        assert t in mcp_server.READ_TOOLS and t not in mcp_server.WRITE_TOOLS


def test_mcp_limit_type_checked():
    r = _call("prioritized_test_failures", {"limit": "ten"})
    assert r["error"]["code"] == -32602


# ------------------------------------------------------------------ scorecards
@pytest.fixture(scope="module")
def cards():
    return reporting.metrics()["scorecards"]


@pytest.mark.parametrize("card", ["efficiency", "risk", "trust"])
def test_scorecard_rows_labeled(cards, card):
    assert cards[card]
    for _k, _v, b in cards[card]:
        assert any(x in b for x in ("measured", "SIMULATED", "author"))


def test_fair_in_risk_card(cards):
    assert sum("FAIR" in k for k, _, _ in cards["risk"]) == 4
    assert all("95%" in s for s in cards["fair_sentences"].values())


def test_no_vendor_claims_in_cards(cards):
    text = str(cards)
    for bad in ("85% answer rate", "1 million", "35-40%"):
        assert bad not in text


def test_daily_deltas():
    d = scorecards.daily_deltas()
    assert len(d) == 3 and "24h" in d[0][0]


def test_reports_include_scorecards():
    from arcampe.grc import reporting
    m = reporting.metrics()
    w, d = reporting.to_html(m, "weekly"), reporting.to_html(m, "daily")
    assert "Leadership scorecards" in w and "Leadership scorecards" not in d
    assert "Operational deltas" in d
    csv = reporting.to_csv(m)
    assert "scorecard_risk" in csv and "daily_delta" in csv
    assert reporting.to_pdf(m, "weekly").startswith(b"%PDF")
