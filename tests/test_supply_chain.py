import pytest

from arcampe import supply_chain as sc

V = sc.load()
SCORES = {"V-001": None}


def test_six_vendors():
    assert len(V) == 6


def test_scores_measured():
    got = sorted((sc.score(v)["score"] for v in V), reverse=True)
    assert got == [81, 61, 45, 44, 30, 30]


@pytest.mark.parametrize("v", V, ids=lambda v: v.id)
def test_score_bounds_and_factors(v):
    s = sc.score(v)
    assert 0 <= s["score"] <= 100
    assert s["score"] == min(100, sum(s["factors"].values()))
    assert s["band"] in ("low", "moderate", "high")


@pytest.mark.parametrize("pii,spend,tier", [(True, 300_000, "critical"), (True, 10, "high"),
                                            (False, 150_000, "moderate"), (False, 10, "low")])
def test_tiering(pii, spend, tier):
    v = sc.Vendor("X", "X", "s", pii, spend, "US", {}, None)
    assert v.tier() == tier


def test_offshore_vendor_flagged():
    v = sc.Vendor("X", "X", "s", True, 10, "CA", {q: True for q in sc.QUESTIONS}, "2026-10-01")
    assert "offshore_data" in sc.score(v)["factors"]


def test_findings_measured():
    f = sc.findings(V)
    assert sum(not x["passed"] for x in f) == 4
    assert {x["id"] for x in f} <= {"SR-ASSESS", "SR-LOC", "SR-FLOW"}


def test_flow_down_check_exists():
    assert any(x["id"] == "SR-FLOW" for x in sc.findings(V))


def test_register_table():
    t = sc.register_table(V)
    assert all(v.name in t for v in V)
