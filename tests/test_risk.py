import pytest

from arcampe.risk import ai_governance, builder, cyber, erm


@pytest.fixture(scope="module")
def rows(findings):
    return cyber.analyze(findings=findings)


def test_fair_seeded_and_measured(rows):
    r01 = next(r for r in rows if r["id"] == "R01")
    assert r01["ale"] == {"mean": 355896, "p10": 0, "p50": 0, "p90": 1622964, "p_any_loss": 0.1716}
    assert cyber.analyze(findings=None, iterations=500) == cyber.analyze(findings=None, iterations=500)


def test_median_zero_means_rare_events(rows):
    # P50 of $0 is expected when loss happens in fewer than half of simulated years.
    for r in rows:
        if r["ale"]["p_any_loss"] < 0.5:
            assert r["ale"]["p50"] == 0


def test_failing_controls_remove_credit(rows):
    r = {x["id"]: x for x in rows}
    assert r["R01"]["control_health"] == 0.0 and r["R01"]["exceeds_appetite"]
    assert r["R03"]["exceeds_appetite"] and not r["R02"]["exceeds_appetite"]
    assert r["R01"]["residual_ale"] == r["R01"]["ale"]


def test_top10_and_heatmap(rows):
    t = cyber.top10(rows)
    assert len(t) <= 10
    assert sum(map(sum, cyber.heatmap(rows))) == len(rows)
    assert "R01" in cyber.top10_markdown(rows)


def test_pert_bounds():
    import random
    rng = random.Random(1)
    xs = [cyber.pert(rng, 10, 20, 50) for _ in range(500)]
    assert min(xs) >= 10 and max(xs) <= 50


def test_eight_frameworks():
    assert len(cyber.frameworks_for(["AC-02", "SC-07"])) == 8


@pytest.mark.parametrize("old,new,err", [
    ("vuln: 0.35", "vuln: 1.35", "probability"),
    ("tef: [0.1, 0.4, 1.5]", "tef: [0.5, 0.4, 1.5]", "tef"),
    ("decision: mitigate", "decision: ignore", "bad decision"),
])
def test_builder_validation(old, new, err):
    from arcampe import DATA
    text = (DATA / "risk" / "modules" / "cyber.yaml").read_text()
    assert old in text
    with pytest.raises(builder.ModuleError, match=err):
        builder.load(text=text.replace(old, new, 1))


def test_builder_missing_keys():
    assert builder.validate({}) == [f"missing {k}" for k in builder.REQUIRED]


@pytest.mark.parametrize("v,status", [(1, "green"), (5, "amber"), (9, "red")])
def test_kri_status(v, status):
    assert erm.kri_status(v, 5, 9, True) == status


def test_erm_and_ai_governance():
    assert len(erm.register()) == 6
    assert erm.maturity(49.8, 16.2, 78.6)["name"] == "defined"
    c = ai_governance.checks()
    assert len(c) == 5 and all(x["passed"] for x in c)
