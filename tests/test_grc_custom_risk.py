import pytest

from arcampe.grc import custom_tests as ct
from arcampe.grc import risk_registers as rr


def _rule(**kw):
    d = {"id": "CT-99", "title": "t", "resource_type": "Microsoft.Storage/storageAccounts",
         "path": "properties.publicNetworkAccess", "op": "eq", "value": "Disabled", "severity": "high",
         "controls": ["SC-07"]}
    d.update(kw)
    return d


# ---------------------------------------------------------------- custom tests
def test_shipped_rules_valid():
    assert all(not ct.validate(r) for r in ct.load_rules())


def test_five_shipped_rules():
    assert [r["id"] for r in ct.load_rules()] == ["CT-01", "CT-02", "CT-03", "CT-04", "CT-05"]


@pytest.mark.parametrize("rid,evaluated,failed", [("CT-01", 9, 1), ("CT-02", 9, 1), ("CT-03", 3, 1), ("CT-05", 3, 0)])
def test_measured_summary(rid, evaluated, failed):
    s = {r["id"]: r for r in ct.summary()}
    assert (s[rid]["evaluated"], s[rid]["failed"]) == (evaluated, failed)


def test_ct04_tls_measured():
    s = {r["id"]: r for r in ct.summary()}
    assert s["CT-04"]["evaluated"] >= 1 and s["CT-04"]["failed"] < s["CT-04"]["evaluated"]


@pytest.mark.parametrize("missing", ["id", "title", "resource_type", "path", "op", "severity", "controls"])
def test_missing_key(missing):
    r = _rule()
    r.pop(missing)
    assert any("missing" in e for e in ct.validate(r))


def test_unknown_key():
    assert ct.validate(_rule(code="import os"))


def test_id_prefix():
    assert "custom test ids start with CT-" in ct.validate(_rule(id="AZ-99"))


def test_unknown_op():
    assert ct.validate(_rule(op="matches"))


def test_op_needs_value():
    r = _rule()
    r.pop("value")
    assert "operator needs a value" in ct.validate(r)


@pytest.mark.parametrize("op", ["exists", "not_exists", "truthy"])
def test_unary_ops_need_no_value(op):
    r = _rule(op=op)
    r.pop("value")
    assert ct.validate(r) == []


def test_bad_severity():
    assert ct.validate(_rule(severity="urgent"))


@pytest.mark.parametrize("path", ["a.b.c.d.e.f.g", "__class__.x", "properties.__dict__"])
def test_bad_path(path):
    assert ct.validate(_rule(path=path))


def test_unknown_control():
    assert any("unknown control" in e for e in ct.validate(_rule(controls=["ZZ-01"])))


def test_no_controls():
    assert "map the test to at least one control" in ct.validate(_rule(controls=[]))


def test_compile_raises():
    with pytest.raises(ct.RuleError):
        ct.compile_rule(_rule(op="bogus"))


def test_compiled_check_shape():
    c = ct.compile_rule(_rule())
    assert c.id == "CT-99" and c.controls == ("SC-07",) and c.severity == "high"


@pytest.mark.parametrize("obj,path,expected", [
    ({"a": {"b": 1}}, "a.b", 1), ({"a": [5, 6]}, "a.1", 6), ({"a": [5]}, "a.3", ct._MISSING),
    ({"a": 1}, "a.b", ct._MISSING), ({}, "x", ct._MISSING)])
def test_lookup(obj, path, expected):
    assert ct.lookup(obj, path) == expected if expected is not ct._MISSING else ct.lookup(obj, path) is ct._MISSING


@pytest.mark.parametrize("op,actual,expected,result", [
    ("eq", 1, 1, True), ("ne", 1, 2, True), ("in", "a", ["a"], True), ("not_in", "a", ["b"], True),
    ("gte", 3, 2, True), ("lte", 3, 2, False), ("contains", ["x"], "x", True), ("contains", 5, "x", False),
    ("truthy", "", None, False), ("truthy", "y", None, True), ("gte", "a", 1, False)])
def test_evaluate(op, actual, expected, result):
    assert ct.evaluate(op, actual, expected) is result


@pytest.mark.parametrize("op,result", [("exists", False), ("not_exists", True), ("eq", False), ("truthy", False)])
def test_evaluate_missing(op, result):
    assert ct.evaluate(op, ct._MISSING, 1) is result


def test_run_on_custom_resources():
    res = [{"id": "/r/1", "name": "s1", "type": "Microsoft.Storage/storageAccounts", "location": "eastus2",
            "tags": {}, "properties": {"publicNetworkAccess": "Enabled"}}]
    f = ct.run([_rule()], res)
    assert len(f) == 1 and not f[0].passed and f[0].check_id == "CT-99"


def test_run_skips_other_types():
    res = [{"id": "/r/1", "name": "kv", "type": "Microsoft.KeyVault/vaults", "location": "eastus2", "tags": {},
            "properties": {}}]
    assert ct.run([_rule()], res) == []


# ---------------------------------------------------------------- risk registers
@pytest.mark.parametrize("formula,vals,expected", [
    ("likelihood * impact", {"likelihood": 3, "impact": 4}, 12.0),
    ("max(likelihood, exposure) * impact", {"likelihood": 2, "exposure": 4, "impact": 3}, 12.0),
    ("min(likelihood, 2) + 1", {"likelihood": 5}, 3.0),
    ("round(likelihood / 3, 2)", {"likelihood": 1}, 0.33),
    ("-likelihood + 10", {"likelihood": 3}, 7.0),
    ("(likelihood + exposure) / 2", {"likelihood": 3, "exposure": 4}, 3.5)])
def test_formula_eval(formula, vals, expected):
    assert rr.evaluate(formula, vals) == expected


@pytest.mark.parametrize("formula", [
    "__import__('os')", "likelihood.__class__", "open('x')", "likelihood ** 2", "[1, 2]", "lambda: 1",
    "likelihood if impact else 0", "secret * 2", "True + 1", "'a' * 3", "likelihood % 2",
    "max(likelihood, key=impact)", "x" * 300])
def test_formula_rejects(formula):
    with pytest.raises(rr.FormulaError):
        rr.parse(formula)


def test_formula_syntax_error():
    with pytest.raises(rr.FormulaError):
        rr.parse("likelihood *")


def test_formula_missing_input():
    with pytest.raises(rr.FormulaError):
        rr.evaluate("likelihood * impact", {"likelihood": 1})


def test_formula_div_zero():
    with pytest.raises(rr.FormulaError):
        rr.evaluate("likelihood / (impact - impact)", {"likelihood": 1, "impact": 2})


def test_four_registers():
    assert [r.id for r in rr.REGISTERS] == ["RR-ENT", "RR-SEC", "RR-PRV", "RR-AI"]


@pytest.mark.parametrize("reg", rr.REGISTERS, ids=lambda r: r.id)
def test_register_formulas_parse(reg):
    rr.parse(reg.formula)
    rr.parse(reg.inherent_formula)


@pytest.mark.parametrize("reg", rr.REGISTERS, ids=lambda r: r.id)
def test_bands_descending(reg):
    lows = [b[1] for b in reg.bands]
    assert lows == sorted(lows, reverse=True) and lows[-1] == 0


@pytest.mark.parametrize("score,band", [(10, "high"), (8, "high"), (5, "moderate"), (0, "low"), (-1, "low")])
def test_ent_band(score, band):
    assert rr.register("RR-ENT").band(score) == band


def test_register_unknown():
    with pytest.raises(KeyError):
        rr.register("RR-X")


def test_library_has_12():
    assert len(rr.LIBRARY) == 12 and len({t["ref"] for t in rr.LIBRARY}) == 12


@pytest.mark.parametrize("t", rr.LIBRARY, ids=lambda t: t["ref"])
def test_library_inputs_complete(t):
    assert set(t["inputs"]) == set(rr.VARS)
    assert 0 <= t["inputs"]["control_effectiveness"] <= 1


@pytest.mark.parametrize("t", rr.LIBRARY, ids=lambda t: t["ref"])
def test_score_residual_le_inherent(t):
    s = rr.score(rr.from_library(t["ref"]))
    assert s["residual"] <= s["inherent"]
    assert s["band"] in ("high", "moderate", "low")


def test_from_library_override_and_register():
    r = rr.from_library("LIB-01", rid="RR-ENT", overrides={"control_effectiveness": 1.0})
    assert r.register == "RR-ENT" and rr.score(r)["residual"] == 0


def test_from_library_unknown():
    with pytest.raises(KeyError):
        rr.from_library("LIB-99")


def test_by_register_counts_sum():
    br = rr.by_register()
    assert sum(d["risks"] for d in br.values()) == 12
    assert all(d["high"] + d["moderate"] + d["low"] == d["risks"] for d in br.values())


def test_snapshot_is_evidence():
    from arcampe.integrations import schema
    s = rr.snapshot("2026-10-01")
    assert s.kind == "risk_snapshot" and schema.verify(s) and set(s.control_hints) == {"RA-03", "PM-09"}


def test_snapshot_deterministic():
    assert rr.snapshot("2026-10-01").content_sha256 == rr.snapshot("2026-10-01").content_sha256


def test_diff_detects_change():
    a = rr.snapshot("2026-09-30")
    risks = rr.default_risks()
    risks[0].inputs["control_effectiveness"] = 0.9
    b = rr.snapshot("2026-10-31", risks)
    d = rr.diff(a, b)
    assert len(d) == 1 and d[0]["change"] == "down"


def test_diff_added_removed():
    a = rr.snapshot("2026-09-30", rr.default_risks()[:3])
    b = rr.snapshot("2026-10-31", rr.default_risks()[1:4])
    kinds = sorted(x["change"] for x in rr.diff(a, b))
    assert kinds == ["added", "removed"]


def test_history_trend_down():
    h = rr.history()
    assert [x["date"] for x in h] == list(rr.HISTORY_MONTHS)
    assert h[0]["total_residual"] == 81.19 and h[-1]["total_residual"] == 55.27
    assert all(a["total_residual"] >= b["total_residual"] for a, b in zip(h, h[1:]))
