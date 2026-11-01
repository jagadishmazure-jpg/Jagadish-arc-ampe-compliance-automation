import json
import re

import pytest

from arcampe import catalog, crosswalk
from arcampe.grc import auditor
from arcampe.grc import frameworks as fw
from arcampe.integrations import schema
from arcampe.integrations.connectors import collect_all

STEERING = ["CCPA", "NIS2", "HITRUST", "CMMC_L2", "NIST_CSF_2", "NIST_800_171", "FEDRAMP_PROXY", "DORA",
            "CYBER_ESSENTIALS", "ISO27701", "CIS_V8", "SOX_ITGC", "EU_AI_ACT", "AIUC_1", "ISO42001", "NIST_AI_RMF"]


# ---------------------------------------------------------------- frameworks
def test_registry_size():
    assert len(fw.REGISTRY) == 34 and len(set(fw.REGISTRY_KEYS)) == 34


@pytest.mark.parametrize("key", STEERING)
def test_steering_frameworks_present(key):
    assert key in fw.REGISTRY_KEYS


@pytest.mark.parametrize("key", [k for k in fw.REGISTRY_KEYS if k in fw.EXT_MAP])
def test_ext_frameworks_labeled_approximate(key):
    assert fw.info(key)["coverage"] == "approximate"


@pytest.mark.parametrize("key", list(fw.EXT_MAP))
def test_ext_map_uses_known_families(key):
    assert set(fw.EXT_MAP[key]) <= set(fw.FAM)


@pytest.mark.parametrize("key", list(fw.EXT_MAP))
def test_ext_map_ids_short_not_text(key):
    for ids in fw.EXT_MAP[key].values():
        assert ids and all(len(i) <= 40 for i in ids)


@pytest.mark.parametrize("key", list(fw.EXT_MAP))
def test_ext_map_has_controls(key):
    assert fw.mapped_controls(key)


def test_ms_sspa_is_gap_and_unmapped():
    assert fw.info("MS_SSPA")["coverage"] == "gap"
    assert "MS_SSPA" not in fw.ALL_MAPPED


def test_custom_covered():
    assert fw.info("CUSTOM")["coverage"].startswith("covered")


def test_info_unknown():
    with pytest.raises(KeyError):
        fw.info("NOPE")


def test_nist_800_53_maps_whole_baseline():
    assert len(fw.mapped_controls("NIST_800_53")) == len(catalog.baseline("ae"))


def test_map_control_includes_core_and_ext():
    m = fw.map_control("AC-02")
    assert set(crosswalk.FRAMEWORKS) <= set(m) and "NIS2" in m and "CMMC_L2" in m


def test_nist_171_ac_maps_03_01():
    assert fw.map_control("AC-02")["NIST_800_171"] == ("03.01",)


def test_unmapped_families_listed():
    assert "PM" in fw.unmapped_families("NIST_800_171")
    assert fw.unmapped_families("SOC2") == []


def test_ccpa_from_core():
    assert "CCPA" in crosswalk.FRAMEWORKS


@pytest.mark.parametrize("row", fw.readiness(), ids=lambda r: r["framework"])
def test_readiness_arithmetic(row):
    assert row["ready"] + row["failing"] + row["untested"] == row["controls"]
    assert row["ready_pct"] == round(100 * row["ready"] / row["controls"], 1)


def test_readiness_nist_measured():
    r = fw.readiness(frameworks=["NIST_800_53"])[0]
    assert (r["ready"], r["controls"], r["ready_pct"]) == (115, 402, 28.6)


def test_readiness_cyber_essentials_measured():
    r = fw.readiness(frameworks=["CYBER_ESSENTIALS"])[0]
    assert (r["ready"], r["controls"]) == (10, 174)


def test_readiness_all_pass_is_100():
    by = {c.id: {"status": "pass"} for c in catalog.baseline("ae")}
    assert all(r["ready_pct"] == 100.0 for r in fw.readiness(by))


def test_readiness_count_matches_mapped_registry():
    assert len(fw.readiness()) == len([k for k in fw.REGISTRY_KEYS if k in fw.ALL_MAPPED or k == "NIST_800_53"])


def test_coverage_table_rows():
    assert fw.coverage_table().count("\n") == 34 + 1


def test_readiness_table_has_percent():
    assert re.search(r"\| \d+ / \d+ \| [\d.]+% \|", fw.readiness_table())


def test_summary_counts_sum():
    s = fw.summary()
    assert sum(s["by_coverage"].values()) == 34 and s["by_coverage"]["gap"] == 1


# ---------------------------------------------------------------- auditor
@pytest.fixture(scope="module")
def evidence():
    return collect_all()


def test_store_put_and_freeze():
    s = auditor.AuditStore()
    s.put("a", 1, "isso")
    h = s.freeze("auditor")
    assert s.frozen and h == s.digest()


@pytest.mark.parametrize("op", ["put", "delete"])
def test_frozen_store_refuses(op):
    s = auditor.AuditStore()
    s.put("a", 1, "isso")
    s.freeze("auditor")
    with pytest.raises(auditor.AuditModeError):
        s.put("a", 2, "isso") if op == "put" else s.delete("a", "isso")
    assert s.unchanged_since_freeze()


def test_refused_write_logged():
    s = auditor.AuditStore()
    s.freeze("auditor")
    with pytest.raises(auditor.AuditModeError):
        s.put("x", 1, "eng")
    assert s.log.entries()[-1].action == "write.refused"


def test_unfreeze_needs_reason_and_human():
    s = auditor.AuditStore()
    s.freeze("auditor")
    with pytest.raises(ValueError):
        s.unfreeze("isso", " ")
    with pytest.raises(PermissionError):
        s.unfreeze("agent:copilot", "done")
    s.unfreeze("isso", "fieldwork closed")
    s.put("x", 1, "isso")
    assert s.log.verify()[0]


def test_unchanged_false_before_freeze():
    assert not auditor.AuditStore().unchanged_since_freeze()


def test_delete_unfrozen():
    s = auditor.AuditStore()
    s.put("a", 1, "x")
    s.delete("a", "x")
    assert s.data == {}


@pytest.mark.parametrize("freq,pop,n", [("annual", 1, 1), ("quarterly", 4, 2), ("monthly", 12, 3),
                                        ("monthly", 2, 2), ("weekly", 52, 10), ("weekly", 10, 6),
                                        ("daily", 250, 40), ("daily", 5, 5), ("multiple_daily", 1000, 60),
                                        ("quarterly", 1, 1), ("daily", 0, 0)])
def test_sample_size(freq, pop, n):
    assert auditor.sample_size(freq, pop) == n


def test_sample_size_unknown():
    with pytest.raises(ValueError):
        auditor.sample_size("hourly", 5)


def test_sample_deterministic_and_seeded():
    pop = [f"x{i}" for i in range(50)]
    a, b = auditor.sample(pop, 5), auditor.sample(pop, 5)
    assert a == b and len(a) == 5 and set(a) <= set(pop)
    assert auditor.sample(pop, 5, seed="other") != a


def test_sample_dedups():
    assert auditor.sample(["a", "a", "b"], 5) == ["a", "b"]


def test_plan_covers_kinds(evidence):
    p = auditor.plan(evidence)
    assert {r["kind"] for r in p} == {e.kind for e in evidence}
    assert all(len(r["picked"]) == r["sample"] <= r["population"] for r in p)


def test_package_verifies(evidence):
    blob = auditor.package(evidence)
    assert auditor.verify(blob) == []


def test_package_deterministic(evidence):
    assert auditor.package(evidence) == auditor.package(evidence)


def test_package_manifest_count(evidence):
    import io
    import zipfile
    z = zipfile.ZipFile(io.BytesIO(auditor.package(evidence)))
    man = json.loads(z.read("manifest.json"))
    assert len(man["files"]) == len({e.evidence_id for e in evidence})


def _rezip(blob, mutate):
    import io
    import zipfile
    src = zipfile.ZipFile(io.BytesIO(blob))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for n in src.namelist():
            data = mutate(n, src.read(n))
            if data is not None:
                z.writestr(n, data)
    return out.getvalue()


def test_verify_detects_tamper(evidence):
    blob = auditor.package(evidence[:3])
    first = sorted(n for n in __import__("zipfile").ZipFile(__import__("io").BytesIO(blob)).namelist()
                   if n.startswith("evidence/"))[0]
    bad = _rezip(blob, lambda n, d: d + b" " if n == first else d)
    assert any("hash mismatch" in p for p in auditor.verify(bad))


def test_verify_detects_missing_and_extra(evidence):
    blob = auditor.package(evidence[:3])
    names = sorted(__import__("zipfile").ZipFile(__import__("io").BytesIO(blob)).namelist())
    gone = _rezip(blob, lambda n, d: None if n == names[0] else d)
    assert any("missing" in p for p in auditor.verify(gone))
    extra = _rezip(blob, lambda n, d: d)
    import io
    import zipfile
    buf = io.BytesIO(extra)
    with zipfile.ZipFile(buf, "a") as z:
        z.writestr("evidence/sneaky.json", b"{}")
    assert any("not in manifest" in p for p in auditor.verify(buf.getvalue()))


def test_package_records_still_verify(evidence):
    assert all(schema.verify(e) for e in evidence)
