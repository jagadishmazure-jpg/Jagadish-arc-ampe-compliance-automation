import pytest

from arcampe import catalog
from arcampe.checks import evidence_checks, registry
from arcampe.checks.base import SEVERITIES

IDS = catalog.by_id()
CHECKS = list(registry.CHECKS)
EV_CHECKS = list(evidence_checks.all_checks())


@pytest.mark.parametrize("chk", CHECKS + EV_CHECKS, ids=lambda c: c.id)
def test_check_controls_exist_in_catalog(chk):
    assert chk.controls
    for c in chk.controls:
        assert c in IDS, f"{chk.id} maps to unknown control {c}"
    assert chk.severity in SEVERITIES


def test_check_ids_unique():
    all_ids = [c.id for c in CHECKS + EV_CHECKS]
    assert len(all_ids) == len(set(all_ids))
    assert len(CHECKS) == 30 and len(EV_CHECKS) == 13


def test_registry_results_measured(findings):
    az = [f for f in findings if f.check_id.startswith("AZ-")]
    idf = [f for f in findings if f.check_id.startswith("ID-")]
    assert (sum(f.passed for f in az), sum(not f.passed for f in az)) == (261, 47)
    assert (sum(f.passed for f in idf), sum(not f.passed for f in idf)) == (5, 3)


def test_evidence_check_results_measured(evidence):
    res = evidence_checks.run(evidence)
    assert len(res) == 34 and sum(f.passed for f in res) == 20


@pytest.mark.parametrize("name,expected_fail", [
    ("stlhxarchive", "AZ-03"),          # Canada region
    ("stlhxstaticweb", "AZ-01"),        # public network
    ("kv-lhx-legacy", "AZ-08"),         # no purge protection
    ("stlhxdevscratch", "AZ-04"),       # TLS 1.0
    ("stlhxtemp", "AZ-05"),             # http allowed
])
def test_planted_misconfigs_are_caught(findings, name, expected_fail):
    assert any(f.resource_name == name and f.check_id == expected_fail and not f.passed for f in findings)


def test_deterministic(findings):
    from arcampe.checks.registry import load_estate, run
    a = run(load_estate())
    b = run(load_estate())
    assert [(f.check_id, f.resource_id, f.passed) for f in a] == [(f.check_id, f.resource_id, f.passed) for f in b]


def test_findings_have_controls(findings):
    for f in findings:
        assert f.controls and all(c in IDS for c in f.controls)


def test_ir06_one_hour_parameter():
    from arcampe.params import PARAMS
    assert PARAMS["IR-06"]["report_within_hours"] == 1
    assert PARAMS["AC-07"] == {"max_attempts": 5, "window_minutes": 15, "lockout_minutes": 30}
