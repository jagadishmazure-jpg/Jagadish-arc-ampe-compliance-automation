import pytest

from arcampe import catalog, crosswalk

AE = catalog.baseline("ae")
EXPECTED = {"HIPAA": (402, 27), "SOC2": (402, 27), "ISO27001": (402, 42), "PCI_DSS": (402, 34),
            "GDPR": (242, 16), "CCPA": (179, 9), "COBIT": (402, 21)}


@pytest.mark.parametrize("fw,exp", sorted(EXPECTED.items()))
def test_coverage_measured(fw, exp):
    cov = crosswalk.coverage()[fw]
    assert (cov["controls_mapped"], cov["distinct_refs"]) == exp


def test_fedramp_proxy_count():
    assert crosswalk.coverage()["FEDRAMP_PROXY"]["controls_mapped"] == 270


@pytest.mark.parametrize("c", AE[::7], ids=lambda c: c.id)
def test_map_control_shape(c):
    m = crosswalk.map_control(c.id)
    assert set(m) == set(crosswalk.FRAMEWORKS)
    assert all(isinstance(v, tuple) for v in m.values())


@pytest.mark.parametrize("fw", ["HIPAA", "SOC2", "ISO27001"])
def test_reverse_is_inverse(fw):
    rev = crosswalk.reverse(fw)
    for ref, ctrls in list(rev.items())[:5]:
        for c in ctrls:
            assert ref in crosswalk.map_control(c)[fw]


def test_key_overrides():
    assert "164.312(b)" in crosswalk.map_control("AU-02")["HIPAA"]
    assert crosswalk.map_control("SC-08")["PCI_DSS"]


def test_coverage_table_lists_frameworks():
    t = crosswalk.coverage_table()
    for fw in EXPECTED:
        assert fw in t
