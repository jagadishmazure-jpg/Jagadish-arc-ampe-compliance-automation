import re

import pytest

from arcampe import catalog, ids, labels
from arcampe.catalog import FAMILY_ORDER

AE = catalog.baseline("ae")
EXPECTED_FAMILY_TOTALS = {"AC": 51, "AT": 9, "AU": 19, "CA": 12, "CM": 31, "CP": 23, "IA": 24, "IR": 16, "MA": 16,
                          "MP": 9, "PE": 19, "PL": 6, "PM": 28, "PS": 9, "PT": 10, "RA": 12, "SA": 34, "SC": 34,
                          "SI": 34, "SR": 6}


def test_ae_has_402_controls():
    assert len(AE) == 402


def test_dee_is_subset_of_ae():
    dee = {c.id for c in catalog.baseline("dee")}
    assert len(dee) == 308
    assert dee <= {c.id for c in AE}


def test_all_20_families_present():
    assert sorted({c.family for c in AE}) == sorted(FAMILY_ORDER)
    assert len(FAMILY_ORDER) == 20


@pytest.mark.parametrize("fam,total", sorted(EXPECTED_FAMILY_TOTALS.items()))
def test_family_totals(fam, total):
    assert sum(c.family == fam for c in AE) == total


def test_label_totals():
    got = {lb: sum(c.label == lb for c in AE) for lb in ("automated", "hybrid", "attestation")}
    assert got == {"automated": 65, "hybrid": 207, "attestation": 130}


@pytest.mark.parametrize("c", AE, ids=lambda c: c.id)
def test_every_control_is_well_formed(c):
    assert re.fullmatch(r"[A-Z]{2}-\d{2}(\(\d{2}\))?", c.id)
    assert c.label in ("automated", "hybrid", "attestation")
    assert c.title
    assert ids.to_oscal(c.id) == c.oscal_id
    assert c.enhancement == ("(" in c.id)


@pytest.mark.parametrize("c", [c for c in AE if c.label == "automated"], ids=lambda c: c.id)
def test_automated_controls_have_a_check(c):
    assert labels.checks_for(c.id)


@pytest.mark.parametrize("raw,canon", [("ac-2", "AC-02"), ("AC-2(3)", "AC-02(03)"), ("si-4 (4)", "SI-04(04)"),
                                       ("SC-07", "SC-07")])
def test_canonical_ids(raw, canon):
    assert ids.canonical(raw) == canon


@pytest.mark.parametrize("bad", ["", "A-1", "ACC-01", "AC-x"])
def test_bad_ids_rejected(bad):
    with pytest.raises(ValueError):
        ids.canonical(bad)


def test_oscal_round_trip():
    assert ids.to_oscal("AC-02(03)") == "ac-2.3"
    assert ids.base_of("AC-02(03)") == "AC-02"


def test_unknown_baseline_rejected():
    with pytest.raises(ValueError):
        catalog.baseline("fedramp")


def test_counts_table_mentions_all_families():
    t = catalog.table("ae")
    for f in FAMILY_ORDER:
        assert f"| {f} " in t
