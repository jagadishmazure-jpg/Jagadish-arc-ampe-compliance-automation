import pytest

from arcampe import attest


def test_summary_measured():
    assert attest.summary(attest.load()) == {"current": 90, "due_soon": 14, "overdue": 16, "missing": 10,
                                             "total": 130}


def test_all_attestation_controls_covered():
    from arcampe import catalog
    att = {c.id for c in catalog.baseline("ae") if c.label == "attestation"}
    assert {a.control for a in attest.load()} == att


def test_reminders_are_drafts():
    r = attest.reminders(attest.load())
    assert r and all(x["status"] == "draft" for x in r)
    assert all("[ARC-AMPE]" in x["subject"] for x in r)


@pytest.mark.parametrize("last,status", [(None, "missing"), ("2026-06-01", "current"), ("2025-11-15", "due_soon"),
                                         ("2025-01-01", "overdue")])
def test_status(last, status):
    a = attest.Attestation("AC-01", "isso", 365, last, None)
    assert a.status() == status


def test_generate_is_seeded():
    assert attest.generate(["PL-02", "PM-01"]) == attest.generate(["PL-02", "PM-01"])
