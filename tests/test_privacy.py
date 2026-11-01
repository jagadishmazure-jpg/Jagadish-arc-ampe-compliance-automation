import pytest

from arcampe import privacy, redact


@pytest.mark.parametrize("text,found", [
    ("ssn 123-45-6789 on file", ["123-45-6789"]),
    ("ssn 123456789", ["123456789"]),
    ("000-12-3456", []), ("666-12-3456", []), ("900-12-3456", []),
    ("123-00-4567", []), ("123-45-0000", []),
    ("phone 1234-56-78901", []),
])
def test_find_ssns_uses_ssa_rules(text, found):
    assert privacy.find_ssns(text) == found


@pytest.mark.parametrize("text,masked", [
    ("SSN 123-45-6789", "SSN ***-**-6789"),
    ("bad 000-12-3456 stays", "bad 000-12-3456 stays"),
])
def test_mask_ssn(text, masked):
    assert privacy.mask_ssn(text) == masked


def test_pseudonymize_is_keyed_and_stable():
    a = privacy.pseudonymize("123-45-6789", b"k1")
    assert a == privacy.pseudonymize("123-45-6789", b"k1")
    assert a != privacy.pseudonymize("123-45-6789", b"k2")
    assert "6789" not in a and a.startswith("tok_")


def test_inventory_findings_measured():
    f = privacy.check_inventory(privacy.load_inventory())
    assert (len(f), sum(x.passed for x in f)) == (36, 27)


@pytest.mark.parametrize("fid", ["PT-AUTH", "PT-PURP", "PT-SSN", "PT-XB", "PT-PIA", "PT-NOTICE", "PT-PLAIN",
                                 "PT-CONSENT"])
def test_each_privacy_check_runs(fid):
    assert any(x.id == fid for x in privacy.check_inventory(privacy.load_inventory()))


def test_rights_requests_deadline():
    rr = {r["id"]: r for r in privacy.rights_requests(privacy.load_inventory())}
    assert not rr["R-01"]["late"] and not rr["R-02"]["late"]
    assert rr["R-03"]["late"] and rr["R-04"]["late"]


def test_dpia_drivers():
    d = privacy.dpia({"id": "A", "data_elements": ["ssn", "income"], "volume": 200_000, "shared_with_vendor": True,
                      "storage_country": "US", "automated_decision": True})
    assert d["level"] == "high" and "SSN collected" in d["drivers"]
    low = privacy.dpia({"id": "B", "data_elements": ["email"], "storage_country": "US"})
    assert low["level"] == "low"


@pytest.mark.parametrize("text,kind", [
    ("call 555-123-4567", "phone"), ("mail jo@lakehaven-hx.example", "email"),
    ("ssn 123-45-6789", "ssn"), ("Medicaid ID: AB12345678", "medicaid_id"),
])
def test_redaction(text, kind):
    clean, counts = redact.redact(text)
    assert counts[kind] == 1
    assert "[" in clean
