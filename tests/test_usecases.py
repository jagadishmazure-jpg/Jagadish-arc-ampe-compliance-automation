"""Every use case in docs/USE_CASES.md runs and tells the story the doc claims."""
import contextlib
import io

import pytest

from arcampe import usecases


def _out(name: str) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        usecases.CASES[name]()
    return buf.getvalue()


@pytest.mark.parametrize("name", sorted(usecases.CASES))
def test_every_case_runs(name):
    assert _out(name).strip()


def test_public_storage_found_then_closed():
    out = _out("conmon_public_storage")
    assert "AZ-01 high" in out and "arcampe-storage-no-public-network" in out
    assert "AZ-01 PASS" in out and "after re-test: 0 -> closed" in out


def test_vendor_score_drops_after_fixes():
    out = _out("new_vendor")
    assert "Risk score (0-100): 46 moderate" in out and "After contract fixes and an assessment: 20 low" in out


def test_incident_clock_and_custody():
    out = _out("privacy_incident")
    assert "met 1-hour clock: True" in out
    assert "Chain of custody intact: True" in out and "After editing one artifact: False" in out
    assert "123-45-6789" not in out.split("SSN masking")[1]


def test_copilot_never_signs_off():
    out = _out("auditor_copilot")
    assert "0 signed off by AI" in out and "agent:copilot on its own upload: refused" in out
    assert "owner cannot validate own fix" in out


def test_first_ato_binder_reproducible():
    assert "same input, same bytes: True" in _out("first_ato")
