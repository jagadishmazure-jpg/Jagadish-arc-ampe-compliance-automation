import hashlib
import io

import pytest
from openpyxl import load_workbook

from arcampe import agent, sspp


@pytest.fixture(scope="module")
def wb(findings):
    return sspp.build(findings)


@pytest.fixture(scope="module")
def blob(wb):
    return sspp.to_bytes(wb)


def test_sheets(wb):
    assert wb.sheetnames == ["Cover", "Controls", "POA&M", "Attestations", "Crosswalk", "Summary"]


def test_one_row_per_ae_control(wb):
    assert wb["Controls"].max_row - 1 == 402


def test_status_counts_measured(wb):
    assert sspp.status_counts(wb) == {"fail": 84, "not tested": 202, "pass": 116}


def test_only_approved_text_is_written(wb):
    approved = agent.load_approvals()
    for row in wb["Controls"].iter_rows(min_row=2, values_only=True):
        if row[0] in approved:
            assert row[8] == approved[row[0]]["text"] and row[9] == "r.alvarez"
        else:
            assert row[8] == "Pending approval"


def test_no_cms_control_text(wb):
    cover = {r[0]: r[1] for r in wb["Cover"].iter_rows(min_row=2, values_only=True)}
    assert "Not included" in cover["Control text"]


def test_reproducible_bytes(findings, blob):
    assert hashlib.sha256(blob).hexdigest() == hashlib.sha256(sspp.to_bytes(sspp.build(findings))).hexdigest()


def test_opens_in_openpyxl(blob):
    wb2 = load_workbook(io.BytesIO(blob))
    assert wb2["Summary"]["B2"].value == 402


def test_poam_sheet_matches(wb, poam_items):
    assert wb["POA&M"].max_row - 1 == len(poam_items)
