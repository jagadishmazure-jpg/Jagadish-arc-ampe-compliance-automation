import csv
import io

import pytest

from arcampe import poam
from arcampe.checks.base import Finding
from arcampe.params import SLA_DAYS


def _f(sev="high", passed=False, cid="AZ-01", rid="r1"):
    return Finding(cid, rid, rid, passed, sev, ("SC-07",), "detail")


def test_measured_summary(poam_items):
    s = poam.summary(poam_items)
    assert s == {"open": 103, "by_severity": {"critical": 2, "high": 41, "moderate": 59, "low": 1},
                 "by_sla": {"on_track": 68, "due_soon": 13, "overdue": 22}}


def test_one_item_per_failed_finding(findings, poam_items):
    assert len(poam_items) == sum(not f.passed for f in findings)


def test_passed_findings_never_become_items():
    assert poam.build([_f(passed=True)], first_seen={}) == []


@pytest.mark.parametrize("sev", list(SLA_DAYS))
def test_due_date_is_first_seen_plus_sla(sev):
    item = poam.build([_f(sev)], today="2026-10-31", first_seen={"AZ-01|r1": "2026-10-01"})[0]
    import datetime as dt
    assert item.due == (dt.date(2026, 10, 1) + dt.timedelta(days=SLA_DAYS[sev])).isoformat()


@pytest.mark.parametrize("seen,status", [("2026-10-31", "on_track"), ("2026-10-05", "due_soon"),
                                         ("2026-09-01", "overdue")])
def test_sla_status(seen, status):
    item = poam.build([_f("high")], today="2026-10-31", first_seen={"AZ-01|r1": seen})[0]
    assert item.sla_status == status


def test_sla_days_match_cms_si02():
    assert SLA_DAYS == {"critical": 15, "high": 30, "moderate": 90, "low": 365}


def test_ids_stable_and_unique(poam_items):
    ids = [i.id for i in poam_items]
    assert len(ids) == len(set(ids))
    assert poam.poam_id("AZ-01|r1") == poam.poam_id("AZ-01|r1")


def test_sorted_by_severity_then_due(poam_items):
    order = list(SLA_DAYS)
    keys = [(order.index(i.severity), i.due) for i in poam_items]
    assert keys == sorted(keys)


def test_csv_round_trip(poam_items):
    rows = list(csv.DictReader(io.StringIO(poam.to_csv(poam_items))))
    assert len(rows) == len(poam_items)
    assert rows[0]["id"] == poam_items[0].id


@pytest.mark.parametrize("prefix,owner", sorted(poam.OWNER_BY_PREFIX.items()))
def test_owner_routing(prefix, owner):
    item = poam.build([_f(cid=f"{prefix}-01")], first_seen={})[0]
    assert item.owner == owner
