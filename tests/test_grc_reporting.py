import csv
import email
import email.policy
import io

import pytest

from arcampe.grc import dashboard, minipdf, reporting, svgchart
from arcampe.grc.__main__ import COMMANDS, main


@pytest.fixture(scope="module")
def m():
    return reporting.metrics()


KPI_KEYS = ["frameworks", "business_units", "controls", "failing_controls", "evidence", "poam", "risk", "vendors",
            "vulnerabilities", "access_review", "agents", "questionnaires", "soc2", "ai_policy", "trust_to_revenue"]


@pytest.mark.parametrize("key", KPI_KEYS)
def test_metrics_have_kpi(m, key):
    assert key in m


def test_controls_measured(m):
    assert m["controls"] == {"tested": 200, "passing": 115, "failing": 85}
    assert len(m["failing_controls"]) == 85


def test_vulns_match_poam(m):
    assert sum(v["open"] for v in m["vulnerabilities"].values()) == m["poam"]["open"] == 103
    assert sum(v["overdue"] for v in m["vulnerabilities"].values()) == m["poam"]["by_sla"]["overdue"] == 22


def test_trust_to_revenue_labeled_simulated(m):
    assert m["trust_to_revenue"]["label"] == "SIMULATED"
    assert m["trust_to_revenue"]["value_waiting"] == 135_000


def test_questionnaire_turnaround(m):
    assert m["questionnaires"] == {"requests": 3, "completed": 2, "avg_days_to_decision": 15.0, "sla_breaches": 1}


def test_agent_kpis(m):
    a = m["agents"]
    assert (a["mapper_precision"], a["mapper_recall"]) == (0.983, 0.95)


def test_headline_rows_labeled(m):
    rows = reporting.headline(m)
    assert len(rows) == 8 and all(b in ("measured, synthetic", "SIMULATED") for _, _, b in rows)


@pytest.mark.parametrize("kind", reporting.KINDS)
def test_html_contains_rings_and_banner(m, kind):
    h = reporting.to_html(m, kind)
    assert "Synthetic data" in h and "<svg" in h and "percent ready" in h and "not sent" in h
    assert "<script" not in h.lower()


def test_daily_is_shorter(m):
    assert len(reporting.to_html(m, "daily")) < len(reporting.to_html(m, "weekly"))
    assert "Vendor risk" not in reporting.to_html(m, "daily")


def test_weekly_has_all_sections(m):
    h = reporting.to_html(m, "weekly")
    for s in ("Framework readiness", "business unit", "severity", "Evidence status", "Risk posture", "Vendor risk",
              "Agent KPIs", "questionnaires", "SIMULATED"):
        assert s in h


def test_bad_kind(m):
    with pytest.raises(ValueError):
        reporting.to_html(m, "hourly")


def test_html_escapes(m):
    m2 = dict(m, entity="<b>x</b>")
    assert "<b>x</b>" not in reporting.to_html(m2, "daily")


def test_csv_parses(m):
    rows = list(csv.DictReader(io.StringIO(reporting.to_csv(m))))
    assert {r["section"] for r in rows} >= {"headline", "framework", "business_unit", "findings", "evidence",
                                             "vendor", "risk_trend", "agents", "trust_to_revenue"}
    assert any(r["basis"] == "SIMULATED" for r in rows)


def test_csv_framework_rows(m):
    rows = [r for r in csv.DictReader(io.StringIO(reporting.to_csv(m))) if r["section"] == "framework"]
    assert len(rows) == 3 * len(m["frameworks"])


@pytest.mark.parametrize("kind", reporting.KINDS)
def test_pdf_valid(m, kind):
    b = reporting.to_pdf(m, kind)
    assert b.startswith(b"%PDF-1.4") and b.rstrip().endswith(b"%%EOF") and minipdf.page_count(b) >= 1


def test_pdf_deterministic(m):
    assert reporting.to_pdf(m) == reporting.to_pdf(m)


@pytest.mark.parametrize("kind", reporting.KINDS)
def test_eml_structure(m, kind):
    msg = email.message_from_bytes(reporting.to_eml(m, kind), policy=email.policy.default)
    assert msg["Subject"].startswith("[PREVIEW - NOT SENT]") and msg["X-ARCAMPE-Preview"] == "true"
    names = sorted(p.get_filename() for p in msg.iter_attachments())
    assert names == [f"{kind}-report.csv", f"{kind}-report.pdf"]
    assert msg.get_body(("html",)) is not None and msg.get_body(("plain",)) is not None


def test_eml_deterministic(m):
    assert reporting.to_eml(m) == reporting.to_eml(m)


def test_write_previews(tmp_path, m):
    files = reporting.write_previews(tmp_path, "daily", m)
    assert [f.rsplit("/", 1)[1] for f in files] == ["daily.csv", "daily.eml", "daily.html", "daily.pdf"]
    assert all((tmp_path / "reports" / f.rsplit("/", 1)[1]).stat().st_size > 0 for f in files)


# ---------------------------------------------------------------- sending is refused by default
GOOD = {"enabled": True, "transport": "smtp", "to": ["ciso@lakehaven-hx.example"],
        "allowed_domains": ["lakehaven-hx.example"]}


def test_send_refused_without_anything():
    with pytest.raises(reporting.SendRefused):
        reporting.send(b"x")


def test_send_refused_without_approval():
    with pytest.raises(reporting.SendRefused, match="approval"):
        reporting.send(b"x", GOOD, approved=False, transport=lambda e, t: "ok")


def test_send_refused_without_transport():
    with pytest.raises(reporting.SendRefused, match="transport"):
        reporting.send(b"x", GOOD, approved=True)


@pytest.mark.parametrize("bad,msg", [
    ({"enabled": False}, "enabled"), ({"transport": "carrier-pigeon"}, "transport"), ({"to": []}, "empty"),
    ({"to": ["boss@elsewhere.example"]}, "allowed_domains"), ({"api_key": "x"}, "secrets"),
    ({"allowed_domains": []}, "allowed_domains")])
def test_send_config_checks(bad, msg):
    assert any(msg in e for e in reporting.check_send_config({**GOOD, **bad}))


def test_no_config_message():
    assert reporting.check_send_config(None) == ["no send config: previews only"]


def test_send_with_everything_uses_injected_transport():
    calls = []
    r = reporting.send(b"eml", GOOD, approved=True, transport=lambda e, t: calls.append((e, t)) or "id-1")
    assert r["sent"] is True and calls == [(b"eml", GOOD["to"])]


def test_module_ships_no_network_code():
    import inspect
    src = inspect.getsource(reporting)
    for bad in ("smtplib", "requests", "urllib", "http", "socket"):
        assert f"import {bad}" not in src and f"from {bad}" not in src


def test_crontab_and_schedule():
    c = reporting.crontab()
    assert "0 7 * * 1-5" in c and "--kind weekly" in c and "CRON_TZ=America/New_York" in c
    assert '"timezone": "America/New_York"' in reporting.schedule_json()


# ---------------------------------------------------------------- charts and dashboard
@pytest.mark.parametrize("pct,color", [(90, "#2e7d32"), (80, "#2e7d32"), (60, "#f9a825"), (10, "#c62828"),
                                       (-5, "#c62828"), (150, "#2e7d32")])
def test_ring_color(pct, color):
    assert color in svgchart.ring(pct, "X")


def test_ring_escapes_label():
    assert "<script>" not in svgchart.ring(50, "<script>")


def test_cards_grid():
    rows = [{"name": f"F{i}", "ready": i, "controls": 10, "ready_pct": i * 10, "coverage": "approximate"}
            for i in range(9)]
    h = svgchart.cards(rows, per_row=4)
    assert h.count("<tr>") == 3 and h.count("<svg") == 9


def test_hbar_zero_max():
    assert "<svg" in svgchart.hbar([("a", 0)], maximum=0)


def test_sparkline_empty():
    assert svgchart.sparkline([]) == ""


def test_stacked_legend():
    assert "overdue" in svgchart.stacked([("x", {"a": 1, "overdue": 2})], [("a", "info"), ("overdue", "bad")])


def test_minipdf_pages():
    d = minipdf.Doc()
    for i in range(120):
        d.text(f"line {i} (with parens)")
    assert minipdf.page_count(d.to_bytes()) >= 2


def test_dashboard(m):
    h = dashboard.to_html(m)
    assert "Content-Security-Policy" in h and "<script" not in h.lower()
    assert h.count("percent ready") == len(m["frameworks"])
    assert "SOC 2 requirements checked" in h


# ---------------------------------------------------------------- CLI
@pytest.mark.parametrize("cmd", [c for c in COMMANDS if c not in ("all",)])
def test_cli_commands(cmd, tmp_path, capsys):
    assert main([cmd, "--out", str(tmp_path)]) == 0
    assert capsys.readouterr().out


def test_cli_all_writes_previews(tmp_path, capsys):
    assert main(["all", "--out", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "wrote preview (not sent)" in out and "package verify: intact" in out
    assert (tmp_path / "reports" / "weekly.eml").exists() and (tmp_path / "grc" / "dashboard.html").exists()
