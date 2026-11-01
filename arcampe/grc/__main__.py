"""Command line for the GRC workspace: python -m arcampe.grc <command>. Offline; writes only under out/."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

from .. import ROOT

COMMANDS = ["workspaces", "workflows", "custom-tests", "risk", "frameworks", "audit-package", "review", "cac",
            "mcp", "ai-policy", "soc2", "evidence", "owners", "vendors", "access-review", "ai-governance", "identity", "industry-packs", "scanner",
            "readiness-approval", "recipes", "insights", "policy-approvals", "risk-program", "ai-tests", "mapping-eval",
            "audit-hub", "ai-frameworks", "roadmap", "recurring", "scorecards", "report", "dashboard",
            "schedule", "all"]


def _write(out: pathlib.Path, name: str, data: bytes | str) -> None:
    p = out / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    print(f"wrote {p.relative_to(ROOT) if p.is_relative_to(ROOT) else p} ({p.stat().st_size} bytes)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="arcampe.grc", description="ARC-AMPE GRC workspace (synthetic demo)")
    ap.add_argument("command", choices=COMMANDS)
    ap.add_argument("--out", default=str(ROOT / "out"))
    ap.add_argument("--kind", choices=["daily", "weekly"], default="weekly")
    a = ap.parse_args(argv)
    out = pathlib.Path(a.out)
    c = a.command
    every = c == "all"

    if c == "workspaces" or every:
        from . import workspaces
        print(workspaces.table())
    if c == "workflows" or every:
        from . import workflows
        r = workflows.run_on_findings()
        print(json.dumps({k: v for k, v in r.items() if k != "log"}))
    if c == "custom-tests" or every:
        from . import custom_tests
        for r in custom_tests.summary():
            print(f"{r['id']} evaluated={r['evaluated']} failed={r['failed']} {r['title']}")
    if c == "risk" or every:
        from . import risk_registers
        print(json.dumps(risk_registers.by_register()))
        print(json.dumps(risk_registers.history()))
    if c == "frameworks" or every:
        from . import frameworks
        print(frameworks.readiness_table())
    if c == "audit-package" or every:
        from ..integrations.connectors import collect_all
        from . import auditor
        blob = auditor.package(collect_all())
        _write(out, "grc/evidence_package.zip", blob)
        print("package verify:", "intact" if not auditor.verify(blob) else "MISMATCH")
    if c == "review" or every:
        from . import review
        print(json.dumps(review.demo()))
    if c == "cac" or every:
        from . import cac
        print(json.dumps(cac.demo()))
    if c == "mcp" or every:
        from . import mcp_server
        s = mcp_server.demo_server()
        r = s.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "propose_status_change",
            "arguments": {"control_id": "AC-02", "status": "passing", "reason": "access review complete"}}},
            "k-copilot")
        print(json.dumps(r))
    if c == "ai-policy" or every:
        from . import ai_policy
        st = ai_policy.status()
        print(f"{st['control']}: {st['ready_parts']}/{st['of']} parts ready")
        for p in st["parts"]:
            print(f"  {p['part']}: {'Ready' if p['ready'] else 'Not ready'} ({p['why']}; owner {p['owner']})")
    if c == "soc2" or every:
        from . import soc2_path
        print(soc2_path.progress()["label"])
        for t in soc2_path.next_tasks():
            print(" -", t)
    if c == "evidence" or every:
        from . import evidence_status
        s = evidence_status.summary()
        print(json.dumps({"counts": s["counts"], "fresh_pct": s["fresh_pct"]}))
    if c == "owners" or every:
        from . import ownership
        print(json.dumps(ownership.ladder_counts()))
    if c == "vendors" or every:
        from . import vendor_requests
        for r in vendor_requests.demo():
            print(json.dumps(r))
    if c == "access-review" or every:
        from . import access_review_import as ar
        print(json.dumps(ar.summarize(ar.load())))
    if c == "ai-governance" or every:
        from . import ai_governance
        for k in ai_governance.kpis():
            print(f"{k['kpi']}: {k['value']} [{k['basis']}]")
        print("register:", json.dumps(ai_governance.register_summary()))
    if c == "identity" or every:
        from .. import resilience
        for r in resilience.identity_checks():
            print(f"{r['id']} {r['control']} {'PASS' if r['passed'] else 'FAIL'} {r['detail']}")
        print(json.dumps(resilience.identity_kpis()))
    if c == "industry-packs" or every:
        from . import industry_packs
        for r in industry_packs.all_readiness():
            print(f"{r['pack']:22} {r['name']:40} {r['ready_pct']:5}%  ({r['ready']}/{r['controls']}, approximate)")
        for r in industry_packs.demo().portfolio():
            print(f"org {r['org']:11} {r['pack']:22} passing/tested {r['passing']}/{r['tested']} = {r['readiness_pct']}%")
    if c == "scanner" or every:
        from . import scanner_import
        for r in scanner_import.checks():
            print(f"{r['id']:18} {r['control']:9} {'PASS' if r['passed'] else 'FAIL'}  {r['detail']}")
        print(json.dumps(scanner_import.kpis()))
    if c == "readiness-approval" or every:
        from . import readiness_approval
        print(json.dumps(readiness_approval.board()))
    if c == "recipes" or every:
        from . import recipes
        r = recipes.run()
        print(json.dumps({k: v for k, v in r.items() if k != "log"}))
        _write(out, "grc/monday_digest.txt", recipes.monday_digest(recipes.tasks_from_poam()))
    if c == "insights" or every:
        from . import insights
        print(json.dumps(insights.summary()))
    if c == "policy-approvals" or every:
        from . import policy_approvals
        d = policy_approvals.demo()
        print(json.dumps({"status": d["status"], "votes": d["votes"], "summary": d["summary"]}))
    if c == "risk-program" or every:
        from . import risk_program
        for r in risk_program.board_view():
            print(f"{r['register']:7} P50 ${r['p50']:>10,}  P90 ${r['p90']:>10,}  P95 ${r['p95']:>10,}  (SIMULATED)")
        print(json.dumps({k: v for k, v in risk_program.sla().items() if k != "rows"}))
    if c == "ai-tests" or every:
        from . import ai_tests
        print(json.dumps(ai_tests.summary()))
    if c == "mapping-eval" or every:
        from . import mapping_eval
        for t, r in mapping_eval.run()["by_type"].items():
            print(f"{t:11} top1={r['top1']} top3={r['top3']} mrr={r['mrr']} missed={r['missed']}")
    if c == "audit-hub" or every:
        from . import audit_hub
        print(json.dumps(audit_hub.request_summary()))
        print(json.dumps(audit_hub.check_independence()))
    if c == "ai-frameworks" or every:
        from . import ai_frameworks
        for r in ai_frameworks.readiness():
            print(f"{r['name']:16} {r['ready']}/{r['controls']} ready ({r['ready_pct']}%, approximate)")
        print(json.dumps(ai_frameworks.overlap()["overlap_pct"]), "% ISO 42001 topic overlap (author judgement)")
        print(json.dumps({k: v for k, v in ai_frameworks.cra_summary().items() if k != "rows"}))
    if c == "roadmap" or every:
        from . import roadmap
        for b in roadmap.BUYER_FIT:
            print(b, [(r["framework"], r["score"]) for r in roadmap.recommend(b)])
    if c == "recurring" or every:
        from . import recurring
        for r in recurring.status():
            print(f"{r['id']} {r['cadence']:11} done {r['completed']}/{r['occurrences']} missed {len(r['missed'])} "
                  f"next {r['next_due']}  {r['title']}")
    if c == "scorecards" or every:
        from . import scorecards
        sc = scorecards.build()
        for card in ("efficiency", "risk", "trust"):
            print(f"[{card}]")
            for k, v, b in sc[card]:
                print(f"  {k}: {v} [{b}]")
    if c in ("report", "dashboard") or every:
        from . import dashboard, reporting
        m = reporting.metrics()
        if c == "report" or every:
            for kind in ([a.kind] if c == "report" else ["daily", "weekly"]):
                for f in reporting.write_previews(out, kind, m):
                    print("wrote preview (not sent):", f)
        if c == "dashboard" or every:
            _write(out, "grc/dashboard.html", dashboard.to_html(m))
    if c == "schedule":
        from . import reporting
        print(reporting.crontab(), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
