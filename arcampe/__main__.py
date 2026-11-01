"""Command line: python -m arcampe <command>. Every command is offline and writes only under out/."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

from . import ROOT


def _out(name: str, data: bytes | str, out: pathlib.Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    p = out / name
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    print(f"wrote {p.relative_to(ROOT) if p.is_relative_to(ROOT) else p} ({p.stat().st_size} bytes)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="arcampe", description="ARC-AMPE compliance automation (synthetic demo)")
    ap.add_argument("command", choices=["catalog", "assess", "poam", "sspp", "conmon", "binder", "attest", "risk",
                                        "trust", "integrations", "mapper", "schedule", "audit", "all"])
    ap.add_argument("--out", default=str(ROOT / "out"))
    a = ap.parse_args(argv)
    out = pathlib.Path(a.out)
    cmd = a.command

    if cmd == "catalog":
        from . import catalog
        print(catalog.table("ae"))
    if cmd in ("assess", "all"):
        from . import assess
        print(json.dumps(assess.summary(), indent=1))
    if cmd in ("poam", "all"):
        from . import assess, poam
        items = poam.build(assess.run_all())
        print(json.dumps(poam.summary(items)))
        _out("poam.csv", poam.to_csv(items), out)
    if cmd in ("sspp", "all"):
        from . import sspp
        wb = sspp.build()
        print(json.dumps(sspp.status_counts(wb)))
        _out("sspp.xlsx", sspp.to_bytes(wb), out)
    if cmd in ("conmon", "all"):
        from . import conmon
        m = conmon.metrics()
        _out("conmon.md", conmon.to_markdown(m), out)
        _out("conmon.html", conmon.to_html(m), out)
    if cmd in ("binder", "all"):
        from . import binder
        b = binder.build()
        _out("ato_binder.zip", b, out)
        print("binder verify:", "intact" if not binder.verify(b) else "MISMATCH")
    if cmd == "attest":
        from . import attest
        items = attest.load()
        print(json.dumps(attest.summary(items)))
        for r in attest.reminders(items):
            print(f"[draft, not sent] to={r['to_role']} cc={r['cc_role']} subject={r['subject']!r}")
    if cmd in ("risk", "all"):
        from . import assess
        from .risk import cyber
        print(cyber.top10_markdown(cyber.analyze(findings=assess.run_all())))
    if cmd == "trust":
        from .platform import trust
        for r in trust.self_assessment():
            print(f"{r['id']} {'PASS' if r['passed'] else 'FAIL'} {r['claim']}")
    if cmd == "integrations":
        from .integrations.connectors import collect_all
        from .integrations.schema import verify
        ev = collect_all()
        print(f"{len(ev)} evidence records, {sum(verify(e) for e in ev)} hash-verified")
    if cmd == "mapper":
        from .integrations import mapper
        print(json.dumps(mapper.evaluate(), indent=1))
    if cmd == "schedule":
        from . import assess, poam
        from .automation import scheduler
        print(json.dumps(scheduler.simulate(30, poam_items=poam.build(assess.run_all()))["runs"]))
    if cmd == "audit":
        from . import assess, audit, catalog
        fams = {c.family: c.family_name for c in catalog.load()}
        for r in audit.audit_plan(assess.by_control(), fams):
            print(r)
    return 0


if __name__ == "__main__":
    sys.exit(main())
