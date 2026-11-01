"""Markdown tables for the docs, printed from live code so the docs cannot drift (see render_docs.py)."""
from __future__ import annotations

import sys


def trust() -> str:
    from .platform.trust import self_assessment
    lines = ["| ID | Claim | Result | Proof (live run) | Code | Test | NIST 800-53 | SOC 2 TSC | ISO 27001:2022 | HIPAA |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for r in self_assessment():
        lines.append(f"| {r['id']} | {r['claim']} | {'PASS' if r['passed'] else 'FAIL'} | {r['detail']} | "
                     f"`{r['code']}` | `{r['test']}` | {', '.join(r['nist'])} | {', '.join(r['soc2'])} | "
                     f"{', '.join(r['iso27001'])} | {', '.join(r['hipaa'])} |")
    return "\n".join(lines)


def responsibility() -> str:
    from .platform import responsibility as r
    return r.to_markdown().rstrip() + f"\n\nPrimary owner per control (402 AE controls): {r.primary_counts()}"


def attestations() -> str:
    from .platform import attestation_map as a
    return a.to_markdown().rstrip()


def ai_config() -> str:
    import json

    from . import DATA
    from .platform.secure_ai import check_ai_config
    cfg = json.loads((DATA / "platform" / "ai_config.json").read_text())
    rows = ["| Rule | Pass | Detail |", "|---|---|---|"]
    rows += [f"| {n} | {'yes' if ok else 'no'} | {d} |" for n, ok, d in check_ai_config(cfg)]
    return "\n".join(rows)


def procedures() -> str:
    from .platform import procedures as p
    out = ["**Change management (CM-03, CM-04, CM-05)**", "", "| Step | Owner | Evidence |", "|---|---|---|"]
    out += [f"| {s} | {o} | `{e}` |" for s, o, e in p.CHANGE_PROCEDURE]
    out += ["", p.EMERGENCY_RULE, "", "**Incident response (IR-04, IR-06, IR-08)**", "",
            "| Phase | Target | Action |", "|---|---|---|"]
    out += [f"| {a} | {b} | {c} |" for a, b, c in p.IR_PROCEDURE]
    return "\n".join(out)


def connectors() -> str:
    from .integrations.connectors import ALL
    rows = ["| Connector | Category | Method | Technology it stands in for | Records |", "|---|---|---|---|---:|"]
    for c in ALL:
        rows.append(f"| {c.name} | {c.category} | {c.method} | {c.product} | {len(c('t').collect())} |")
    return "\n".join(rows)


def mapper() -> str:
    from .integrations.mapper import sweep
    rows = ["| Threshold | Auto-mapped | Sent to review | Precision | Recall |", "|---:|---:|---:|---:|---:|"]
    rows += [f"| {r['threshold']} | {r['auto']} | {r['review']} | {r['precision']} | {r['recall']} |" for r in sweep()]
    return "\n".join(rows) + "\n\n60 items, labelled by the author. A regression check, not a quality claim."


def assurance() -> str:
    from .platform import assurance as a
    recs = a.load()
    rows = ["| Record | Labelled as | Evidence shows | OK | Issues |", "|---|---|---|---|---|"]
    rows += [f"| {r['id']} | {r['claimed']} | {r['actual']} | {'yes' if r['ok'] else 'no'} | {'; '.join(r['issues'])} |"
             for r in a.validate(recs)]
    rows += ["", "| Type | Control | Every (days) | Also when | Last | Next due | OK |", "|---|---|---:|---|---|---|---|"]
    rows += [f"| {c['type']} | {c['control']} | {c['every_days']} | {c['also_when']} | {c['last']} | {c['next_due']} | "
             f"{'yes' if c['ok'] else 'no'} |" for c in a.cadence_status(recs)]
    return "\n".join(rows)


def risk() -> str:
    from . import assess
    from .risk import cyber
    return cyber.top10_markdown(cyber.analyze(findings=assess.run_all())).rstrip()


def risk_frameworks() -> str:
    from .risk import builder, cyber
    m = builder.load()
    rows = ["| Threat | Controls | Frameworks reached (author-built crosswalks) |", "|---|---|---|"]
    for t in m["threats"]:
        fw = cyber.frameworks_for(t["controls"])
        rows.append(f"| {t['id']} {t['name']} | {', '.join(t['controls'])} | "
                    f"{', '.join(f'{k} ({len(v)})' for k, v in fw.items())} |")
    return "\n".join(rows)


def crosswalks() -> str:
    from .crosswalk import coverage
    rows = ["| Framework | AE controls mapped | Distinct references |", "|---|---:|---:|"]
    for fw, c in coverage().items():
        rows.append(f"| {fw} | {c['controls_mapped']} | {c['distinct_refs']} |")
    return "\n".join(rows)


def sources() -> str:
    from .source_coverage import NOT_USED_AS_FACT, to_markdown
    return to_markdown().rstrip() + "\n\n**Vendor claims seen on the pages and not used as facts:**\n\n" + \
        "\n".join(f"- {c}" for c in NOT_USED_AS_FACT)


TABLES = {n: f for n, f in globals().items() if callable(f) and n not in ("annotations",) and not n.startswith("_")
          and f.__module__ == __name__}

if __name__ == "__main__":
    print(TABLES[sys.argv[1]]())
