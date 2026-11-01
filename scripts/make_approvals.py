"""Create data/approvals.json: stub-drafted statements approved by a fictional human ISSO (synthetic)."""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from arcampe import DATA, agent, assess  # noqa: E402

CONTROLS = ["AC-02(03)", "AC-07", "AC-11", "AU-11", "CP-09", "IA-02(01)", "IR-06", "PS-04", "RA-05", "SC-08",
            "SC-28", "SI-02"]
res = assess.by_control()
out = []
for c in CONTROLS:
    d = agent.draft(c, results=res.get(c))
    a = agent.approve(d, "r.alvarez", "isso", "Synthetic demo approval: checked text against check output.")
    out.append(agent.as_record(a))
(DATA / "approvals.json").write_text(json.dumps(out, indent=1) + "\n")
print(f"wrote {len(out)} approved statements")
