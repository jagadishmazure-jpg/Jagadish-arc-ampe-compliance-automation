"""Write data/poam_history.json: synthetic first-seen dates for today's failed findings (seeded)."""
import datetime as dt
import json
import pathlib
import random
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from arcampe import DATA, TODAY, assess, poam  # noqa: E402

rng = random.Random(1031)
today = dt.date.fromisoformat(TODAY)
hist = {}
for f in sorted(assess.run_all(), key=poam.key):
    if not f.passed:
        hist[poam.key(f)] = (today - dt.timedelta(days=rng.choice([0, 3, 10, 14, 20, 28, 45, 60, 85, 100]))).isoformat()
(DATA / "poam_history.json").write_text(json.dumps(hist, indent=1, sort_keys=True) + "\n")
print(f"wrote {len(hist)} first-seen dates")
