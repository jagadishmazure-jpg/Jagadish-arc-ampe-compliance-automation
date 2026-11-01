"""Regenerate data/attestations.json (one row per attestation-labelled control, synthetic dates)."""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from arcampe import DATA, attest, catalog  # noqa: E402

ids = [c.id for c in catalog.load() if c.label == "attestation"]
(DATA / "attestations.json").write_text(json.dumps(attest.generate(ids), indent=1) + "\n")
print(f"wrote {len(ids)} attestation rows")
