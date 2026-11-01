import json
import re
import subprocess
import sys

from arcampe import ROOT, iac
from arcampe.checks.registry import CHECKS
from arcampe.params import US_REGIONS


def test_policies_match_generator(tmp_path):
    before = {p.name: p.read_text() for p in iac.POLICY_DIR.glob("*.json")}
    subprocess.run([sys.executable, "scripts/make_policies.py"], cwd=ROOT, check=True, capture_output=True)
    assert {p.name: p.read_text() for p in iac.POLICY_DIR.glob("*.json")} == before


def test_each_policy_maps_to_a_real_check():
    ids = {c.id for c in CHECKS}
    for name, body in iac.load().items():
        assert body["metadata"]["arcampeCheck"] in ids, name
        assert body["parameters"]["effect"]["defaultValue"] == "Audit"


def test_terraform_regions_match():
    tf = (ROOT / "infra" / "terraform" / "variables.tf").read_text()
    block = tf[tf.index('variable "allowed_locations"'):]
    block = block[:block.index("\n}\n")]
    assert set(re.findall(r'"([a-z0-9]+)"', block.split("default", 1)[1])) == set(US_REGIONS)


def test_policy_regions_match():
    body = iac.load()["arcampe-us-locations"]
    assert set(body["parameters"]["allowedLocations"]["defaultValue"]) == set(US_REGIONS)


def test_bicep_uses_policy_files():
    b = (ROOT / "infra" / "bicep" / "main.bicep").read_text()
    for name in iac.load():
        assert f"{name}.json" in b


def test_evaluator_flags_planted(findings):
    from arcampe.checks.registry import load_estate
    hits = {(h["check"], h["resource"]) for h in iac.evaluate(load_estate())}
    assert ("AZ-03", "stlhxarchive") in hits and ("AZ-01", "stlhxstaticweb") in hits
    assert json.dumps(sorted(hits))
