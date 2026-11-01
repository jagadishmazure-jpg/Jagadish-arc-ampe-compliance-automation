import subprocess
import sys

import pytest

from arcampe import ROOT


@pytest.mark.parametrize("script", ["check_brands.py", "render_docs.py"])
def test_repo_scripts_pass(script):
    args = [sys.executable, f"scripts/{script}"] + (["--check"] if script == "render_docs.py" else [])
    r = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stdout + r.stderr


def test_no_old_brand_name():
    bad = "Azure AI " + "Foundry"
    for p in ROOT.rglob("*"):
        if p.is_file() and p.suffix in {".py", ".md", ".json", ".yml", ".yaml", ".tf", ".bicep"} and \
                ".git" not in p.parts and "out" not in p.parts:
            assert bad not in p.read_text(errors="ignore"), p
