"""Every control ID and every code/test path referenced anywhere in the repo must exist."""
import re

import pytest

from arcampe import ROOT, catalog
from arcampe.catalog import FAMILY_ORDER
from arcampe.platform import attestation_map, trust

IDS = catalog.by_id()
PAT = re.compile(r"\b(%s)-\d{2}(?:\(\d{2}\))?(?![\d(])" % "|".join(FAMILY_ORDER))
FILES = sorted([*ROOT.joinpath("arcampe").rglob("*.py"), *ROOT.joinpath("data").rglob("*.json"),
                *ROOT.joinpath("data").rglob("*.yaml"), *ROOT.joinpath("policies").rglob("*.json")])
FILES = [f for f in FILES if "catalog" not in f.parts]


@pytest.mark.parametrize("path", FILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_control_ids_exist(path):
    unknown = sorted({m.group(0) for m in PAT.finditer(path.read_text())} - set(IDS))
    assert not unknown, unknown


def _paths(text: str) -> list[str]:
    return re.findall(r"(?:arcampe|tests)/[\w/]+\.py", text)


def _nodes():
    out = []
    for i in trust.ITEMS:
        out += [(i.id, p) for p in _paths(i.code)] + [(i.id, i.test)]
    for _prog, items in attestation_map.MAP.items():
        for name, code, test, _ in items:
            out += [(name, p) for p in _paths(code) + _paths(test)]
    return out


@pytest.mark.parametrize("owner,ref", _nodes())
def test_referenced_code_and_tests_exist(owner, ref):
    path, _, node = ref.partition("::")
    p = ROOT / path
    assert p.exists(), f"{owner}: {path} missing"
    if node:
        assert re.search(rf"^def {node}\b", p.read_text(), re.M), f"{owner}: {ref} missing"


def test_capability_coverage_paths_exist():
    from arcampe import ROOT, capability_coverage
    for slug, _, mods, test, status, _ in capability_coverage.AREAS:
        assert status in ("built", "partial", "gap"), slug
        for m in mods.split() + [test]:
            assert (ROOT / m).exists(), (slug, m)
    assert len(capability_coverage.AREAS) == 18


def test_readme_start_here_lists_every_markdown_file():
    import subprocess

    from arcampe import ROOT
    tracked = subprocess.run(["git", "ls-files", "*.md"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    on_disk = {str(p.relative_to(ROOT)) for p in ROOT.rglob("*.md")
               if not any(part.startswith(".") or part in ("out", "node_modules") for part in p.relative_to(ROOT).parts)}
    readme = (ROOT / "README.md").read_text()
    section = readme.split("## Start here: reading order", 1)[1].split("\n## ", 1)[0]
    missing = sorted(f for f in set(tracked) | on_disk if f"]({f})" not in section)
    assert not missing, missing
