"""ATO evidence binder: every output file plus a SHA-256 manifest, packed into a reproducible zip."""
from __future__ import annotations

import hashlib
import io
import json
import zipfile

from . import ENTITY, TODAY, assess, attest, conmon, poam, sspp
from .integrations.connectors import collect_all
from .platform import responsibility, trust
from .risk import cyber

ZIP_TIME = (2026, 10, 31, 0, 0, 0)


def files(findings=None) -> dict[str, bytes]:
    findings = assess.run_all() if findings is None else findings
    items = poam.build(findings)
    m = conmon.metrics(findings)
    ev = collect_all()
    return {
        "01_sspp/sspp.xlsx": sspp.to_bytes(sspp.build(findings)),
        "02_poam/poam.csv": poam.to_csv(items).encode(),
        "03_conmon/conmon.md": conmon.to_markdown(m).encode(),
        "03_conmon/conmon.html": conmon.to_html(m).encode(),
        "04_evidence/evidence.jsonl": "".join(json.dumps(e.to_dict(),
                                                         sort_keys=True, default=list) + "\n" for e in ev).encode(),
        "05_attestations/attestations.json": json.dumps(
            [{"control": a.control, "owner": a.owner, "status": a.status(), "last": a.last_attested}
             for a in attest.load()], indent=1).encode(),
        "06_risk/top10.md": cyber.top10_markdown(cyber.analyze(findings=findings)).encode(),
        "07_trust/self_assessment.json": json.dumps(trust.self_assessment(), indent=1, default=str).encode(),
        "07_trust/shared_responsibility.csv": responsibility.to_csv().encode(),
    }


def manifest(fs: dict[str, bytes]) -> dict:
    return {"entity": f"{ENTITY} (fictional)", "as_of": TODAY, "note": "Synthetic demo binder. Not a real ATO package.",
            "files": [{"path": k, "sha256": hashlib.sha256(v).hexdigest(), "bytes": len(v)} for k, v in sorted(fs.items())]}


def build(findings=None) -> bytes:
    fs = files(findings)
    fs["manifest.json"] = (json.dumps(manifest(fs), indent=1) + "\n").encode()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name in sorted(fs):
            zi = zipfile.ZipInfo(name, date_time=ZIP_TIME)
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, fs[name])
    return out.getvalue()


def verify(blob: bytes) -> list[str]:
    """Return paths whose hash does not match the manifest (empty list = intact)."""
    z = zipfile.ZipFile(io.BytesIO(blob))
    m = json.loads(z.read("manifest.json"))
    return [f["path"] for f in m["files"] if hashlib.sha256(z.read(f["path"])).hexdigest() != f["sha256"]]
