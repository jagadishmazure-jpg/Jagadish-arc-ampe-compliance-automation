"""Secure AI processing: AI runs inside a governed boundary and customer evidence never trains a model.

Enforced in code:
  * egress allow-list: the only host any AI client may call is the tenant's own Microsoft Foundry
    endpoint, reached over a private endpoint (HTTPS, named host, no IP literals);
  * an AI configuration policy (private endpoint, public access off, no training use, zero retention
    configured, U.S. region, redaction on);
  * prompts are redacted and screened before they leave the process;
  * a source scan proving the package has no network client code outside the guarded backend.
"""
from __future__ import annotations

import ast
import json
import pathlib
import re
from urllib.parse import urlparse

from .. import DATA, ROOT
from ..guards import screen
from ..params import US_REGIONS
from ..redact import redact

NETWORK_MODULES = {"requests", "httpx", "aiohttp", "urllib.request", "http.client", "socket", "ftplib", "smtplib"}
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^\[?[0-9a-f:]+\]?$", re.I)


class EgressBlocked(PermissionError):
    pass


def allowlist(path=None) -> dict:
    return json.loads((path or DATA / "platform" / "egress_allowlist.json").read_text())


def assert_egress_allowed(url: str, allow: dict | None = None) -> None:
    allow = allow or allowlist()
    u = urlparse(url)
    if u.scheme != "https":
        raise EgressBlocked("only https egress")
    host = (u.hostname or "").lower()
    if not host or IP_RE.match(host):
        raise EgressBlocked("IP literal or empty host")
    if host not in allow["hosts"]:
        raise EgressBlocked(f"{host} not in egress allow-list")


def check_ai_config(cfg: dict, allow: dict | None = None) -> list[tuple[str, bool, str]]:
    allow = allow or allowlist()
    host = urlparse(cfg["endpoint"]).hostname
    return [
        ("private endpoint", cfg.get("private_endpoint") is True, "required"),
        ("public network access off", cfg.get("public_network_access") == "Disabled", cfg.get("public_network_access")),
        ("endpoint on allow-list", host in allow["hosts"], host),
        ("no training on customer data", cfg.get("training_on_customer_data") is False, "contract + config"),
        ("zero data retention configured", cfg.get("data_retention_days") == 0, str(cfg.get("data_retention_days"))),
        ("U.S. region", cfg.get("region") in US_REGIONS, cfg.get("region")),
        ("PII redaction before prompt", cfg.get("redact_before_prompt") is True, "redact.py"),
        ("key-less auth (managed identity)", cfg.get("local_auth") is False, "Entra ID only"),
    ]


def prepare_prompt(text: str) -> str:
    hits = screen(text)
    if hits:
        raise EgressBlocked(f"prompt injection markers: {hits}")
    clean, _ = redact(text)
    if redact(clean)[1]["ssn"]:
        raise EgressBlocked("PII remained after redaction")
    return clean


def scan_source(root: pathlib.Path | None = None) -> list[str]:
    """Return network imports or hard-coded http(s) URLs found in the arcampe package."""
    root = root or ROOT / "arcampe"
    bad = []
    for f in sorted(root.rglob("*.py")):
        tree = ast.parse(f.read_text())
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
            for n in names:
                if n in NETWORK_MODULES:
                    bad.append(f"{f.relative_to(root.parent)}: import {n}")
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and re.match(r"https?://", node.value) \
                    and not (urlparse(node.value).hostname or "").endswith(".example"):   # RFC 2606 placeholders
                bad.append(f"{f.relative_to(root.parent)}: url {node.value}")
    return bad
