"""No-code export: an n8n workflow and Zapier-style recipes that push evidence to the signed webhook.

These are files to import into a no-code tool. Nothing here runs them. The endpoint and secret are
placeholders; the HMAC is computed in the workflow so the receiver's checks still apply.
"""
from __future__ import annotations

import json

ENDPOINT = "https://grc.lakehaven-hx.example/hooks/evidence"   # placeholder, .example is reserved

SIGN_JS = """// Build X-ArcAmpe-Signature: t=<ts>,v1=<hmac>
const crypto = require('crypto');
const body = JSON.stringify($json);
const ts = Math.floor(Date.now() / 1000);
const mac = crypto.createHmac('sha256', $env.ARCAMPE_WEBHOOK_SECRET).update(`${ts}.${body}`).digest('hex');
return [{ json: { body, header: `t=${ts},v1=${mac}` } }];"""


def n8n_workflow() -> dict:
    return {
        "name": "ARC-AMPE evidence push (example)",
        "nodes": [
            {"id": "1", "name": "Every day 06:00", "type": "n8n-nodes-base.scheduleTrigger", "typeVersion": 1,
             "position": [0, 0], "parameters": {"rule": {"interval": [{"field": "cronExpression",
                                                                       "expression": "0 6 * * *"}]}}},
            {"id": "2", "name": "Read source", "type": "n8n-nodes-base.httpRequest", "typeVersion": 4,
             "position": [220, 0], "parameters": {"method": "GET", "url": "={{$env.SOURCE_URL}}"}},
            {"id": "3", "name": "Map to evidence", "type": "n8n-nodes-base.set", "typeVersion": 3,
             "position": [440, 0], "parameters": {"values": {"string": [
                 {"name": "id", "value": "={{$json.id}}"}, {"name": "source", "value": "nocode_n8n"},
                 {"name": "category", "value": "webhook"}, {"name": "kind", "value": "={{$json.kind}}"},
                 {"name": "subject", "value": "={{$json.subject}}"},
                 {"name": "observed_at", "value": "={{$json.date}}"}]}}},
            {"id": "4", "name": "Sign", "type": "n8n-nodes-base.code", "typeVersion": 2, "position": [660, 0],
             "parameters": {"jsCode": SIGN_JS}},
            {"id": "5", "name": "POST to ARC-AMPE", "type": "n8n-nodes-base.httpRequest", "typeVersion": 4,
             "position": [880, 0], "parameters": {
                 "method": "POST", "url": ENDPOINT, "sendBody": True, "contentType": "raw",
                 "body": "={{$json.body}}", "sendHeaders": True,
                 "headerParameters": {"parameters": [{"name": "X-ArcAmpe-Signature", "value": "={{$json.header}}"},
                                                     {"name": "Content-Type", "value": "application/json"}]}}},
        ],
        "connections": {"Every day 06:00": {"main": [[{"node": "Read source", "type": "main", "index": 0}]]},
                        "Read source": {"main": [[{"node": "Map to evidence", "type": "main", "index": 0}]]},
                        "Map to evidence": {"main": [[{"node": "Sign", "type": "main", "index": 0}]]},
                        "Sign": {"main": [[{"node": "POST to ARC-AMPE", "type": "main", "index": 0}]]}},
        "settings": {"executionOrder": "v1"},
        "meta": {"note": "Example only. Set ARCAMPE_WEBHOOK_SECRET and SOURCE_URL in n8n credentials/env."},
    }


RECIPES = [
    {"name": "New HR termination -> evidence", "trigger": "HR system: employee terminated",
     "action": "Webhooks: POST", "kind": "hr_event", "controls": ["PS-04"],
     "map": {"subject": "work email", "observed_at": "termination date", "attributes.event": "'termination'"}},
    {"name": "Training completed -> evidence", "trigger": "Learning platform: course completed",
     "action": "Webhooks: POST", "kind": "training", "controls": ["AT-02"],
     "map": {"subject": "learner email", "observed_at": "completed date", "attributes.course": "course name"}},
    {"name": "Vendor contract signed -> evidence", "trigger": "E-signature: envelope completed",
     "action": "Webhooks: POST", "kind": "vendor_contract", "controls": ["SR-03", "SA-09"],
     "map": {"subject": "vendor id", "observed_at": "signed date", "attributes.breach_notify_hours": "clause value"}},
    {"name": "Policy approved -> evidence", "trigger": "Document library: file approved",
     "action": "Webhooks: POST", "kind": "policy_doc", "controls": ["PL-01", "PM-01"],
     "map": {"subject": "control id", "observed_at": "approved date", "attributes.version": "version"}},
]


def recipe_payload(recipe: dict, sample: dict) -> dict:
    """What a recipe sends: the same JSON the receiver expects (id, source, kind, subject, ...)."""
    return {"id": sample["id"], "source": "nocode_zapier", "category": "webhook", "kind": recipe["kind"],
            "subject": sample["subject"], "observed_at": sample["observed_at"],
            "attributes": sample.get("attributes", {}), "control_hints": recipe["controls"]}


def export(dirpath) -> list[str]:
    import pathlib
    d = pathlib.Path(dirpath)
    d.mkdir(parents=True, exist_ok=True)
    (d / "n8n_evidence_workflow.json").write_text(json.dumps(n8n_workflow(), indent=1) + "\n")
    (d / "zapier_style_recipes.json").write_text(json.dumps({"endpoint": ENDPOINT, "header": "X-ArcAmpe-Signature",
                                                              "recipes": RECIPES}, indent=1) + "\n")
    return ["n8n_evidence_workflow.json", "zapier_style_recipes.json"]
