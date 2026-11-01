# 04. Agents

**What you'll learn:** each AI or automated agent, its autonomy level, what it may touch and who approves its output.

**Read this after:** [03_ARCHITECTURE](03_ARCHITECTURE.md)

| Agent | Autonomy | What it does | Who approves | Guardrails |
|---|---|---|---|---|
| `agent:evidence-mapper` | act-with-approval | Maps evidence text to controls with a confidence score; below 0.6 goes to a person | ISSO for review items | injection screen, threshold, decision record |
| `agent:drafter` | suggest-only | Drafts control statements | ISSO | cannot change status |
| `agent:ownership` | suggest-only | Suggests an owner for unowned tasks | control owner's manager | agents cannot approve |
| `agent:tprm` | suggest-only | Scores vendors and sends questionnaires (simulated outbox) | procurement lead; CISO when high risk | no self-approval |
| `agent:copilot` | suggest-only | Answers questions and proposes changes through the MCP server | ISSO or CISO | scoped service keys, pending changes |
| `agent:discovery` | suggest-only | Finds AI tools in SSO and expense logs (shadow AI) | IT operations manager | routed to a named owner |

## The MCP-style server

Agents talk to the compliance data through a JSON-RPC server with **read tools** and **write tools**. A write
tool never writes: it creates a pending change (`CHG-00N`) that a human with the `isso` or `ciso` role must approve
with a note. Unknown keys, out-of-scope tools, bad arguments and injection text get distinct error codes.

<!-- run: python -m arcampe.grc mcp --out out -->
```text
{"jsonrpc": "2.0", "id": 1, "result": {"change_id": "CHG-001", "status": "pending_approval", "applied": false}}
```
<!-- /run -->

## Monitoring

Each agent must send a heartbeat at least every 24 hours. One does not (`agent:copilot`), so monitoring coverage
is below 100% and the AI-AGENT-OVERSIGHT control fails. See [07_AI_GOVERNANCE](07_AI_GOVERNANCE.md).

---

**Next:** [05_WORKFLOWS](05_WORKFLOWS.md)
