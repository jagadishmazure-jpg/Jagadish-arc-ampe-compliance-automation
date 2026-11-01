"""An MCP-style query server for AI assistants: JSON-RPC shaped requests, tools, scoped keys, approvals.

It mirrors the Model Context Protocol request shape ("tools/list", "tools/call") but runs in-process with
no network. Rules:
* Every call needs a service key. Read tools need the "read" scope.
* Write tools need "write:<tool>" scope AND never change anything directly: they create a pending change.
* A pending change is applied only after a human with the approver role approves it. Agents can't approve,
  and the person who asked can't approve their own change.
* Arguments are checked against each tool's schema (unknown keys rejected) and screened for prompt injection.
* Every call, refusal, approval and apply is written to a hash-chained audit log.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .. import TODAY, catalog
from ..guards import screen
from ..platform.audit_log import AuditLog

READ_TOOLS = {
    "list_controls": {"family": str},
    "get_control": {"control_id": str},
    "control_status": {"control_id": str},
    "framework_readiness": {"framework": str},
    "search_evidence": {"control_id": str},
    "poam_summary": {},
}
WRITE_TOOLS = {
    "propose_status_change": {"control_id": str, "status": str, "reason": str},
    "assign_owner": {"control_id": str, "owner": str, "reason": str},
    "create_exception": {"control_id": str, "reason": str, "expires": str},
}
APPROVER_ROLES = {"isso", "ciso"}


class McpError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ServiceKey:
    id: str
    principal: str
    scopes: tuple[str, ...]
    is_agent: bool = True


@dataclass
class Server:
    keys: dict[str, ServiceKey]
    log: AuditLog = field(default_factory=AuditLog)
    pending: dict[str, dict] = field(default_factory=dict)
    state: dict = field(default_factory=lambda: {"status": {}, "owner": {}, "exceptions": []})

    # ---- JSON-RPC entry point -------------------------------------------------------------------------
    def handle(self, req: dict, key_id: str) -> dict:
        rid = req.get("id")
        try:
            key = self.keys.get(key_id)
            if key is None:
                raise McpError(-32001, "unknown service key")
            m = req.get("method")
            if m == "tools/list":
                return {"jsonrpc": "2.0", "id": rid, "result": {"tools": self.tools(key)}}
            if m == "tools/call":
                p = req.get("params") or {}
                return {"jsonrpc": "2.0", "id": rid, "result": self.call(key, p.get("name", ""), p.get("arguments") or {})}
            raise McpError(-32601, f"method not found: {m}")
        except McpError as e:
            self.log.append(TODAY, "lakehaven", key_id, "mcp.error", str(req.get("method")), {"code": e.code, "msg": str(e)})
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": e.code, "message": str(e)}}

    def tools(self, key: ServiceKey) -> list[dict]:
        out = []
        for name, schema in READ_TOOLS.items():
            if "read" in key.scopes:
                out.append({"name": name, "kind": "read", "args": sorted(schema)})
        for name, schema in WRITE_TOOLS.items():
            if f"write:{name}" in key.scopes:
                out.append({"name": name, "kind": "write (needs human approval)", "args": sorted(schema)})
        return out

    def _check_args(self, schema: dict, args: dict) -> None:
        extra = set(args) - set(schema)
        if extra:
            raise McpError(-32602, f"unknown arguments {sorted(extra)}")
        for k, t in schema.items():
            if k not in args:
                if k == "family":
                    continue
                raise McpError(-32602, f"missing argument {k}")
            if not isinstance(args[k], t):
                raise McpError(-32602, f"{k} must be {t.__name__}")
            if isinstance(args[k], str) and screen(args[k]):
                raise McpError(-32003, f"argument {k} looks like a prompt injection")

    def call(self, key: ServiceKey, name: str, args: dict) -> dict:
        if name in READ_TOOLS:
            if "read" not in key.scopes:
                raise McpError(-32002, "key lacks read scope")
            self._check_args(READ_TOOLS[name], args)
            self.log.append(TODAY, "lakehaven", key.principal, "mcp.read", name, dict(args))
            return self._read(name, args)
        if name in WRITE_TOOLS:
            if f"write:{name}" not in key.scopes:
                raise McpError(-32002, f"key lacks write:{name} scope")
            self._check_args(WRITE_TOOLS[name], args)
            if "control_id" in args and args["control_id"] not in catalog.by_id():
                raise McpError(-32602, "unknown control")
            cid = f"CHG-{len(self.pending) + 1:03d}"
            self.pending[cid] = {"id": cid, "tool": name, "args": dict(args), "requested_by": key.principal,
                                 "status": "pending"}
            self.log.append(TODAY, "lakehaven", key.principal, "mcp.propose", name, {"change": cid})
            return {"change_id": cid, "status": "pending_approval", "applied": False}
        raise McpError(-32601, f"unknown tool {name}")

    def _read(self, name: str, a: dict) -> dict:
        from .. import assess
        if name == "list_controls":
            ids = [c.id for c in catalog.baseline("ae") if not a.get("family") or c.family == a["family"]]
            return {"count": len(ids), "controls": ids[:50]}
        if name == "get_control":
            c = catalog.by_id().get(a["control_id"])
            if c is None:
                raise McpError(-32602, "unknown control")
            return {"id": c.id, "title": c.title, "family": c.family, "label": c.label,
                    "owner": self.state["owner"].get(c.id)}
        if name == "control_status":
            st = assess.by_control().get(a["control_id"], {"status": "not_tested"})
            return {"control_id": a["control_id"], **st, "override": self.state["status"].get(a["control_id"])}
        if name == "framework_readiness":
            from . import frameworks
            if a["framework"] not in frameworks.ALL_MAPPED and a["framework"] != "NIST_800_53":
                raise McpError(-32602, "unknown framework")
            return frameworks.readiness(frameworks=[a["framework"]])[0]
        if name == "search_evidence":
            from ..integrations.connectors import collect_all
            hits = [e.evidence_id for e in collect_all() if a["control_id"] in e.control_hints]
            return {"control_id": a["control_id"], "evidence": hits}
        from .. import poam
        return poam.summary(poam.build(assess.run_all()))

    def approve(self, change_id: str, approver: str, role: str, is_agent: bool = False, note: str = "") -> dict:
        ch = self.pending.get(change_id)
        if ch is None or ch["status"] != "pending":
            raise McpError(-32004, "no such pending change")
        if is_agent or approver.startswith("agent:"):
            raise McpError(-32005, "agents cannot approve changes")
        if role not in APPROVER_ROLES:
            raise McpError(-32005, f"role {role} cannot approve")
        if approver == ch["requested_by"]:
            raise McpError(-32005, "cannot approve your own request")
        if not note.strip():
            raise McpError(-32602, "approval needs a note")
        a = ch["args"]
        if ch["tool"] == "propose_status_change":
            self.state["status"][a["control_id"]] = a["status"]
        elif ch["tool"] == "assign_owner":
            self.state["owner"][a["control_id"]] = a["owner"]
        else:
            self.state["exceptions"].append({"control": a["control_id"], "expires": a["expires"]})
        ch.update(status="applied", approved_by=approver)
        self.log.append(TODAY, "lakehaven", approver, "mcp.approve", change_id, {"note": note})
        return ch

    def reject(self, change_id: str, approver: str, note: str) -> dict:
        ch = self.pending[change_id]
        ch.update(status="rejected", approved_by=approver)
        self.log.append(TODAY, "lakehaven", approver, "mcp.reject", change_id, {"note": note})
        return ch


def demo_server() -> Server:
    return Server({"k-copilot": ServiceKey("k-copilot", "agent:copilot", ("read", "write:propose_status_change",
                                                                          "write:assign_owner")),
                   "k-readonly": ServiceKey("k-readonly", "agent:dashboard", ("read",))})
