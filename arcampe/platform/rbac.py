"""Role-based access control with least privilege, MFA for privileged actions and separation of duties."""
from __future__ import annotations

from dataclasses import dataclass

PERMISSIONS = {
    "viewer": {"read"},
    "auditor": {"read", "export_binder", "read_audit_log"},
    "control_owner": {"read", "attest", "upload_evidence", "draft_statement"},
    "isso": {"read", "attest", "upload_evidence", "approve_statement", "manage_poam", "export_binder",
             "read_audit_log", "signoff_evidence"},
    "tenant_admin": {"read", "manage_users", "manage_connectors", "read_audit_log"},
}
PRIVILEGED = {"approve_statement", "manage_users", "manage_connectors", "export_binder", "signoff_evidence",
              "manage_poam"}


class AccessDenied(PermissionError):
    pass


@dataclass(frozen=True)
class Principal:
    id: str
    tenant_id: str
    roles: tuple[str, ...]
    mfa: bool = False
    phishing_resistant: bool = False
    is_agent: bool = False


def permissions(p: Principal) -> set[str]:
    out: set[str] = set()
    for r in p.roles:
        out |= PERMISSIONS.get(r, set())
    if p.is_agent:   # agents can read and draft only, never approve or sign off
        out &= {"read", "draft_statement"}
    return out


def authorize(p: Principal, action: str, tenant_id: str, *, owner_id: str | None = None) -> None:
    if p.tenant_id != tenant_id:
        raise AccessDenied("cross-tenant access")
    if action not in permissions(p):
        raise AccessDenied(f"{p.id} lacks {action}")
    if action in PRIVILEGED and not (p.mfa and p.phishing_resistant):
        raise AccessDenied(f"{action} needs phishing-resistant MFA")
    if owner_id is not None and owner_id == p.id and action in {"approve_statement", "signoff_evidence"}:
        raise AccessDenied("separation of duties: cannot approve own work")


def least_privilege_report(principals: list[Principal]) -> list[dict]:
    """Flag principals holding more roles than one, or admin without MFA."""
    out = []
    for p in principals:
        issues = []
        if len(p.roles) > 1:
            issues.append("multiple roles")
        if set(p.roles) & {"isso", "tenant_admin"} and not p.phishing_resistant:
            issues.append("privileged without phishing-resistant MFA")
        out.append({"principal": p.id, "roles": list(p.roles), "issues": issues})
    return out
