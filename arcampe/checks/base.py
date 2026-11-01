"""Shared types for configuration and evidence checks."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

SEVERITIES = ("critical", "high", "moderate", "low")


@dataclass(frozen=True)
class Finding:
    check_id: str
    resource_id: str
    resource_name: str
    passed: bool
    severity: str
    controls: tuple[str, ...]
    detail: str
    evidence: dict = field(default_factory=dict, hash=False, compare=False)


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    controls: tuple[str, ...]
    severity: str
    applies_to: tuple[str, ...]          # resource types, or ("directory",) / ("evidence:<kind>",)
    fn: Callable = field(hash=False, compare=False)
    rationale: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(self.severity)
