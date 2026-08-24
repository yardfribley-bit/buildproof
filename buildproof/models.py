from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Evidence:
    path: str
    line: int
    excerpt: str = ""


@dataclass(frozen=True)
class Endpoint:
    method: str
    path: str
    handler: str
    auth: str
    transport: str
    evidence: Evidence


@dataclass(frozen=True)
class ClientCall:
    path: str
    transport: str
    evidence: Evidence


@dataclass
class WebSurface:
    route: str
    source: Evidence
    calls: list[ClientCall] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    unresolved_calls: list[ClientCall] = field(default_factory=list)


@dataclass
class BusinessDomain:
    name: str
    pages: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    ecosystem: str
    layer: str
    scope: str
    evidence: Evidence


@dataclass
class AnalysisReport:
    project: str
    root: str
    technologies: list[str]
    entrypoints: list[Evidence]
    pages: list[WebSurface]
    endpoints: list[Endpoint]
    domains: list[BusinessDomain]
    components: list[Component]
    stats: dict[str, int]
    warnings: list[str]
    generated_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
