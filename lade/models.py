"""Typed domain models for a Lade case."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

class Phase(str, Enum):
    CATALOG = "CATALOG"
    EXTRACTION = "EXTRACTION"
    CROSS_SYSTEM = "CROSS_SYSTEM"
    ALTERNATIVE_NARRATIVE = "ALTERNATIVE_NARRATIVE"
    REPORT = "REPORT"

PHASE_ORDER = tuple(Phase)
DEFAULT_MODELS = {"planner": "claude-opus-4-6", "executor": "claude-haiku-4-5", "analyst": "claude-opus-4-6"}

@dataclass(frozen=True)
class AgentConfig:
    role: str
    model: str

@dataclass
class EvidenceRef:
    call_id: str
    quote: str
    source_id: str

@dataclass
class Finding:
    finding_id: str
    title: str
    narrative: str
    severity: str
    confidence: float
    created_at: str
    evidence_refs: list[EvidenceRef]
    mitre_techniques: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class PhaseResult:
    phase: Phase
    success: bool
    attempts: int
    detail: str
