"""V2 labeling schema for crypto asset extraction and LLM dataset generation."""

from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class Category(str, Enum):
    SYMMETRIC_ENCRYPTION = "symmetric_encryption"
    ASYMMETRIC_CRYPTOGRAPHY = "asymmetric_cryptography"
    HASH_FUNCTION = "hash_function"
    MAC = "mac"
    KEY_EXCHANGE = "key_exchange"
    RNG = "rng"
    UNKNOWN = "unknown"


class ValueState(str, Enum):
    KNOWN = "known"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class PqcStatus(str, Enum):
    LEGACY = "legacy"
    TRANSITION = "transition"
    PQC_SAFE = "pqc_safe"
    UNKNOWN = "unknown"


class ScoredValue(BaseModel):
    value: Optional[str | int] = None
    state: ValueState = ValueState.UNKNOWN
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    reason: str = ""


class UsageItem(BaseModel):
    name: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class EvidenceItem(BaseModel):
    file_path: str
    language: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    function_name: Optional[str] = None
    snippet: Optional[str] = None
    context_before: Optional[str] = None
    context_after: Optional[str] = None
    detector: str = "static"
    source_type: str = "source"


class ValidationResult(BaseModel):
    is_valid: bool = True
    issues: List[str] = Field(default_factory=list)
    field_scores: Dict[str, float] = Field(default_factory=dict)


class DecisionAction(str, Enum):
    DROP = "drop"
    KEEP = "keep"
    KEEP_WITH_PENALTY = "keep_with_penalty"
    REQUIRE_REVIEW = "require_review"


class SeverityLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class QualityTier(str, Enum):
    HIGH = "high_quality"
    MEDIUM = "medium_quality"
    LOW = "low_quality"


class IssueDecision(BaseModel):
    issue: str
    severity: SeverityLevel
    action: DecisionAction


class DecisionResult(BaseModel):
    include: bool
    final_action: DecisionAction
    max_severity: SeverityLevel
    quality_score: float = Field(default=0.0, ge=0.0, le=100.0)
    quality_tier: QualityTier = QualityTier.LOW
    unknown_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    issue_count: int = 0
    evidence_count: int = 0
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    field_confidence_avg: float = Field(default=0.0, ge=0.0, le=1.0)
    severity_penalty: float = 0.0
    reasons: List[str] = Field(default_factory=list)
    issue_decisions: List[IssueDecision] = Field(default_factory=list)


class LabeledCryptoAsset(BaseModel):
    schema_version: str = "2.0.0"
    asset_id: str
    algorithm: str
    family: str
    category: Category
    key_length: ScoredValue
    mode: ScoredValue
    padding: ScoredValue
    usage: List[UsageItem] = Field(default_factory=list)
    pqc_status: PqcStatus = PqcStatus.UNKNOWN
    pqc_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    validation: ValidationResult = Field(default_factory=ValidationResult)
    decision: Optional[DecisionResult] = None


class InstructionRecord(BaseModel):
    instruction: str
    input: str
    output: Dict[str, str | int | None | List[str]]
    metadata: Dict[str, str | int | float | None]
