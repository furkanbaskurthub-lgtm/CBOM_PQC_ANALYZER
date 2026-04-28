"""Policy-driven decision layer for dataset quality gating."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from models.label_schema import (
    DecisionAction,
    DecisionResult,
    IssueDecision,
    LabeledCryptoAsset,
    QualityTier,
    SeverityLevel,
    ValueState,
)


DEFAULT_POLICY_FILE = Path("config/policy_rules.json")


SEVERITY_ORDER = {
    SeverityLevel.LOW: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.HIGH: 3,
}


ACTION_ORDER = {
    DecisionAction.KEEP: 1,
    DecisionAction.KEEP_WITH_PENALTY: 2,
    DecisionAction.REQUIRE_REVIEW: 3,
    DecisionAction.DROP: 4,
}


class DecisionEngine:
    """Evaluates labeled assets against a policy and produces inclusion decisions."""

    def __init__(self, policy_path: str | Path = DEFAULT_POLICY_FILE):
        self.policy_path = Path(policy_path)
        self.policy = self._load_policy(self.policy_path)

    def reload_policy(self):
        self.policy = self._load_policy(self.policy_path)

    def evaluate_asset(self, asset: LabeledCryptoAsset) -> DecisionResult:
        issue_decisions = self._resolve_issue_decisions(asset.validation.issues)
        max_severity = self._max_severity(issue_decisions)
        final_action = self._final_action(issue_decisions)

        confidence = float(asset.confidence)
        field_confidence_avg = self._field_confidence_avg(asset)
        unknown_ratio = self._unknown_ratio(asset)
        issue_count = len(asset.validation.issues)
        evidence_count = len(asset.evidence)
        severity_penalty = self._severity_penalty(issue_decisions)

        quality_score = self._compute_quality_score(
            confidence=confidence,
            field_confidence_avg=field_confidence_avg,
            unknown_ratio=unknown_ratio,
            evidence_count=evidence_count,
            severity_penalty=severity_penalty,
            issue_count=issue_count,
        )
        quality_tier = self._quality_tier(quality_score)

        # Auto-include rule for common transport RNG/TLS artifacts: if clearly high-confidence
        # TLS/SSL or RNG evidence exists, avoid forcing require_review. This helps C/C++ repos
        # (e.g., QuickFIX) where algorithm details (key length/mode) are not present but
        # static evidence is strong.
        algo_name = getattr(asset, "algorithm", "") or getattr(asset, "family", "")
        algo_upper = (algo_name or "").upper() if isinstance(algo_name, str) else ""
        if evidence_count >= 1 and confidence >= 0.85 and (
            "TLS" in algo_upper or "SSL" in algo_upper or "RNG" in algo_upper or "CSPRNG" in algo_upper
        ):
            reasons = ["auto_include_tls_high_confidence"]
            return DecisionResult(
                include=True,
                final_action=DecisionAction.KEEP_WITH_PENALTY,
                max_severity=max_severity,
                quality_score=quality_score,
                quality_tier=quality_tier,
                unknown_ratio=unknown_ratio,
                issue_count=issue_count,
                evidence_count=evidence_count,
                confidence=confidence,
                field_confidence_avg=field_confidence_avg,
                severity_penalty=severity_penalty,
                reasons=reasons,
                issue_decisions=issue_decisions,
            )

        include, reasons = self._should_include(
            action=final_action,
            quality_score=quality_score,
            confidence=confidence,
            field_confidence_avg=field_confidence_avg,
            unknown_ratio=unknown_ratio,
            evidence_count=evidence_count,
        )

        return DecisionResult(
            include=include,
            final_action=final_action,
            max_severity=max_severity,
            quality_score=quality_score,
            quality_tier=quality_tier,
            unknown_ratio=unknown_ratio,
            issue_count=issue_count,
            evidence_count=evidence_count,
            confidence=confidence,
            field_confidence_avg=field_confidence_avg,
            severity_penalty=severity_penalty,
            reasons=reasons,
            issue_decisions=issue_decisions,
        )

    def split_by_decision(self, assets: List[LabeledCryptoAsset]) -> Dict[str, List[LabeledCryptoAsset]]:
        training: List[LabeledCryptoAsset] = []
        review: List[LabeledCryptoAsset] = []
        policy_drop: List[LabeledCryptoAsset] = []
        quality_reject: List[LabeledCryptoAsset] = []
        dropped: List[LabeledCryptoAsset] = []

        for asset in assets:
            decision = asset.decision or self.evaluate_asset(asset)
            asset.decision = decision

            if decision.include:
                training.append(asset)
                continue

            if decision.final_action == DecisionAction.REQUIRE_REVIEW:
                review.append(asset)
            elif decision.final_action == DecisionAction.DROP:
                policy_drop.append(asset)
                dropped.append(asset)
            else:
                quality_reject.append(asset)
                dropped.append(asset)

        return {
            "training": training,
            "review": review,
            "policy_drop": policy_drop,
            "quality_reject": quality_reject,
            "dropped": dropped,
        }

    def _resolve_issue_decisions(self, issues: List[str]) -> List[IssueDecision]:
        issue_policies = self.policy.get("issue_policies", {})
        results: List[IssueDecision] = []

        for issue in issues:
            key = self._normalize_issue_key(issue)
            config = issue_policies.get(key) or issue_policies.get("UNKNOWN", {"severity": "medium", "action": "require_review"})
            results.append(
                IssueDecision(
                    issue=key,
                    severity=SeverityLevel(config.get("severity", "medium")),
                    action=DecisionAction(config.get("action", "require_review")),
                )
            )

        return results

    def _max_severity(self, issue_decisions: List[IssueDecision]) -> SeverityLevel:
        if not issue_decisions:
            return SeverityLevel.LOW
        return max(issue_decisions, key=lambda x: SEVERITY_ORDER[x.severity]).severity

    def _final_action(self, issue_decisions: List[IssueDecision]) -> DecisionAction:
        if not issue_decisions:
            return DecisionAction.KEEP
        return max(issue_decisions, key=lambda x: ACTION_ORDER[x.action]).action

    def _severity_penalty(self, issue_decisions: List[IssueDecision]) -> float:
        penalties = self.policy.get("penalties", {})
        total = 0.0
        for item in issue_decisions:
            total += float(penalties.get(item.severity.value, 0.0))
        return total

    def _field_confidence_avg(self, asset: LabeledCryptoAsset) -> float:
        values = list(asset.validation.field_scores.values())
        if not values:
            return 0.0
        return min(max(sum(values) / len(values), 0.0), 1.0)

    def _unknown_ratio(self, asset: LabeledCryptoAsset) -> float:
        fields = [asset.key_length, asset.mode, asset.padding]
        applicable = [f for f in fields if f.state != ValueState.NOT_APPLICABLE]
        if not applicable:
            return 0.0
        unknown = [f for f in applicable if f.state == ValueState.UNKNOWN]
        return len(unknown) / len(applicable)

    def _compute_quality_score(
        self,
        confidence: float,
        field_confidence_avg: float,
        unknown_ratio: float,
        evidence_count: int,
        severity_penalty: float,
        issue_count: int,
    ) -> float:
        weights = self.policy.get("quality_weights", {})
        w_conf = float(weights.get("confidence", 0.45))
        w_field = float(weights.get("field_confidence", 0.25))
        w_known = float(weights.get("knownness", 0.15))
        w_evidence = float(weights.get("evidence", 0.15))

        evidence_score = 1.0 if evidence_count >= 2 else (0.7 if evidence_count == 1 else 0.0)
        quality_raw = 100.0 * (
            (w_conf * confidence)
            + (w_field * field_confidence_avg)
            + (w_known * (1.0 - unknown_ratio))
            + (w_evidence * evidence_score)
        )

        score = quality_raw - severity_penalty - (2.0 * issue_count)
        return round(min(max(score, 0.0), 100.0), 2)

    def _quality_tier(self, quality_score: float) -> QualityTier:
        tiers = self.policy.get("quality_tiers", {})
        high_min = float(tiers.get("high_min", 80))
        medium_min = float(tiers.get("medium_min", 60))

        if quality_score >= high_min:
            return QualityTier.HIGH
        if quality_score >= medium_min:
            return QualityTier.MEDIUM
        return QualityTier.LOW

    def _should_include(
        self,
        action: DecisionAction,
        quality_score: float,
        confidence: float,
        field_confidence_avg: float,
        unknown_ratio: float,
        evidence_count: int,
    ) -> Tuple[bool, List[str]]:
        global_cfg = self.policy.get("global", {})
        reasons: List[str] = []

        if action == DecisionAction.DROP:
            reasons.append("drop_action_policy")
            return False, reasons

        if action == DecisionAction.REQUIRE_REVIEW and not bool(global_cfg.get("allow_require_review_in_training", False)):
            reasons.append("requires_review")
            return False, reasons

        if evidence_count < int(global_cfg.get("min_evidence_count", 1)):
            reasons.append("insufficient_evidence")
        if confidence < float(global_cfg.get("min_confidence", 0.55)):
            reasons.append("low_confidence")
        if field_confidence_avg < float(global_cfg.get("min_field_confidence_avg", 0.5)):
            reasons.append("low_field_confidence")
        if unknown_ratio > float(global_cfg.get("max_unknown_ratio", 0.5)):
            reasons.append("high_unknown_ratio")
        if quality_score < 60.0:
            reasons.append("quality_below_threshold")

        return len(reasons) == 0, reasons

    def _normalize_issue_key(self, issue: str) -> str:
        return (issue or "UNKNOWN").strip().upper().replace("-", "_")

    def _load_policy(self, path: Path) -> Dict[str, Any]:
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
