"""Validation and correction layer for cryptographic labeling."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from models.crypto_schema import CryptoAsset
from models.label_schema import (
    Category,
    EvidenceItem,
    LabeledCryptoAsset,
    PqcStatus,
    ScoredValue,
    UsageItem,
    ValidationResult,
    ValueState,
)


BLOCK_MODES = {"CBC", "GCM", "CTR", "ECB", "CCM"}
RSA_PADDINGS = {"OAEP", "PKCS1", "PSS", "PKCS1V15"}


def _algorithm_family(name: str) -> str:
    upper = name.upper()
    if "AES" in upper:
        return "AES"
    if "CHACHA" in upper:
        return "ChaCha20"
    if "RSA" in upper:
        return "RSA"
    if "ECDSA" in upper:
        return "ECDSA"
    if "ECDH" in upper:
        return "ECDH"
    if "ECC" in upper or "EC_" in upper:
        return "ECC"
    if "SHA" in upper:
        return "SHA"
    if "MD5" in upper:
        return "MD5"
    if "HMAC" in upper:
        return "HMAC"
    if "PBKDF2" in upper:
        return "PBKDF2"
    if "BCRYPT" in upper:
        return "bcrypt"
    if "ARGON2" in upper:
        return "argon2"
    if "KYBER" in upper or "ML-KEM" in upper:
        return "ML-KEM"
    if "ML-DSA" in upper or "DILITHIUM" in upper:
        return "ML-DSA"
    if "CSPRNG" in upper or "RANDOM" in upper:
        return "RNG"
    return name


def _infer_category(name: str) -> Category:
    upper = name.upper()
    if any(x in upper for x in ["AES", "CHACHA", "DES", "RC4"]):
        return Category.SYMMETRIC_ENCRYPTION
    if any(x in upper for x in ["RSA", "ECC", "ECDSA", "ECDH", "DSA", "ML-DSA"]):
        return Category.ASYMMETRIC_CRYPTOGRAPHY
    if any(x in upper for x in ["SHA", "MD5", "BLAKE"]):
        return Category.HASH_FUNCTION
    if any(x in upper for x in ["PBKDF2", "BCRYPT", "ARGON2"]):
        return Category.HASH_FUNCTION
    if "HMAC" in upper:
        return Category.MAC
    if any(x in upper for x in ["KEM", "KEY-EXCHANGE", "KEY_AGREEMENT", "ECDH"]):
        return Category.KEY_EXCHANGE
    if any(x in upper for x in ["RNG", "RANDOM"]):
        return Category.RNG
    return Category.UNKNOWN


def _infer_pqc_status(name: str) -> PqcStatus:
    upper = name.upper()
    if any(x in upper for x in ["ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", "FALCON", "SLH-DSA"]):
        return PqcStatus.PQC_SAFE
    if any(x in upper for x in ["RSA", "ECDSA", "ECDH", "MD5", "SHA-1"]):
        return PqcStatus.LEGACY
    if any(x in upper for x in ["AES", "SHA-256", "SHA-512", "HMAC"]):
        return PqcStatus.TRANSITION
    return PqcStatus.UNKNOWN


def _make_usage(asset: CryptoAsset) -> List[UsageItem]:
    usages: List[UsageItem] = []
    for fn in asset.crypto_functions:
        usages.append(UsageItem(name=fn.value, confidence=min(max(asset.confidence, 0.2), 1.0)))
    if not usages:
        usages.append(UsageItem(name="unknown", confidence=0.3))
    return usages


def _scored_known(value: str | int | None, confidence: float, reason: str) -> ScoredValue:
    if value is None:
        return ScoredValue(value=None, state=ValueState.UNKNOWN, confidence=0.35, reason="not_detected")
    return ScoredValue(value=value, state=ValueState.KNOWN, confidence=confidence, reason=reason)


def _not_applicable(reason: str) -> ScoredValue:
    return ScoredValue(value=None, state=ValueState.NOT_APPLICABLE, confidence=1.0, reason=reason)


class ValidationEngine:
    """Rule-driven correction engine for category/attribute consistency."""

    def validate_asset(self, asset: CryptoAsset, evidence: List[EvidenceItem]) -> LabeledCryptoAsset:
        algorithm = asset.algorithm.name
        category = _infer_category(algorithm)
        family = _algorithm_family(algorithm)
        issues: List[str] = []

        if category == Category.UNKNOWN:
            issues.append("unknown_category")

        base_conf = min(max(asset.confidence, 0.1), 1.0)

        key_length = _scored_known(asset.algorithm.key_length, base_conf, "detected_or_inferred")
        mode = _scored_known(asset.algorithm.mode, base_conf, "detected_or_inferred")
        padding = _scored_known(asset.algorithm.padding, base_conf, "detected_or_inferred")

        # Category-aware correction rules
        if category == Category.ASYMMETRIC_CRYPTOGRAPHY:
            if mode.state == ValueState.KNOWN:
                issues.append("mode_removed_for_asymmetric")
            mode = _not_applicable("asymmetric_algorithms_do_not_use_mode")
            if padding.state == ValueState.UNKNOWN:
                padding.reason = "padding_may_apply_but_not_detected"

        elif category == Category.HASH_FUNCTION:
            key_length = _not_applicable("hash_functions_do_not_use_key_length")
            mode = _not_applicable("hash_functions_do_not_use_mode")
            padding = _not_applicable("hash_functions_do_not_use_padding")

        elif category == Category.MAC:
            mode = _not_applicable("mac_does_not_use_block_mode")
            padding = _not_applicable("mac_does_not_use_padding")

        elif category == Category.KEY_EXCHANGE:
            mode = _not_applicable("key_exchange_does_not_use_mode")
            padding = _not_applicable("key_exchange_does_not_use_padding")

        elif category == Category.RNG:
            key_length = _not_applicable("rng_key_length_not_applicable")
            mode = _not_applicable("rng_mode_not_applicable")
            padding = _not_applicable("rng_padding_not_applicable")

        elif category == Category.SYMMETRIC_ENCRYPTION:
            if mode.state == ValueState.KNOWN and str(mode.value).upper() not in BLOCK_MODES:
                issues.append("invalid_mode_for_symmetric")
                mode = ScoredValue(value=None, state=ValueState.UNKNOWN, confidence=0.3, reason="mode_not_in_known_set")

            # Padding only meaningful for selected block modes
            if mode.state == ValueState.KNOWN and str(mode.value).upper() in {"GCM", "CCM", "CTR"}:
                if padding.state == ValueState.KNOWN:
                    issues.append("padding_removed_for_aead_or_stream_mode")
                padding = _not_applicable("padding_not_used_in_aead_or_ctr")

        # Example contamination guard: CBC on RSA-like algorithm names
        if "RSA" in algorithm.upper() and mode.state == ValueState.KNOWN:
            issues.append("cross_algorithm_contamination_mode_removed")
            mode = _not_applicable("rsa_does_not_use_mode")

        # Confidence per field
        field_scores = {
            "algorithm": base_conf,
            "category": 0.95,
            "key_length": key_length.confidence,
            "mode": mode.confidence,
            "padding": padding.confidence,
            "usage": base_conf,
        }

        pqc_status = _infer_pqc_status(algorithm)
        pqc_conf = 0.9 if pqc_status != PqcStatus.UNKNOWN else 0.4

        validation = ValidationResult(
            is_valid=len(issues) == 0,
            issues=issues,
            field_scores=field_scores,
        )

        return LabeledCryptoAsset(
            asset_id=asset.ref,
            algorithm=algorithm,
            family=family,
            category=category,
            key_length=key_length,
            mode=mode,
            padding=padding,
            usage=_make_usage(asset),
            pqc_status=pqc_status,
            pqc_confidence=pqc_conf,
            confidence=base_conf,
            evidence=evidence,
            validation=validation,
        )
