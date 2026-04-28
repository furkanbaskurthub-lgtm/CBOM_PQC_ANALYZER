"""Helpers to convert labeled assets into instruction-tuning dataset records."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

from models.label_schema import InstructionRecord, LabeledCryptoAsset


DEFAULT_INSTRUCTION = (
    "Extract a structured cryptographic label from the input evidence. "
    "Return algorithm family, category, field states, and PQC status."
)


def build_instruction_record(asset: LabeledCryptoAsset, instruction: str = DEFAULT_INSTRUCTION) -> InstructionRecord:
    primary_evidence = asset.evidence[0] if asset.evidence else None
    input_text = ""
    if primary_evidence and primary_evidence.snippet:
        input_text = primary_evidence.snippet
    elif primary_evidence and primary_evidence.file_path:
        input_text = f"Detected in file: {primary_evidence.file_path}"
    else:
        input_text = f"Algorithm: {asset.algorithm}"

    output = {
        "algorithm": asset.algorithm,
        "family": asset.family,
        "category": asset.category.value,
        "key_length": asset.key_length.value,
        "key_length_state": asset.key_length.state.value,
        "mode": asset.mode.value,
        "mode_state": asset.mode.state.value,
        "padding": asset.padding.value,
        "padding_state": asset.padding.state.value,
        "pqc_status": asset.pqc_status.value,
        "usage": [item.name for item in asset.usage],
    }

    metadata = {
        "schema_version": asset.schema_version,
        "asset_id": asset.asset_id,
        "confidence": asset.confidence,
        "pqc_confidence": asset.pqc_confidence,
        "validation_ok": int(asset.validation.is_valid),
        "include": int(asset.decision.include) if asset.decision else 1,
        "quality_score": asset.decision.quality_score if asset.decision else None,
        "quality_tier": asset.decision.quality_tier.value if asset.decision else None,
        "decision_action": asset.decision.final_action.value if asset.decision else None,
        "max_severity": asset.decision.max_severity.value if asset.decision else None,
    }

    return InstructionRecord(
        instruction=instruction,
        input=input_text,
        output=output,
        metadata=metadata,
    )


def build_instruction_records(assets: Iterable[LabeledCryptoAsset], instruction: str = DEFAULT_INSTRUCTION) -> List[InstructionRecord]:
    return [build_instruction_record(asset, instruction=instruction) for asset in assets]


def write_jsonl(records: Iterable[InstructionRecord], output_path: str) -> int:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record.model_dump(), ensure_ascii=True) + "\n")
            count += 1
    return count
