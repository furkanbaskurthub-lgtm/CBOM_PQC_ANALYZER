"""Run repository-level cryptographic labeling with profile-based include/exclude rules."""

from __future__ import annotations

import argparse
import os
import json
import time
import re
import threading
import shutil
import tempfile
import subprocess
import uuid
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional

from main import PQCReadyAnalyzer
from models.crypto_schema import CryptoBOM
from models.label_schema import LabeledCryptoAsset
from utils.repo_batch import collect_profile_files, load_scan_profile


_THREAD_LOCAL = threading.local()


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "-", (value or "run").strip())
    return cleaned.strip("-._") or "run"


def _create_run_output_dir(base_output_dir: str, run_label: str) -> Path:
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    run_dir = Path(base_output_dir) / f"run_{timestamp}_{_safe_name(run_label)}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def _get_worker_analyzer(output_dir: str) -> PQCReadyAnalyzer:
    analyzer = getattr(_THREAD_LOCAL, "analyzer", None)
    if analyzer is None:
        analyzer = PQCReadyAnalyzer(output_dir=output_dir, llm_cache_enabled=True)
        _THREAD_LOCAL.analyzer = analyzer
    return analyzer


def _analyze_single_file(
    file_path: str,
    use_llm: bool,
    output_dir: str,
    llm_candidate_only: bool,
    llm_min_confidence: float,
    llm_max_snippets: int,
) -> Tuple[list, Optional[CryptoBOM], str | None]:
    analyzer = _get_worker_analyzer(output_dir)
    try:
        cbom = analyzer.analyze_target(
            file_path,
            use_llm=use_llm,
            llm_candidate_only=llm_candidate_only,
            llm_min_confidence=llm_min_confidence,
            llm_max_snippets=llm_max_snippets,
        )
        labels = analyzer.generate_labeled_assets(cbom)
        # Worker memory footprint is kept bounded for large repos.
        analyzer.cbom_results.clear()
        analyzer._last_static_results.clear()
        return labels, cbom, None
    except Exception as exc:
        return [], None, str(exc)


def _build_repository_cbom(repo_root: str, cboms: List[CryptoBOM], profile_name: str, use_llm: bool) -> CryptoBOM:
    repo_cbom = CryptoBOM(
        bom_ref=f"cbom-repo-{uuid.uuid4().hex[:10]}",
        target_file=str(Path(repo_root).resolve()),
        target_type="application",
        created=datetime.utcnow(),
        metadata={
            "analysis_type": "repository_batch",
            "profile": profile_name,
            "use_llm": use_llm,
            "source_cbom_count": len(cboms),
        },
    )

    for cbom in cboms:
        repo_cbom.crypto_assets.extend(cbom.crypto_assets)

    return repo_cbom


def _split_cbom_layers(repo_cbom: CryptoBOM, labeled_assets: List[LabeledCryptoAsset]) -> Tuple[CryptoBOM, CryptoBOM]:
    """CBOM varlıklarını confirmed/context katmanlarına ayır."""
    by_asset_id = {a.asset_id: a for a in labeled_assets}
    context_only_detectors = {"java_import_signal"}

    confirmed_assets = []
    context_assets = []

    for asset in repo_cbom.crypto_assets:
        labeled = by_asset_id.get(asset.ref)
        detectors = {ev.detector for ev in labeled.evidence} if labeled else set()
        is_context = bool(detectors) and detectors.issubset(context_only_detectors)

        if is_context:
            asset.notes = "layer=context_crypto"
            context_assets.append(asset)
        else:
            asset.notes = "layer=confirmed_crypto"
            confirmed_assets.append(asset)

    confirmed_cbom = repo_cbom.model_copy(deep=True)
    confirmed_cbom.crypto_assets = confirmed_assets
    context_cbom = repo_cbom.model_copy(deep=True)
    context_cbom.crypto_assets = context_assets

    repo_cbom.metadata["layers"] = {
        "confirmed_crypto_assets": len(confirmed_assets),
        "context_crypto_assets": len(context_assets),
    }

    return confirmed_cbom, context_cbom


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Repository batch crypto labeling")
    parser.add_argument("repo_root", nargs="?", help="Path to repository root")
    parser.add_argument("--repo-url", help="GitHub repository URL (https://github.com/<org>/<repo>)")
    parser.add_argument("--ref", default="", help="Optional git ref/branch/tag")
    parser.add_argument("--profile", default="fineract-java", help="Profile name from config/scan_profiles.json")
    parser.add_argument("--use-llm", action="store_true", help="Enable LLM enrichment during analysis")
    parser.add_argument(
        "--llm-candidate-only",
        action="store_true",
        help="Run LLM only on candidate files with static crypto signals",
    )
    parser.add_argument(
        "--llm-min-confidence",
        type=float,
        default=0.85,
        help="When candidate mode is enabled, run LLM if static confidence is <= this threshold",
    )
    parser.add_argument(
        "--llm-max-snippets",
        type=int,
        default=2,
        help="Maximum code snippets per file for LLM analysis",
    )
    parser.add_argument("--output-dir", default="output", help="Output directory")
    parser.add_argument("--clone-depth", type=int, default=1, help="Shallow clone depth for URL mode")
    parser.add_argument("--keep-clone", action="store_true", help="Keep temporary cloned repository")
    parser.add_argument(
        "--workers",
        type=int,
        default=max(1, (os.cpu_count() or 4) // 2),
        help="Parallel worker count (default: half CPU cores)",
    )
    return parser.parse_args()


def _validate_github_url(repo_url: str) -> None:
    parsed = urlparse(repo_url)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise ValueError("Only https://github.com URLs are supported")

    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        raise ValueError("Invalid GitHub URL format. Expected https://github.com/<org>/<repo>")


def _build_clone_url(repo_url: str) -> str:
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if not token:
        return repo_url

    parsed = urlparse(repo_url)
    # Token is used only in transport URL and never written to summary outputs.
    return f"https://{token}@{parsed.netloc}{parsed.path}"


def _clone_repo_to_temp(repo_url: str, ref: str, clone_depth: int) -> Tuple[str, str]:
    _validate_github_url(repo_url)
    temp_dir = tempfile.mkdtemp(prefix="pqc-repo-")
    repo_dir = Path(temp_dir) / "repo"

    clone_url = _build_clone_url(repo_url)
    cmd = ["git", "clone", "--depth", str(max(1, clone_depth)), clone_url, str(repo_dir)]
    if ref.strip():
        cmd.extend(["--branch", ref.strip()])

    completed = subprocess.run(cmd, capture_output=True, text=True)
    if completed.returncode != 0:
        shutil.rmtree(temp_dir, ignore_errors=True)
        stderr = (completed.stderr or "").strip()
        raise RuntimeError(f"git clone failed: {stderr}")

    return str(repo_dir), temp_dir


def run_batch_scan(
    repo_root: str,
    profile_name: str = "fineract-java",
    use_llm: bool = False,
    output_dir: str = "output",
    workers: int = max(1, (os.cpu_count() or 4) // 2),
    llm_candidate_only: bool = False,
    llm_min_confidence: float = 0.85,
    llm_max_snippets: int = 2,
) -> Dict:
    profile = load_scan_profile(profile_name)
    prefix = profile.get("output_prefix", "repo")
    run_output_dir = _create_run_output_dir(output_dir, f"{prefix}-{profile_name}")
    analyzer = PQCReadyAnalyzer(output_dir=str(run_output_dir))
    files = collect_profile_files(repo_root, profile)

    if not files:
        summary = {
            "profile": profile_name,
            "repo_root": str(Path(repo_root).resolve()),
            "output_dir": str(run_output_dir.resolve()),
            "workers": max(1, workers),
            "duration_seconds": 0.0,
            "files_selected": 0,
            "assets_total": 0,
            "training": 0,
            "review": 0,
            "policy_drop": 0,
            "quality_reject": 0,
            "dropped": 0,
            "failures": [],
            "outputs": {},
            "message": "No files found for selected profile.",
        }

        summary_file = run_output_dir / f"{prefix}_batch_summary.json"
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        return summary

    print(f"Profile: {profile_name}")
    print(f"Files selected: {len(files)}")
    print(f"Workers: {max(1, workers)}")
    if use_llm:
        print(
            "LLM mode:",
            {
                "candidate_only": llm_candidate_only,
                "min_confidence": llm_min_confidence,
                "max_snippets": llm_max_snippets,
            },
        )

    all_labels: List = []
    all_cboms: List[CryptoBOM] = []
    failures = []
    started = time.time()

    worker_count = max(1, workers)

    if worker_count == 1:
        for i, file_path in enumerate(files, start=1):
            labels, file_cbom, err = _analyze_single_file(
                str(file_path),
                use_llm,
                str(run_output_dir),
                llm_candidate_only,
                llm_min_confidence,
                llm_max_snippets,
            )
            if err:
                failures.append({"file": str(file_path), "error": err})
            else:
                all_labels.extend(labels)
                if file_cbom:
                    all_cboms.append(file_cbom)

            if i % 250 == 0:
                print(f"Processed {i}/{len(files)} files...")
    else:
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_to_file = {
                executor.submit(
                    _analyze_single_file,
                    str(file_path),
                    use_llm,
                    str(run_output_dir),
                    llm_candidate_only,
                    llm_min_confidence,
                    llm_max_snippets,
                ): str(file_path)
                for file_path in files
            }

            for i, future in enumerate(as_completed(future_to_file), start=1):
                file_name = future_to_file[future]
                labels, file_cbom, err = future.result()
                if err:
                    failures.append({"file": file_name, "error": err})
                else:
                    all_labels.extend(labels)
                    if file_cbom:
                        all_cboms.append(file_cbom)

                if i % 250 == 0 or i == len(files):
                    print(f"Processed {i}/{len(files)} files...")

    split = analyzer.split_labeled_assets_by_decision(all_labels)

    labeled_json = analyzer.save_labeled_json(all_labels, filename=f"{prefix}_labeled_v2.json")
    training_jsonl = analyzer.export_instruction_dataset(
        split["training"],
        output_filename=f"{prefix}_dataset_training.jsonl",
        training_only=False,
    )
    review_jsonl = analyzer.export_instruction_dataset(
        split["review"],
        output_filename=f"{prefix}_dataset_review.jsonl",
        training_only=False,
    )
    dropped_jsonl = analyzer.export_instruction_dataset(
        split["dropped"],
        output_filename=f"{prefix}_dataset_dropped.jsonl",
        training_only=False,
    )
    policy_drop_jsonl = analyzer.export_instruction_dataset(
        split.get("policy_drop", []),
        output_filename=f"{prefix}_dataset_policy_drop.jsonl",
        training_only=False,
    )
    quality_reject_jsonl = analyzer.export_instruction_dataset(
        split.get("quality_reject", []),
        output_filename=f"{prefix}_dataset_quality_reject.jsonl",
        training_only=False,
    )

    repository_cbom = _build_repository_cbom(repo_root, all_cboms, profile_name, use_llm)
    confirmed_cbom, context_cbom = _split_cbom_layers(repository_cbom, all_labels)
    analyzer._compute_summary(repository_cbom)
    analyzer._compute_summary(confirmed_cbom)
    analyzer._compute_summary(context_cbom)
    cbom_json = analyzer.save_cbom_json(repository_cbom, filename=f"{prefix}_cbom_cyclonedx.json")
    cbom_confirmed_json = analyzer.save_cbom_json(confirmed_cbom, filename=f"{prefix}_cbom_confirmed.json")
    cbom_context_json = analyzer.save_cbom_json(context_cbom, filename=f"{prefix}_cbom_context.json")

    summary = {
        "profile": profile_name,
        "repo_root": str(Path(repo_root).resolve()),
        "output_dir": str(run_output_dir.resolve()),
        "workers": worker_count,
        "use_llm": use_llm,
        "llm_candidate_only": llm_candidate_only,
        "llm_min_confidence": llm_min_confidence,
        "llm_max_snippets": llm_max_snippets,
        "duration_seconds": round(time.time() - started, 2),
        "files_selected": len(files),
        "assets_total": len(all_labels),
        "training": len(split["training"]),
        "review": len(split["review"]),
        "policy_drop": len(split.get("policy_drop", [])),
        "quality_reject": len(split.get("quality_reject", [])),
        "dropped": len(split["dropped"]),
        "failures": failures,
        "outputs": {
            "cbom_json": str(cbom_json),
            "cbom_confirmed_json": str(cbom_confirmed_json),
            "cbom_context_json": str(cbom_context_json),
            "labeled_json": str(labeled_json),
            "training_jsonl": str(training_jsonl),
            "review_jsonl": str(review_jsonl),
            "policy_drop_jsonl": str(policy_drop_jsonl),
            "quality_reject_jsonl": str(quality_reject_jsonl),
            "dropped_jsonl": str(dropped_jsonl),
        },
    }

    summary_file = run_output_dir / f"{prefix}_batch_summary.json"
    summary_file.parent.mkdir(parents=True, exist_ok=True)
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    return summary


def main() -> None:
    args = parse_args()
    if not args.repo_root and not args.repo_url:
        raise ValueError("Provide either repo_root or --repo-url")

    if args.repo_root and args.repo_url:
        raise ValueError("Use either repo_root or --repo-url, not both")

    repo_path = args.repo_root
    temp_clone_dir: Optional[str] = None
    try:
        if args.repo_url:
            repo_path, temp_clone_dir = _clone_repo_to_temp(args.repo_url, args.ref, args.clone_depth)

        summary = run_batch_scan(
            repo_root=str(repo_path),
            profile_name=args.profile,
            use_llm=args.use_llm,
            output_dir=args.output_dir,
            workers=args.workers,
            llm_candidate_only=args.llm_candidate_only,
            llm_min_confidence=args.llm_min_confidence,
            llm_max_snippets=args.llm_max_snippets,
        )

        if args.repo_url:
            summary["repo_url"] = args.repo_url
            summary["ref"] = args.ref

        print("Batch completed.")
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    finally:
        if temp_clone_dir and not args.keep_clone:
            shutil.rmtree(temp_clone_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
