"""Repository-level batch scanning helpers with include/exclude profiles."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List


def load_scan_profile(profile_name: str, config_path: str = "config/scan_profiles.json") -> Dict:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Scan profile config not found: {config_path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    profiles = data.get("profiles", {})
    if profile_name not in profiles:
        available = ", ".join(sorted(profiles.keys()))
        raise ValueError(f"Unknown profile '{profile_name}'. Available: {available}")

    return profiles[profile_name]


def list_scan_profiles(config_path: str = "config/scan_profiles.json") -> List[str]:
    path = Path(config_path)
    if not path.exists():
        return []

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return sorted(data.get("profiles", {}).keys())


def _normalize_path(path: Path) -> str:
    return path.as_posix().lower()


def _is_excluded(path: Path, repo_root: Path, exclude_globs: List[str]) -> bool:
    rel = path.relative_to(repo_root)
    rel_str = _normalize_path(rel)

    for pattern in exclude_globs:
        if rel.match(pattern):
            return True

        token = pattern.replace("**/", "").replace("/**", "").replace("*", "")
        token = token.strip("/").lower()
        if token and token in rel_str:
            return True

    return False


def collect_profile_files(repo_root: str, profile: Dict) -> List[Path]:
    root = Path(repo_root)
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Repo root not found: {repo_root}")

    include_globs = profile.get("include_globs", ["**/*"])
    exclude_globs = profile.get("exclude_globs", [])
    max_files = int(profile.get("max_files", 20000))

    found: List[Path] = []
    seen = set()

    for pattern in include_globs:
        for candidate in root.glob(pattern):
            if not candidate.is_file():
                continue

            key = str(candidate.resolve()).lower()
            if key in seen:
                continue

            if _is_excluded(candidate, root, exclude_globs):
                continue

            seen.add(key)
            found.append(candidate)

            if len(found) >= max_files:
                return sorted(found)

    return sorted(found)
