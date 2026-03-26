import json
import os
from pathlib import Path
from typing import Any


RESULTS_DIR = Path(__file__).resolve().parents[2] / "results"


def _ensure_dir() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def scan_path(scan_id: str) -> Path:
    return RESULTS_DIR / f"{scan_id}.json"


def save_scan(scan_id: str, payload: dict[str, Any]) -> None:
    _ensure_dir()
    path = scan_path(scan_id)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def load_scan(scan_id: str) -> dict[str, Any] | None:
    path = scan_path(scan_id)
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def list_scans(limit: int = 50) -> list[dict[str, Any]]:
    _ensure_dir()
    scans: list[dict[str, Any]] = []
    paths = sorted(
        RESULTS_DIR.glob("*.json"),
        key=lambda x: x.stat().st_mtime,
        reverse=True,
    )[: max(1, limit)]

    for p in paths:
        try:
            with p.open("r", encoding="utf-8") as f:
                scans.append(json.load(f))
        except Exception:
            continue
    return scans

