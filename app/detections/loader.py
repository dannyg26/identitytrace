"""Load and validate detection rule YAML files from the detections/ directory."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import ValidationError

from app.detections.schema import DetectionRule
from app.resources import resource_directory


def _default_detections_dir() -> Path:
    # The relative-path default only holds when app/ sits in a source
    # checkout next to detections/ - true for a local run or an editable
    # install (`pip install -e .`, what this project's Dockerfile and dev
    # setup both use), but NOT true after a real `pip install .` relocates
    # the app package into site-packages away from detections/. Rather
    # than silently loading zero rules in that case, allow an explicit
    # override.
    override = os.environ.get("IDENTITYTRACE_DETECTIONS_DIR")
    if override:
        return Path(override)
    return resource_directory("detections")


DEFAULT_DETECTIONS_DIR = _default_detections_dir()


class DetectionLoadError(RuntimeError):
    pass


def load_rules(directory: Path = DEFAULT_DETECTIONS_DIR) -> list[DetectionRule]:
    rules: list[DetectionRule] = []
    seen_ids: dict[str, Path] = {}

    for path in sorted(directory.rglob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if raw is None:
            continue
        try:
            rule = DetectionRule(**raw)
        except ValidationError as exc:
            raise DetectionLoadError(f"invalid detection rule in {path}: {exc}") from exc

        if rule.id in seen_ids:
            raise DetectionLoadError(
                f"duplicate detection id '{rule.id}' in {path} "
                f"(already defined in {seen_ids[rule.id]})"
            )
        seen_ids[rule.id] = path
        rules.append(rule)

    return rules
