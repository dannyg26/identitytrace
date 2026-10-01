"""Load and validate correlation rule YAML files from correlations/."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import ValidationError

from app.correlation.schema import CorrelationRule
from app.resources import resource_directory


def _default_correlations_dir() -> Path:
    # See app/detections/loader.py's _default_detections_dir() for why an
    # override matters: this relative path only resolves correctly when
    # app/ sits in a source checkout (local run or editable install) -
    # not after a real, non-editable `pip install .`.
    override = os.environ.get("IDENTITYTRACE_CORRELATIONS_DIR")
    if override:
        return Path(override)
    return resource_directory("correlations")


DEFAULT_CORRELATIONS_DIR = _default_correlations_dir()


class CorrelationLoadError(RuntimeError):
    pass


def load_correlation_rules(
    directory: Path = DEFAULT_CORRELATIONS_DIR,
) -> list[CorrelationRule]:
    rules: list[CorrelationRule] = []
    seen_ids: dict[str, Path] = {}

    for path in sorted(directory.rglob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if raw is None:
            continue
        try:
            rule = CorrelationRule(**raw)
        except ValidationError as exc:
            raise CorrelationLoadError(
                f"invalid correlation rule in {path}: {exc}"
            ) from exc

        if rule.id in seen_ids:
            raise CorrelationLoadError(
                f"duplicate correlation id '{rule.id}' in {path} "
                f"(already defined in {seen_ids[rule.id]})"
            )
        seen_ids[rule.id] = path
        rules.append(rule)

    return rules
