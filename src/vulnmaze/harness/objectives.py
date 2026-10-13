from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_TACTIC_RE = re.compile(r"^TA\d{4}$")


@dataclass(frozen=True)
class Objective:
    id: str
    tactic: str
    goal: str


def load_objectives(path: Path) -> dict[str, Objective]:
    """Load and validate an objective set from a YAML list of {id, tactic, goal} mappings."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list) or not raw:
        raise ValueError(f"{path}: expected a non-empty list of objectives")
    catalog: dict[str, Objective] = {}
    for entry in raw:
        if not isinstance(entry, dict) or set(entry) != {"id", "tactic", "goal"}:
            raise ValueError(f"{path}: each objective needs exactly id, tactic and goal; got {entry!r}")
        if not isinstance(entry["id"], str) or not _ID_RE.match(entry["id"]):
            raise ValueError(f"{path}: id must be a kebab-case slug; got {entry['id']!r}")
        if not isinstance(entry["tactic"], str) or not _TACTIC_RE.match(entry["tactic"]):
            raise ValueError(f"{path}: tactic must be an ATT&CK id like TA0007; got {entry['tactic']!r}")
        if not isinstance(entry["goal"], str) or not entry["goal"].strip():
            raise ValueError(f"{path}: goal must be a non-empty string for {entry['id']!r}")
        obj = Objective(entry["id"], entry["tactic"], entry["goal"].strip())
        if obj.id in catalog:
            raise ValueError(f"{path}: duplicate objective id {obj.id!r}")
        catalog[obj.id] = obj
    return catalog


DEFAULT_OBJECTIVES_FILE = Path(__file__).parent / "data" / "objectives.yml"
OBJECTIVES: dict[str, Objective] = load_objectives(DEFAULT_OBJECTIVES_FILE)
