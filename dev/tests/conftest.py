from pathlib import Path

import pytest

from vulnmaze.common.deid import Deidentifier
from vulnmaze.llm.persona import Persona

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def deid() -> Deidentifier:
    """A de-identifier with a fixed test key."""
    return Deidentifier(bytes.fromhex("11" * 32))


@pytest.fixture
def persona() -> Persona:
    """The persona shipped in infra/persona/persona.yml."""
    return Persona.load(ROOT / "infra/persona/persona.yml")
