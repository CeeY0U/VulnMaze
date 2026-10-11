import configparser
from pathlib import Path

import pytest

from vulnmaze.llm.persona import Persona
from vulnmaze.llm.pinning import PersonaChecker, fact_contradictions

ROOT = Path(__file__).resolve().parents[2]


def test_persona_matches_cowrie_config(persona):
    """The LLM persona and Cowrie's own config describe the same machine."""
    cfg = configparser.RawConfigParser()
    cfg.read(ROOT / "infra/honeypot/cowrie.cfg")
    assert cfg["honeypot"]["hostname"] == persona.hostname
    assert cfg["shell"]["kernel_version"] == persona.kernel
    assert persona.codename in persona.os_pretty


def test_persona_rejects_overlapping_command_lists(tmp_path):
    """A command cannot be both installed and absent."""
    raw = (ROOT / "infra/persona/persona.yml").read_text().replace("    - masscan", "    - masscan\n    - lsblk")
    path = tmp_path / "persona.yml"
    path.write_text(raw)
    with pytest.raises(ValueError):
        Persona.load(path)


def test_checker_accepts_consistent_output(persona):
    """Output that repeats persona facts passes."""
    text = f"Linux {persona.hostname} {persona.kernel} #1 SMP\ninet {persona.facts['primary_ip']}/24\nnginx/1.22.1"
    assert PersonaChecker(persona).check(text) == []


@pytest.mark.parametrize("text,reason", [
    ("Linux mailhost 6.1.0-21-amd64 #1", "contradicts_persona:hostname=mailhost"),
    ("Ubuntu 22.04.3 LTS", "contradicts_persona:os=Ubuntu"),
    ("VERSION_CODENAME=jammy", "contradicts_persona:codename=jammy"),
    ("6.8.0-45-generic", "contradicts_persona:kernel=6.8.0-45-generic"),
    ("inet 192.168.1.50/24", "contradicts_persona:ip=192.168.1.50"),
    ("Server: nginx/1.18.0", "contradicts_persona:nginx_version=1.18.0"),
])
def test_checker_catches_contradictions(persona, text, reason):
    """Each kind of persona contradiction is detected without a model."""
    assert reason in PersonaChecker(persona).check(text)


def test_declared_and_stored_fact_contradictions(persona):
    """Declared facts must agree with the persona and with facts already pinned."""
    assert PersonaChecker(persona).check_declared({"php_version": "7.4.0"}) == ["contradicts_persona:php_version=7.4.0"]
    assert fact_contradictions({"db": "a", "new": "x"}, {"db": "b"}) == ["contradicts_fact:db"]
