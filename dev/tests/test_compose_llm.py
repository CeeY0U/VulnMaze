"""Static checks: the LLM services cannot widen the honeypot's reach."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[2]


@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load((ROOT / "infra/docker-compose.yml").read_text())


def members(compose, network):
    out = set()
    for name, svc in compose["services"].items():
        nets = svc.get("networks", [])
        if network in (nets if isinstance(nets, list) else nets.keys()):
            out.add(name)
    return out


def test_new_networks_are_internal(compose):
    for net in ("hpgw", "llm"):
        assert compose["networks"][net]["internal"] is True


def test_honeypot_shares_hpgw_with_the_gateway_only(compose):
    assert members(compose, "hpgw") == {"cowrie", "llm-gateway"}


def test_model_server_reachable_only_by_gateway(compose):
    assert members(compose, "llm") == {"llm-gateway", "ollama"}
    assert set(compose["services"]["ollama"]["networks"]) == {"llm"}
    assert "ports" not in compose["services"]["ollama"]


def test_only_the_gateway_bridges_attacker_side_and_backend(compose):
    attacker_side = members(compose, "dmz") | members(compose, "hpgw")
    assert attacker_side & members(compose, "backend") == {"llm-gateway"}
    assert "llm-gateway" not in members(compose, "dmz")


def test_egress_is_only_for_the_model_download_job(compose):
    assert members(compose, "egress") == {"ollama-pull"}
    assert compose["services"]["ollama-pull"]["profiles"] == ["models"]
    assert compose["services"]["ollama-pull"]["restart"] == "no"


def test_escalation_is_off_unless_configured(compose):
    env = compose["services"]["cowrie"]["environment"]
    assert env["VULNMAZE_ESCALATION"] == "${VULNMAZE_ESCALATION:-off}"


def test_persona_mounted_read_only(compose):
    assert "./persona:/persona:ro" in compose["services"]["llm-gateway"]["volumes"]
