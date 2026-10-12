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


@pytest.mark.parametrize("service,var,value", [
    ("llm-gateway", "VULNMAZE_LLM_MODEL", "${VULNMAZE_LLM_MODEL:-qwen3.5:4b}"),
    ("ollama-pull", "VULNMAZE_LLM_MODEL", "${VULNMAZE_LLM_MODEL:-qwen3.5:4b}"),
    ("llm-gateway", "VULNMAZE_LLM_THINK", "${VULNMAZE_LLM_THINK:-false}"),
    ("llm-gateway", "VULNMAZE_LLM_MAX_TOKENS", "${VULNMAZE_LLM_MAX_TOKENS:-800}"),
])
def test_model_defaults_match_the_code(compose, service, var, value):
    assert compose["services"][service]["environment"][var] == value


@pytest.mark.parametrize("service", ["llm-gateway", "ollama-pull"])
def test_no_service_defaults_to_the_old_model(compose, service):
    assert "llama3.1:8b" not in str(compose["services"][service]["environment"])


@pytest.fixture(scope="module")
def hosted():
    return yaml.safe_load((ROOT / "infra/docker-compose.openrouter.yml").read_text())


def test_hosted_override_only_widens_the_gateway(hosted):
    assert set(hosted["services"]) == {"llm-gateway"}
    gateway = hosted["services"]["llm-gateway"]
    assert gateway["networks"] == ["egress"]
    assert gateway["environment"]["VULNMAZE_LLM_ALLOW_HOSTED"] == "1"
    assert gateway["environment"]["VULNMAZE_LLM_URL"] == "https://openrouter.ai/api"
    assert gateway["environment"]["VULNMAZE_LLM_API_KEY"].startswith("${OPENROUTER_API_KEY:?")
    assert gateway["environment"]["VULNMAZE_LLM_MODEL"].startswith("${OPENROUTER_MODEL:?")


@pytest.mark.parametrize("text", ["OPENROUTER", "openrouter", "VULNMAZE_LLM_ALLOW_HOSTED", "VULNMAZE_LLM_API_KEY"])
def test_default_stack_has_no_hosted_model_settings(text):
    assert text not in (ROOT / "infra/docker-compose.yml").read_text()


@pytest.mark.parametrize("name", ["OPENROUTER_API_KEY", "OPENROUTER_MODEL"])
def test_env_example_ships_openrouter_commented_out(name):
    lines = (ROOT / "infra/.env.example").read_text().splitlines()
    assert any(line.startswith(f"# {name}=") for line in lines)
    assert not any(line.startswith(f"{name}=") for line in lines)


def test_persona_mounted_read_only(compose):
    assert "./persona:/persona:ro" in compose["services"]["llm-gateway"]["volumes"]
