"""The state-store HTTP API, and consistency seen by an attacker."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.db

TOKEN = "test-token"


@pytest.fixture
def client(pg, dsn, monkeypatch):
    from conftest import TEST_KEY
    from fastapi.testclient import TestClient

    from vulnmaze.state import api

    monkeypatch.setenv("VULNMAZE_DSN", dsn)
    monkeypatch.setenv("VULNMAZE_DEID_KEY", TEST_KEY.hex())
    monkeypatch.setenv("VULNMAZE_STATE_TOKEN", TOKEN)
    with TestClient(api.app) as c:
        yield c


def test_requires_token(client):
    assert client.get("/v1/attackers/203.0.113.7/root/facts").status_code == 401
    assert client.get("/v1/attackers/203.0.113.7/root/facts",
                      headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_put_is_create_if_absent(client):
    h = {"Authorization": f"Bearer {TOKEN}"}
    url = "/v1/attackers/203.0.113.7/root/facts/file:/home/bob/notes.txt"
    r1 = client.put(url, json={"value": {"content": "v1"}, "created_by": "llm:test"}, headers=h).json()
    r2 = client.put(url, json={"value": {"content": "v2"}}, headers=h).json()
    assert r1["created"] and not r2["created"]
    assert r2["value"] == {"content": "v1"}
    assert client.get(url, headers=h).json()["value"] == {"content": "v1"}
    assert client.get("/v1/attackers/203.0.113.7/root/facts/nope", headers=h).status_code == 404
    listing = client.get("/v1/attackers/203.0.113.7/root/facts?prefix=file:", headers=h).json()
    assert [f["fact"] for f in listing] == ["file:/home/bob/notes.txt"]


@pytest.mark.cowrie
def test_same_output_after_reconnect(cowrie_server):
    """What the attacker sees must not change between sessions. In Phase A
    Cowrie serves these from its static filesystem; from v0.6 LLM-created
    files must pass this same test via the state store."""
    from _support import ssh_session

    cmds = ["cat /etc/passwd", "uname -a", "hostname", "ls -la /root", "exit"]
    first = ssh_session(cowrie_server.host, cowrie_server.port, cmds)
    second = ssh_session(cowrie_server.host, cowrie_server.port, cmds)
    assert first == second
