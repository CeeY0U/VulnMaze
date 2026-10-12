from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
from pathlib import Path

import pytest

from vulnmaze.common.deid import Deidentifier
from vulnmaze.llm.persona import Persona

ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(Path(__file__).parent))

from _support import run_cowrie  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
TEST_KEY = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
PERSONA_PATH = ROOT / "infra/persona/persona.yml"

# Values a test gateway is built with; they are not secrets, just fixed for assertions.
CANARY = "ref-0badc0ffee42"
TOKEN = "gateway-test-token-0123456789"
IP = "203.0.113.7"


@pytest.fixture
def fixtures() -> Path:
    """The directory of recorded Cowrie JSONL fixtures."""
    return FIXTURES


@pytest.fixture
def deid() -> Deidentifier:
    """A de-identifier with a fixed test key."""
    return Deidentifier(bytes.fromhex("11" * 32))


@pytest.fixture
def persona() -> Persona:
    """The persona shipped in infra/persona/persona.yml."""
    return Persona.load(ROOT / "infra/persona/persona.yml")


@pytest.fixture
def dsn() -> str:
    """The PostgreSQL DSN, or a skip when VULNMAZE_TEST_DSN is unset."""
    dsn = os.environ.get("VULNMAZE_TEST_DSN")
    if not dsn:
        pytest.skip("VULNMAZE_TEST_DSN not set")
    return dsn


@pytest.fixture
def pg(dsn):
    """A connection to an empty VulnMaze schema (tables dropped and recreated)."""
    import psycopg

    from vulnmaze.db import apply_schema

    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            "DROP TABLE IF EXISTS events, session_digests, ingest_checkpoints, "
            "ingest_errors, attacker_facts, llm_calls CASCADE"
        )
        apply_schema(conn)
        yield conn


@pytest.fixture
def fake_llm():
    """A scriptable stand-in for Ollama, so gateway tests need no model."""
    from _fake_llm import FakeLLM

    fake = FakeLLM().start()
    yield fake
    fake.stop()


@pytest.fixture
def loop():
    """An event loop for driving the async gateway from synchronous tests."""
    lp = asyncio.new_event_loop()
    yield lp
    lp.close()


@pytest.fixture
def make_gateway(pg, dsn, deid, fake_llm, loop):
    """Build a Gateway on the fake model and the test database.

    Returns build(backend=None, **cfg_overrides) -> (gateway, run), where
    run(argv, **request_fields) -> ShellResult.
    """
    from psycopg_pool import ConnectionPool

    from vulnmaze.llm.backends import OllamaBackend
    from vulnmaze.llm.gateway import Db, Gateway, GatewayConfig
    from vulnmaze.llm.persona import Persona
    from vulnmaze.llm.schema import EscalationRequest

    pools = []

    def build(backend=None, deadline_s: float = 5.0, warm: bool = True, **cfg):
        pool: ConnectionPool = ConnectionPool(
            dsn, open=True, min_size=1, max_size=10, kwargs={"autocommit": True})
        pools.append(pool)
        config = GatewayConfig(token=TOKEN, canary=CANARY, deadline_s=deadline_s, **cfg)
        gw = Gateway(config, Db(pool, deid), backend or OllamaBackend(fake_llm.url, "fake:1b"),
                     Persona.load(PERSONA_PATH))
        if warm:
            # The gateway answers with a fallback until Ollama has loaded the model, so tests that
            # exercise generation pay for that load up front. Pass warm=False for the not-ready path.
            async def load_model():
                gw.ensure_warming()
                if gw.warm_task is not None:
                    await gw.warm_task

            loop.run_until_complete(load_model())
            assert gw.model_ready, "the stand-in model did not finish loading"

        def run(argv, ip=IP, username="root", cwd="/root", stdin=None, session="s1", history=None):
            req = EscalationRequest(session=session, src_ip=ip, username=username, cwd=cwd,
                                    argv=list(argv), stdin=stdin, history=history or [])
            return loop.run_until_complete(gw.escalate(req))

        return gw, run

    yield build
    for p in pools:
        p.close()


@pytest.fixture
def _need_cowrie():
    if importlib.util.find_spec("cowrie") is None:
        pytest.skip("cowrie not installed (pip install -e '.[honeypot]')")


@pytest.fixture
def cowrie_server(_need_cowrie):
    """A throwaway Cowrie instance running the VulnMaze shell profile."""
    with run_cowrie("vulnmaze") as server:
        yield server


@pytest.fixture
def stock_cowrie_server(_need_cowrie):
    """A throwaway Cowrie instance running the upstream shell profile."""
    with run_cowrie("cowrie") as server:
        yield server


def pytest_collection_modifyitems(config, items):
    """Tests marked `stack` need `docker compose up`; skip them unless asked."""
    if os.environ.get("VULNMAZE_STACK") == "1":
        return
    skip = pytest.mark.skip(reason="set VULNMAZE_STACK=1 with the compose stack running")
    for item in items:
        if "stack" in item.keywords:
            item.add_marker(skip)
