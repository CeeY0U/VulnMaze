import os

import pytest

from vulnmaze.ingest.tailer import FileTailer
from vulnmaze.llm.backends import backend_from_env
from vulnmaze.llm.evaluation import cohen_kappa, trap_violation
from vulnmaze.llm.gateway import GatewayConfig
from vulnmaze.llm.ratelimit import TokenBuckets


def test_token_bucket_refills_over_time():
    """A burst is allowed, then requests wait for refill at the configured rate."""
    b = TokenBuckets(per_minute=60, burst=2)
    assert [b.allow("a", now=0), b.allow("a", now=0), b.allow("a", now=0)] == [True, True, False]
    assert b.allow("a", now=1.0) and b.allow("b", now=0)


def test_tailer_returns_only_complete_lines(tmp_path):
    """A line Cowrie is half-way through writing waits for the next poll."""
    log = tmp_path / "cowrie.json"
    log.write_bytes(b'{"a":1}\n{"b":')
    t = FileTailer(str(log))
    assert t.poll() == ['{"a":1}']
    with open(log, "ab") as fh:
        fh.write(b"2}\n")
    assert t.poll() == ['{"b":2}']
    assert t.checkpoint.offset == log.stat().st_size


@pytest.mark.skipif(os.name == "nt", reason="Windows cannot rename a file that is open")
def test_tailer_follows_rotation(tmp_path):
    """After rotation the old file is drained before the new one is read."""
    log = tmp_path / "cowrie.json"
    log.write_text("1\n")
    t = FileTailer(str(log))
    assert t.poll() == ["1"]
    with open(log, "a") as fh:
        fh.write("2\n")
    log.rename(tmp_path / "cowrie.json.2026-10-01")
    log.write_text("3\n")
    assert t.poll() == ["2"]
    assert t.poll() == ["3"]


def test_cohen_kappa():
    """Perfect agreement is 1, chance-level agreement is 0."""
    assert cohen_kappa([1, 0, 1, 0], [1, 0, 1, 0]) == 1.0
    assert cohen_kappa([1, 1, 0, 0], [1, 0, 1, 0]) == 0.0
    with pytest.raises(ValueError):
        cohen_kappa([1], [])


def test_trap_violation_only_counts_claimed_success():
    """A logic trap is violated only when the model answered and claimed success."""
    assert trap_violation("trap", "generated", 0)
    assert not trap_violation("trap", "generated", 1)
    assert not trap_violation("trap", "fallback", 0)
    assert not trap_violation("normal", "generated", 0)


def test_backend_defaults_fit_the_deadline(monkeypatch):
    """Answer cap, context window and deadline defaults are pinned, so results do not depend on Ollama's defaults."""
    for var in ("VULNMAZE_LLM_BACKEND", "VULNMAZE_LLM_MAX_TOKENS", "VULNMAZE_LLM_NUM_CTX", "VULNMAZE_LLM_DEADLINE_S"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("VULNMAZE_GATEWAY_TOKEN", "t" * 16)
    backend = backend_from_env()
    assert (backend.max_tokens, backend.num_ctx) == (400, 4096)
    assert GatewayConfig.from_env().deadline_s == 15.0
