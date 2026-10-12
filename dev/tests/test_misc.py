import os

import pytest

from vulnmaze.ingest.tailer import FileTailer
from vulnmaze.llm.backends import backend_from_env
from vulnmaze.llm.evaluation import cohen_kappa, trap_violation
from vulnmaze.llm.gateway import GatewayConfig
from vulnmaze.llm.ratelimit import TokenBuckets


def _write_more(log, text: str) -> None:
    """Append to the log the way Cowrie does, without truncating it."""
    with open(log, "a") as fh:
        fh.write(text)


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
    assert t.poll() == []
    with open(log, "ab") as fh:
        fh.write(b"2}\n")
    assert t.poll() == ['{"b":2}']
    cp = t.checkpoint
    assert cp is not None and cp.offset == log.stat().st_size


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


def test_tailer_resumes_from_a_checkpoint(tmp_path):
    """Restarting the ingester with a stored checkpoint replays nothing."""
    log = tmp_path / "cowrie.json"
    log.write_text("1\n2\n")
    t = FileTailer(str(log))
    t.poll()
    _write_more(log, "3\n")
    assert FileTailer(str(log), t.checkpoint).poll() == ["3"]


@pytest.mark.skipif(os.name == "nt", reason="Windows cannot rename a file that is open")
def test_tailer_resumes_after_rotation_during_downtime(tmp_path):
    """Lines written and rotated while the ingester was down are still read once."""
    log = tmp_path / "cowrie.json"
    log.write_text("1\n")
    t = FileTailer(str(log))
    assert t.poll() == ["1"]
    _write_more(log, "2\n")
    log.rename(tmp_path / "cowrie.json.2026-10-01")
    log.write_text("3\n")
    t2 = FileTailer(str(log), t.checkpoint)
    assert t2.poll() == ["2"]
    assert t2.poll() == ["3"]


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
    for var in ("VULNMAZE_LLM_BACKEND", "VULNMAZE_LLM_MODEL", "VULNMAZE_LLM_MAX_TOKENS", "VULNMAZE_LLM_NUM_CTX",
                "VULNMAZE_LLM_DEADLINE_S"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("VULNMAZE_GATEWAY_TOKEN", "t" * 16)
    backend = backend_from_env()
    assert (backend.model, backend.max_tokens, backend.num_ctx) == ("qwen3.5:4b", 800, 4096)
    assert GatewayConfig.from_env().deadline_s == 15.0


@pytest.mark.parametrize("value,expected", [("false", False), ("0", False), ("true", True), ("yes", True)])
def test_think_setting_reaches_the_backend(monkeypatch, value, expected):
    """VULNMAZE_LLM_THINK turns the model's thinking mode on or off."""
    monkeypatch.setenv("VULNMAZE_LLM_THINK", value)
    assert backend_from_env().think is expected


@pytest.mark.parametrize("value", ["abc", "8.5", ""])
def test_token_cap_must_be_an_integer(monkeypatch, value):
    """A non-integer answer cap stops the gateway instead of being guessed."""
    monkeypatch.setenv("VULNMAZE_LLM_MAX_TOKENS", value)
    with pytest.raises(ValueError):
        backend_from_env()
