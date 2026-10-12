"""Checks against a REAL local model. Never runs in CI; run it on the machine
with the GPU before tagging v0.6, and whenever you change model or prompt.

    export VULNMAZE_EVAL_LLM_URL=http://localhost:11434 VULNMAZE_EVAL_LLM_MODEL=qwen3.5:4b
    export VULNMAZE_TEST_DSN=postgresql://...
    pytest tests/v0_6/test_real_model.py -v -s

Thresholds (override with env vars) follow the roadmap: T0.6.5 no invented
success on logic traps (a small tolerance for 8B models, tighten as you
improve prompts), T0.6.7 p95 under 2 s, and no leak ever visible.
"""

from __future__ import annotations

import os
import statistics

import pytest
from conftest import ROOT

from vulnmaze.llm.evaluation import load_golden, trap_violation, visible_leak

pytestmark = [pytest.mark.llm, pytest.mark.db]

URL = os.environ.get("VULNMAZE_EVAL_LLM_URL")
MAX_TRAP_RATE = float(os.environ.get("VULNMAZE_EVAL_MAX_TRAP_RATE", "0.10"))
MAX_P95_MS = int(os.environ.get("VULNMAZE_EVAL_MAX_P95_MS", "2000"))


@pytest.fixture
def real_gateway(make_gateway):
    if not URL:
        pytest.skip("set VULNMAZE_EVAL_LLM_URL to run against a real model")
    from vulnmaze.llm.backends import OllamaBackend, OpenAIBackend

    model = os.environ.get("VULNMAZE_EVAL_LLM_MODEL", "qwen3.5:4b")
    kind = os.environ.get("VULNMAZE_EVAL_LLM_BACKEND", "ollama")
    backend = (OllamaBackend if kind == "ollama" else OpenAIBackend)(URL, model)
    return make_gateway(backend=backend, deadline_s=float(os.environ.get("VULNMAZE_LLM_DEADLINE_S", "8")),
                        per_attacker_per_min=10_000, burst=10_000, concurrency=1)


def test_real_model_golden_set(real_gateway):
    from vulnmaze.llm.gateway import CORRECTION
    from vulnmaze.llm.persona import Persona  # noqa: F401  (persona loaded by fixture)
    from vulnmaze.llm.sanitize import LeakageDetector

    gw, run = real_gateway
    detector = LeakageDetector(gw.prompts.leakage_corpus() + [CORRECTION], gw.cfg.canary)
    golden = load_golden(ROOT / "dev/eval/golden_commands.yml")
    results = [(g, run(g.argv, stdin=g.stdin)) for g in golden]

    leaks = [(g.id, visible_leak(detector, r.stdout, r.stderr)) for g, r in results]
    assert not [x for x in leaks if x[1]], f"visible leaks: {[x for x in leaks if x[1]]}"

    traps = [(g, r) for g, r in results if g.category == "trap"]
    violations = [g.id for g, r in traps if trap_violation(g.category, r.outcome, r.exit_code)]
    print(f"\ntrap violations: {len(violations)}/{len(traps)} {violations}")
    assert len(violations) / len(traps) <= MAX_TRAP_RATE

    lat = [r.latency_ms for _, r in results if r.outcome in ("generated", "fallback")]
    p95 = statistics.quantiles(lat, n=20)[18]
    fallbacks = sum(r.outcome == "fallback" for _, r in results)
    print(f"p95 latency {p95} ms, fallbacks {fallbacks}/{len(results)}")
    assert p95 <= MAX_P95_MS
    assert all(r.outcome == "not_installed" for g, r in results if g.category == "absent")
