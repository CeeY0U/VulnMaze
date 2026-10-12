"""The real-model evaluation tooling: golden set shape, scoring, and the eval script."""

from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from _fake_llm import FakeLLM, Rule, ok
from conftest import PERSONA_PATH

from vulnmaze.llm.evaluation import cohen_kappa, load_golden, score, trap_violation
from vulnmaze.llm.persona import Persona
from vulnmaze.router import Route, classify_argv

ROOT = Path(__file__).parents[2]
GOLDEN = load_golden(ROOT / "dev/eval/golden_commands.yml")


def test_golden_set_shape():
    ids = [g.id for g in GOLDEN]
    assert len(ids) == len(set(ids)) and len(GOLDEN) >= 90
    cats = {g.category for g in GOLDEN}
    assert cats == {"system", "database", "web", "trap", "injection", "absent", "unknown"}
    assert sum(g.category == "trap" for g in GOLDEN) >= 25


@pytest.mark.parametrize("g", GOLDEN, ids=[g.id for g in GOLDEN])
def test_every_golden_command_reaches_the_gateway(g):
    """A golden command Cowrie answers itself, or a privilege one, would
    never reach the model and would measure nothing."""
    assert classify_argv(g.argv).route is Route.ESCALATE_CANDIDATE


def test_absent_category_matches_persona():
    persona = Persona.load(PERSONA_PATH)
    for g in GOLDEN:
        assert (g.argv[0] in persona.absent) == (g.category == "absent"), g.id


def test_cohen_kappa_known_values():
    assert cohen_kappa([1, 1, 0, 0, 1, 0], [1, 0, 0, 0, 1, 1]) == pytest.approx(1 / 3)
    assert cohen_kappa([0, 1, 1, 0, 1], [0, 1, 0, 0, 1]) == pytest.approx(0.32 / 0.52)
    assert cohen_kappa([1, 1, 1], [1, 1, 1]) == 1.0
    with pytest.raises(ValueError):
        cohen_kappa([1], [1, 0])


def test_trap_violation_rule():
    assert trap_violation("trap", "generated", 0)
    assert not trap_violation("trap", "generated", 1)
    assert not trap_violation("trap", "fallback", 0)          # attacker saw an error
    assert not trap_violation("system", "generated", 0)


@pytest.mark.db
def test_eval_script_end_to_end(dsn, pg, tmp_path):
    """The script runs the whole golden set through the real gateway code
    and writes a CSV plus summary; `score` reads the rated CSV back."""
    fake = FakeLLM(default=lambda cmd: ok(stderr=f"{cmd.split()[0]}: error\n", exit_code=1)).start()
    fake.rules = [Rule(r"systemctl status nonexistent-unit-xyz", ok(stdout="looks fine\n")),   # a violation
                  Rule(r"^(certbot|fail2ban-client|ufw|cloud-init|fooctl)", ok(exists=False))]
    from conftest import TEST_KEY
    fake.load()                                    # the script's preflight requires a loaded model
    env = os.environ | {"VULNMAZE_DSN": dsn, "VULNMAZE_DEID_KEY": TEST_KEY.hex(), "VULNMAZE_LLM_URL": fake.url,
                        "VULNMAZE_LLM_MODEL": "fake:1b", "VULNMAZE_PERSONA": str(PERSONA_PATH)}
    try:
        out = subprocess.run([sys.executable, str(ROOT / "dev/scripts/llm_eval.py"), "run", "--out", str(tmp_path)],
                             env=env, capture_output=True, text=True, timeout=240)
    finally:
        fake.stop()
    assert out.returncode == 0, out.stderr[-2000:]
    csv_path = next(tmp_path.glob("*.csv"))
    summary = json.loads(csv_path.with_suffix(".summary.json").read_text())
    assert summary["commands"] == len(GOLDEN)
    assert summary["trap_violations"] == 1 and summary["visible_leaks"] == 0
    assert summary["outcomes"]["not_installed"] >= 10          # 5 absent + 5 unknown
    assert summary["latency_ms_p95"] is not None

    rows = list(csv.DictReader(open(csv_path)))
    for i, r in enumerate(rows):                                # simulate two raters
        r["rater_1"] = "1"
        r["rater_2"] = "1" if i % 10 else "0"
    with open(csv_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)
    s = score(csv_path)
    assert s["rated"] == len(GOLDEN) and s["realistic_rater_1"] == 1.0 and s["cohen_kappa"] == 0.0
