from __future__ import annotations

import io
import json

import pytest

from vulnmaze.harness import runner
from vulnmaze.harness.agent import AgentError, AgentStep, parse_step
from vulnmaze.harness.objectives import OBJECTIVES, load_objectives
from vulnmaze.harness.runner import ContainmentError, check_target, run_session


class _FakeClient:
    def close(self) -> None:
        pass


class _FakeChan:
    def __init__(self) -> None:
        self.sent: list[str] = []

    def sendall(self, data: str) -> None:
        self.sent.append(data)


class _ScriptedAttacker:
    model = "fake/model"
    prompt_tokens = 11
    completion_tokens = 7

    def __init__(self, steps: list[AgentStep]) -> None:
        self._steps = steps
        self.seen: list[str | None] = []

    def next_step(self, last_output):
        self.seen.append(last_output)
        return self._steps.pop(0)


@pytest.mark.parametrize(
    "command, done",
    [("id", True), ("uname -a", True)],
)
def test_valid_step_drives_command(monkeypatch, command, done):
    """A parsed step sends its command to the shell and logs a well-formed record."""
    chan = _FakeChan()
    monkeypatch.setattr(runner, "_open_shell", lambda *a, **k: (_FakeClient(), chan, "127.0.0.1", 54321))
    monkeypatch.setattr(runner, "_read_until_idle", lambda *a, **k: "uid=0(root)\n")
    step = AgentStep(command=command, intent="probe", tactic="TA0007", technique="T1082", done=done)
    attacker = _ScriptedAttacker([step])
    sink = io.StringIO()

    summary = run_session(
        OBJECTIVES["discovery"],
        attacker,
        sink,
        host="127.0.0.1",
        port=2222,
        username="root",
        password="hunter2x",
        max_steps=5,
        read_timeout=1.0,
    )

    assert chan.sent == [command + "\n"]
    record = json.loads(sink.getvalue().splitlines()[-1])
    assert record["command"] == command
    assert record["tier"] == "llm_agent"
    assert record["output_len"] == len("uid=0(root)\n")
    assert summary["steps"] == 1


@pytest.mark.parametrize(
    "body",
    [
        "- id: discovery\n  tactic: TA0007\n  goal: Fingerprint the host.\n",
        "- {id: a, tactic: TA0001, goal: g1}\n- {id: b, tactic: TA0002, goal: g2}\n",
    ],
)
def test_load_objectives_valid(tmp_path, body):
    """A well-formed YAML objective set loads into Objective records keyed by id."""
    path = tmp_path / "objectives.yml"
    path.write_text(body, encoding="utf-8")
    catalog = load_objectives(path)
    first = next(iter(catalog.values()))
    assert all(k == v.id for k, v in catalog.items())
    assert first.tactic.startswith("TA")


@pytest.mark.parametrize(
    "body",
    [
        "{}\n",
        "- id: discovery\n  tactic: TA0007\n",
        "- id: Bad_Id\n  tactic: TA0007\n  goal: g\n",
        "- id: discovery\n  tactic: discovery\n  goal: g\n",
        "- id: dup\n  tactic: TA0001\n  goal: g\n- id: dup\n  tactic: TA0002\n  goal: g\n",
    ],
)
def test_load_objectives_invalid(tmp_path, body):
    """Malformed structure, bad id/tactic or a duplicate id is rejected."""
    path = tmp_path / "objectives.yml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ValueError):
        load_objectives(path)


@pytest.mark.parametrize(
    "kind, payload",
    [
        ("reply", "not json at all"),
        ("reply", '{"command": "", "intent": "x", "tactic": "t", "technique": "y", "done": false}'),
        ("reply", '{"intent": "x", "tactic": "t", "technique": "y", "done": false}'),
        ("target", ("8.8.8.8", 2222)),
        ("target", ("127.0.0.1", 22)),
    ],
)
def test_invalid_input_rejected(kind, payload):
    """Malformed agent replies raise AgentError and out-of-scope targets are refused."""
    if kind == "reply":
        with pytest.raises(AgentError):
            parse_step(payload)
    else:
        with pytest.raises(ContainmentError):
            check_target(*payload)
