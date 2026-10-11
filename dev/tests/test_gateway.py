import asyncio
import json

import pytest

from vulnmaze.llm import sanitize
from vulnmaze.llm.backends import ModelError, ModelReply
from vulnmaze.llm.gateway import Context, Gateway, GatewayConfig, parse_reply
from vulnmaze.llm.schema import CreatedFile, EscalationRequest


class FakeDb:
    """In-memory stand-in for the gateway's database layer."""

    def __init__(self, deid, pinned_output=None, exists_global=None):
        """Start with optional pinned output and global existence pin."""
        self.deid = deid
        self.pinned_output = pinned_output
        self.exists = {"global": exists_global}
        self.pins = []
        self.commits = []
        self.logged = []

    def load(self, req, name, out_key):
        """Return the stored context for this request."""
        return Context(self.pinned_output, self.exists["global"], None, {})

    def file_contents(self, req, paths):
        """Return no stored files."""
        return [CreatedFile(path=p, content="") for p in paths]

    def pin_exists(self, req, name, value, created_by, attacker_only=False):
        """Record an existence pin and return the stored value."""
        self.pins.append((name, value, attacker_only))
        return value

    def facts_contradictions(self, req, declared):
        """Report no stored-fact contradictions."""
        return []

    def commit(self, req, out_key, c, created_by):
        """Record an accepted answer and return it as stored."""
        self.commits.append(c)
        return {"stdout": c.stdout, "stderr": c.stderr, "exit_code": c.exit_code, "files": [p for p, _ in c.files]}

    def log_call(self, row):
        """Record an llm_calls row."""
        self.logged.append(row)


class FakeBackend:
    """A model that replays scripted replies or raises."""

    name = "fake:model"
    mode = "json"

    def __init__(self, *replies):
        """Queue the replies to return, one per call."""
        self.replies = list(replies)
        self.calls = 0

    async def generate(self, messages, schema, timeout):
        """Return the next scripted reply."""
        self.calls += 1
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return ModelReply(text=reply if isinstance(reply, str) else json.dumps(reply), model_ms=5)


def answer(stdout="", stderr="", exit_code=0, exists=True):
    """A well-formed model answer in json mode."""
    return {"command_exists": exists, "stdout": stdout, "stderr": stderr, "exit_code": exit_code}


def run(persona, deid, argv, backend, **db_kwargs):
    """Escalate one command through a gateway built on fakes."""
    db = FakeDb(deid, **db_kwargs)
    gw = Gateway(GatewayConfig(token="t" * 16, canary="ref-canary"), db, backend, persona)
    req = EscalationRequest(session="s1", src_ip="198.51.100.9", username="root", argv=argv)
    return asyncio.run(gw.escalate(req)), db


def test_route_recheck_refuses_privilege_commands(persona, deid):
    """A privilege command that reaches the gateway is refused without calling the model."""
    backend = FakeBackend()
    result, db = run(persona, deid, ["cat", "/etc/shadow"], backend)
    assert result.outcome == "refused" and result.exit_code == 127 and backend.calls == 0
    assert db.logged[0]["outcome"] == "refused"


def test_persona_absent_commands_are_not_found(persona, deid):
    """Commands the persona lists as absent get bash's error with no model call."""
    backend = FakeBackend()
    result, _ = run(persona, deid, ["nmap", "-sS", "10.0.0.0/8"], backend)
    assert result.outcome == "not_installed" and "nmap: command not found" in result.stderr
    assert backend.calls == 0


def test_pinned_output_is_served_again(persona, deid):
    """An attacker repeating a command gets the stored answer, not a new generation."""
    backend = FakeBackend()
    pinned = {"stdout": "NAME MAJ:MIN\n", "stderr": "", "exit_code": 0, "files": []}
    result, _ = run(persona, deid, ["lsblk"], backend, pinned_output=pinned)
    assert result.outcome == "pinned" and result.stdout == "NAME MAJ:MIN\n" and backend.calls == 0


def test_valid_answer_is_generated_and_committed(persona, deid):
    """A clean answer for an installed command is returned and pinned."""
    backend = FakeBackend(answer("NAME MAJ:MIN RM SIZE RO TYPE MOUNTPOINTS\nvda  254:0 0 40G 0 disk\n"))
    result, db = run(persona, deid, ["lsblk"], backend)
    assert result.outcome == "generated" and result.stdout.startswith("NAME")
    assert len(db.commits) == 1 and db.pins == []
    assert db.logged[0]["model"] == "fake:model" and db.logged[0]["attempts"] == 1


def test_leaky_answers_fall_back_after_one_retry(persona, deid):
    """Two leaking answers end in a transient error for an installed command, never the leak."""
    backend = FakeBackend(answer("As an AI language model I cannot run lsblk"), answer("I am an AI"))
    result, db = run(persona, deid, ["lsblk"], backend)
    assert result.outcome == "fallback" and "AI" not in result.stdout + result.stderr
    assert "fork: Resource temporarily unavailable" in result.stderr and backend.calls == 2
    assert db.commits == [] and db.logged[0]["rejected_output"]


def test_persona_contradiction_is_retried(persona, deid):
    """A contradicting first answer is regenerated, and a consistent second answer is accepted."""
    backend = FakeBackend(answer("Static hostname: mailhost\n"), answer(f"Static hostname: {persona.hostname}\n"))
    result, _ = run(persona, deid, ["hostnamectl"], backend)
    assert result.outcome == "generated" and persona.hostname in result.stdout and backend.calls == 2


def test_unknown_command_reported_missing_is_pinned_globally(persona, deid):
    """When the model says an unknown program is not installed, that is pinned for every attacker."""
    backend = FakeBackend(answer(stderr="-bash: foo: command not found\n", exit_code=127, exists=False))
    result, db = run(persona, deid, ["foo"], backend)
    assert result.outcome == "not_installed" and db.pins == [("foo", False, False)]


def test_model_outage_pins_absence_for_this_attacker_only(persona, deid):
    """A model error on an unknown program never decides its existence for everyone."""
    result, db = run(persona, deid, ["foo"], FakeBackend(ModelError("down")))
    assert result.outcome == "fallback" and result.exit_code == 127
    assert db.pins == [("foo", False, True)]


def test_attacker_ip_is_redacted_from_the_call_log(persona, deid):
    """The llm_calls row never holds the raw source IP."""
    _, db = run(persona, deid, ["ping6", "198.51.100.9"], FakeBackend(ModelError("down")))
    row = db.logged[0]
    assert "198.51.100.9" not in json.dumps(row) and row["attacker_key"] == deid.ip("198.51.100.9")


def test_parse_reply_modes():
    """JSON answers are parsed and validated, and raw answers infer the exit code from the text."""
    cand, stripped = parse_reply("<think>x</think>" + json.dumps(answer("hi\n")), "json")
    assert cand.stdout == "hi\n" and stripped
    raw, _ = parse_reply("ls: invalid option -- 'z'\n", "raw")
    assert raw.exit_code == 2 and raw.stderr and not raw.stdout
    with pytest.raises(sanitize.Rejected):
        parse_reply("not json", "json")
    with pytest.raises(sanitize.Rejected):
        parse_reply(json.dumps(answer(exit_code=300)), "json")
