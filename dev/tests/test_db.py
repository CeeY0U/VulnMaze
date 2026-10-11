import json
import os
import uuid

import pytest

psycopg = pytest.importorskip("psycopg")

from vulnmaze.db import apply_schema  # noqa: E402
from vulnmaze.ingest.pipeline import Ingestor  # noqa: E402
from vulnmaze.state.store import StateStore  # noqa: E402

DSN = os.environ.get("VULNMAZE_TEST_DSN")
pytestmark = [pytest.mark.db, pytest.mark.skipif(not DSN, reason="set VULNMAZE_TEST_DSN to run database tests")]


@pytest.fixture
def conn():
    """An autocommit connection to a database with the schema applied."""
    with psycopg.connect(DSN, autocommit=True) as c:
        apply_schema(c)
        yield c


def test_facts_are_write_once(conn, deid):
    """The first value wins, later writes return it, and a direct UPDATE is rejected by the trigger."""
    store = StateStore(conn, deid)
    ip, fact = "198.51.100.9", f"user:{uuid.uuid4().hex}"
    first = store.create_if_absent(ip, "root", fact, {"v": 1}, "test")
    second = store.create_if_absent(ip, "root", fact, {"v": 2}, "test")
    assert first.created and not second.created and second.value == {"v": 1}
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("UPDATE attacker_facts SET value = '{}' WHERE fact = %s", (fact,))
    stored_keys = [r[0] for r in conn.execute("SELECT attacker_key FROM attacker_facts WHERE fact = %s", (fact,))]
    assert stored_keys == [deid.ip(ip)]


def test_like_prefix_is_escaped(conn, deid):
    """Listing by prefix treats % and _ literally."""
    store = StateStore(conn, deid)
    ip = f"203.0.113.{uuid.uuid4().int % 250}"
    store.create_if_absent(ip, "root", "file:/a_b", {"content": ""})
    store.create_if_absent(ip, "root", "file:/axb", {"content": ""})
    assert [f.fact for f in store.list(ip, "root", "file:/a_")] == ["file:/a_b"]


def test_ingested_events_are_visible_to_other_connections(conn, deid):
    """Ingested batches commit, so a second connection sees the events and digest (the v0.6.1 regression)."""
    source, session = f"test:{uuid.uuid4().hex[:8]}", "s1"
    lines = [json.dumps(e) for e in (
        {"eventid": "cowrie.login.success", "session": session, "timestamp": "2026-10-01T00:00:00Z",
         "src_ip": "198.51.100.9", "username": "root", "password": "hunter22"},
        {"eventid": "cowrie.command.input", "session": session, "timestamp": "2026-10-01T00:00:03Z",
         "input": "uname -a"},
    )]
    ingestor = Ingestor(conn, deid, source=source)
    with conn.transaction():
        assert ingestor.ingest_lines(lines + ["not json"]) == 2
    with conn.transaction():
        assert ingestor.ingest_lines(lines) == 0
    with psycopg.connect(DSN) as other:
        n = other.execute("SELECT count(*) FROM events WHERE source = %s", (source,)).fetchone()[0]
        digest = other.execute("SELECT digest FROM session_digests WHERE source = %s", (source,)).fetchone()[0]
        raw = other.execute("SELECT count(*) FROM events WHERE source = %s AND data::text LIKE '%%hunter22%%'",
                            (source,)).fetchone()[0]
    assert n == 2 and raw == 0 and digest["counts"]["commands"] == 1
    assert ingestor.stats == {"inserted": 2, "duplicates": 2, "errors": 1}
