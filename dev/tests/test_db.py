import gzip
import json
import os
import uuid

import pytest

psycopg = pytest.importorskip("psycopg")

from vulnmaze.db import apply_schema  # noqa: E402
from vulnmaze.ingest.pipeline import Ingestor  # noqa: E402
from vulnmaze.ingest.public import load as load_public  # noqa: E402
from vulnmaze.state.store import StateStore  # noqa: E402

DSN = os.environ.get("VULNMAZE_TEST_DSN")
pytestmark = [pytest.mark.db, pytest.mark.skipif(not DSN, reason="set VULNMAZE_TEST_DSN to run database tests")]

# Values that appear raw in the recorded fixture and must never reach the database.
RAW_SECRETS = ["203.0.113.7", "192.0.2.10", "S3cretPass!"]


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


def _ingest_fixture(conn, deid, fixtures, source, name="cowrie_session_basic.jsonl"):
    """Store one recorded fixture under a private source and return the ingestor."""
    ingestor = Ingestor(conn, deid, source=source)
    with conn.transaction():
        ingestor.ingest_lines((fixtures / name).read_text().splitlines())
    return ingestor


def test_recorded_session_is_stored_in_event_order(conn, deid, fixtures):
    """Reading a session back ordered by (ts, id) replays it the way the attacker typed it."""
    source = f"test:{uuid.uuid4().hex[:8]}"
    assert _ingest_fixture(conn, deid, fixtures, source).stats["inserted"] == 41
    lines = (fixtures / "cowrie_session_basic.jsonl").read_text().splitlines()
    session = next(json.loads(x)["session"] for x in lines if json.loads(x)["eventid"] == "cowrie.command.input")
    rows = conn.execute(
        "SELECT eventid, input FROM events WHERE source = %s AND session = %s ORDER BY ts, id",
        (source, session),
    ).fetchall()
    assert [r[0] for r in rows][0] == "cowrie.session.connect"
    assert [r[0] for r in rows][-1] == "cowrie.session.closed"
    assert [r[1] for r in rows if r[0] == "cowrie.command.input"][:3] == [
        "uname -a", "whoami", "cat /etc/passwd | head -3"]


def test_no_raw_identifier_survives_in_any_stored_column(conn, deid, fixtures):
    """The whole row, not just one field: no raw IP, sensor address or password in events or digests."""
    source = f"test:{uuid.uuid4().hex[:8]}"
    _ingest_fixture(conn, deid, fixtures, source)
    for table in ("events", "session_digests"):
        dump = conn.execute(f"SELECT string_agg(t::text, ' ') FROM {table} t WHERE source = %s", (source,)).fetchone()[0]
        for secret in RAW_SECRETS:
            assert secret not in dump, f"{secret!r} leaked into {table}"


def test_public_dataset_loader_tags_source_and_records_errors(conn, deid, fixtures, tmp_path):
    """A gzipped public dump goes through the same pipeline, is tagged with its source, and one digest per session."""
    src = tmp_path / "2019-05-13.json.gz"
    with gzip.open(src, "wt") as fh:
        fh.write((fixtures / "cowrie_scanner_banner.jsonl").read_text())
        fh.write("this line is broken\n")
    stats = load_public(conn, "fixture", [str(src)], deid)
    assert stats["inserted"] == 3 and stats["errors"] == 1
    sessions = [r[0] for r in conn.execute(
        "SELECT DISTINCT session FROM events WHERE source = %s", ("public:fixture",)).fetchall()]
    assert len(sessions) == 1
    assert conn.execute("SELECT count(*) FROM session_digests WHERE source = %s AND session = %s",
                        ("public:fixture", sessions[0])).fetchone()[0] == 1
