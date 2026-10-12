"""The write-once per-attacker state store."""

from __future__ import annotations

import threading
from typing import Any

import psycopg
import pytest

from vulnmaze.state.store import Fact, StateStore

pytestmark = pytest.mark.db

IP = "203.0.113.7"


def _value(store: StateStore, *key: str) -> Any:
    """The stored value of a fact this test just wrote; a missing fact is a failure."""
    fact = store.get(*key)
    assert fact is not None, f"no fact at {key}"
    return fact.value


def test_create_if_absent_never_overwrites(pg, deid):
    store = StateStore(pg, deid)
    first = store.create_if_absent(IP, "root", "file:/home/bob/notes.txt", {"content": "v1"}, "llm:test")
    second = store.create_if_absent(IP, "root", "file:/home/bob/notes.txt", {"content": "v2"}, "llm:test")
    assert first.created and not second.created
    assert second.value == {"content": "v1"}
    assert _value(store, IP, "root", "file:/home/bob/notes.txt") == {"content": "v1"}


def test_database_rejects_updates(pg, deid):
    """Write-once is enforced by a trigger, so a bug elsewhere cannot overwrite."""
    StateStore(pg, deid).create_if_absent(IP, "root", "hostname", "web-portal-01")
    with pytest.raises(psycopg.errors.RaiseException):
        pg.execute("UPDATE attacker_facts SET value = '\"other\"'")


def test_usernames_are_separate(pg, deid):
    store = StateStore(pg, deid)
    store.create_if_absent(IP, "root", "user:bob", {"uid": 1001})
    store.create_if_absent(IP, "admin", "user:bob", {"uid": 1002})
    assert _value(store, IP, "root", "user:bob") == {"uid": 1001}
    assert _value(store, IP, "admin", "user:bob") == {"uid": 1002}
    assert store.get("198.51.100.1", "root", "user:bob") is None


def test_raw_ip_is_not_stored(pg, deid):
    StateStore(pg, deid).create_if_absent(IP, "root", "hostname", "x")
    dump = pg.execute("SELECT string_agg(t::text, ' ') FROM attacker_facts t").fetchone()[0]
    assert IP not in dump


def test_list_by_prefix(pg, deid):
    store = StateStore(pg, deid)
    for f in ("file:/etc/motd", "file:/root/todo.txt", "user:bob"):
        store.create_if_absent(IP, "root", f, f)
    assert [f.fact for f in store.list(IP, "root", "file:")] == ["file:/etc/motd", "file:/root/todo.txt"]


def test_limits(pg, deid):
    store = StateStore(pg, deid)
    with pytest.raises(ValueError):
        store.create_if_absent(IP, "root", "", "x")
    with pytest.raises(ValueError):
        store.create_if_absent(IP, "root", "big", "x" * 300_000)


def test_survives_reconnect(pg, deid, dsn):
    """Persistence at the database level. The container-restart version of
    this test is in dev/tests/test_stack.py (needs docker compose)."""
    StateStore(pg, deid).create_if_absent(IP, "root", "hostname", "web-portal-01")
    with psycopg.connect(dsn, autocommit=True) as fresh:
        assert _value(StateStore(fresh, deid), IP, "root", "hostname") == "web-portal-01"


def test_concurrent_creators_one_winner(pg, deid, dsn):
    # 100 parallel callers as in the roadmap, over 20 connections: PostgreSQL's
    # default max_connections is 100, so one connection per caller would fail.
    n, n_conns = 100, 20
    results: list[Fact | None] = [None] * n
    barrier = threading.Barrier(n_conns, timeout=30)

    def worker(c):
        with psycopg.connect(dsn, autocommit=True) as conn:
            store = StateStore(conn, deid)
            barrier.wait()
            for i in range(c, n, n_conns):
                results[i] = store.create_if_absent(IP, "root", "cred:mysql", {"password": f"pw-{i}"})

    threads = [threading.Thread(target=worker, args=(c,)) for c in range(n_conns)]

    for t in threads:
        t.start()
    for t in threads:
        t.join()
    filled = [r for r in results if r is not None]
    assert len(filled) == n, "a worker exited without recording a result"
    winners = [r for r in filled if r.created]
    assert len(winners) == 1
    assert {r.value["password"] for r in filled} == {winners[0].value["password"]}
