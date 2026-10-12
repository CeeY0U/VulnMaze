"""End-to-end: attacker -> real Cowrie -> gateway -> stand-in model -> PostgreSQL.

Needs Cowrie and VULNMAZE_TEST_DSN. Runs in CI.
"""

from __future__ import annotations

import os
import threading
import time

import paramiko
import pytest
from _fake_llm import FakeLLM, Rule, ok
from _support import _read_until_prompt, free_port, run_cowrie, ssh_session
from conftest import PERSONA_PATH, TOKEN

pytestmark = [pytest.mark.cowrie, pytest.mark.db]

DUMP = "-- MariaDB dump 10.19  Distrib 10.11.6-MariaDB, for debian-linux-gnu (x86_64)\n--\n-- Host: localhost\n"
RULES = [
    Rule(r"^mysqldump", ok(files=[{"path": "/tmp/portal.sql", "content": DUMP}])),
    Rule(r"^mysql", lambda cmd, msgs: ok(stdout="stdin seen\n") if "Piped standard input" in msgs[1]["content"]
         else ok(stdout="", stderr="ERROR 1045 (28000): Access denied for user 'root'@'localhost'\n", exit_code=1)),
    Rule(r"^systemctl is-active", ok(stdout="active\n")),
    Rule(r"^journalctl", ok(stdout="-- No entries --\n"), delay=6),
]


@pytest.fixture(scope="module")
def stack():
    dsn = os.environ.get("VULNMAZE_TEST_DSN")
    if not dsn:
        pytest.skip("VULNMAZE_TEST_DSN not set")
    import psycopg
    import uvicorn
    from conftest import TEST_KEY

    from vulnmaze.db import apply_schema
    from vulnmaze.llm.gateway import app

    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS llm_calls, attacker_facts CASCADE")
        apply_schema(conn)

    fake = FakeLLM(rules=list(RULES)).start()
    env = {"VULNMAZE_DSN": dsn, "VULNMAZE_DEID_KEY": TEST_KEY.hex(), "VULNMAZE_GATEWAY_TOKEN": TOKEN,
           "VULNMAZE_LLM_URL": fake.url, "VULNMAZE_LLM_MODEL": "fake:1b", "VULNMAZE_PERSONA": str(PERSONA_PATH),
           "VULNMAZE_LLM_DEADLINE_S": "3", "VULNMAZE_LLM_PER_ATTACKER_PER_MIN": "1000", "VULNMAZE_LLM_BURST": "100"}
    saved = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)
    cowrie_env = {"VULNMAZE_ESCALATION": "all", "VULNMAZE_GATEWAY_URL": f"http://127.0.0.1:{port}",
                  "VULNMAZE_GATEWAY_TOKEN": TOKEN, "VULNMAZE_GATEWAY_TIMEOUT": "8"}
    try:
        with run_cowrie("vulnmaze", env=cowrie_env) as cowrie:
            yield {"cowrie": cowrie, "fake": fake, "dsn": dsn}
    finally:
        server.should_exit = True
        fake.stop()
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def llm_events(cowrie, since=0):
    return [e for e in cowrie.events()[since:] if e["eventid"] == "cowrie.vulnmaze.llm"]


def test_live_invented_file_survives_to_next_session(stack):
    c = stack["cowrie"]
    first = ssh_session(c.host, c.port, ["mysqldump --result-file=/tmp/portal.sql portal",
                                         "cat /tmp/portal.sql", "exit"], password="Portal#2026")
    assert first[1] == DUMP.rstrip("\n")
    # new interactive session: the very first command already sees the file
    assert ssh_session(c.host, c.port, ["cat /tmp/portal.sql", "exit"], password="Portal#2026")[0] == DUMP.rstrip("\n")
    # exec session (`ssh host cmd`), where the command runs at connect time
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(c.host, c.port, username="root", password="Portal#2026", look_for_keys=False, allow_agent=False)
    stdin, out, _ = client.exec_command("cat /tmp/portal.sql")
    stdin.channel.shutdown_write()        # EOF at once, as bots and `ssh host cmd < /dev/null` do
    assert out.read().decode() == DUMP
    client.close()


def test_live_same_command_same_output(stack):
    c, fake = stack["cowrie"], stack["fake"]
    before = len(fake.calls)
    a = ssh_session(c.host, c.port, ["systemctl is-active php8.2-fpm", "exit"])
    b = ssh_session(c.host, c.port, ["systemctl is-active php8.2-fpm", "exit"])
    assert a == b and a[0] == "active"
    assert len(fake.calls) == before + 1


def test_errors_go_to_stderr_with_exit_code(stack):
    c = stack["cowrie"]
    out = ssh_session(c.host, c.port, ["mysql -u root; echo rc=$?", "exit"])
    assert out[0].splitlines() == ["ERROR 1045 (28000): Access denied for user 'root'@'localhost'", "rc=1"]


def test_piped_stdin_reaches_the_model(stack):
    c = stack["cowrie"]
    assert ssh_session(c.host, c.port, ["echo 'SELECT 1;' | mysql portal", "exit"])[0] == "stdin seen"
    assert "Piped standard input (data):\nSELECT 1;" in stack["fake"].messages[-1][1]["content"]


def test_absent_command_is_not_found_without_model(stack):
    c, fake = stack["cowrie"], stack["fake"]
    before = len(fake.calls)
    assert ssh_session(c.host, c.port, ["docker ps", "exit"])[0] == "-bash: docker: command not found"
    assert len(fake.calls) == before


# ---- T0.6.9: privilege stages never reach the gateway, even with escalation=all -------------

PRIVILEGE_UNIMPLEMENTED = [
    "visudo", "vigr", "doas id", "insmod /tmp/rk.ko", "modprobe -r nf_tables", "chroot /mnt /bin/sh",
    "nsenter -t 1 -m -u -i -n sh", "unshare -r /bin/sh", "runuser -u www-data id", "newgrp docker",
    "setfacl -m u:bob:rwx /etc", "umount /mnt",
    # installed, escalatable programs pointed at privilege paths
    "lsof /etc/shadow", "journalctl --file /etc/shadow", "rsync /root/.ssh/id_rsa /tmp/",
    "mysql < /etc/shadow", "openssl enc -in /etc/sudoers -base64",
    # the routing gap reported by Magazov et al. [13]
    "echo ubuntu | sudo -S cat /etc/shadow",
]


def test_live_privilege_never_escalated(stack):
    c, fake = stack["cowrie"], stack["fake"]
    calls_before, events_before = len(fake.calls), len(c.events())
    ssh_session(c.host, c.port, PRIVILEGE_UNIMPLEMENTED + ["exit"])
    time.sleep(0.5)
    assert len(fake.calls) == calls_before, fake.calls[calls_before:]
    assert llm_events(c, events_before) == []
    routes = [e for e in c.events()[events_before:] if e["eventid"] == "cowrie.vulnmaze.route"]
    assert any(r["route"] == "privilege" for r in routes)


# ---- T0.6.5: logic traps Cowrie owns never reach the model --------------------------------

TRAPS = ["cd /nonexistent", "cd /nonexistent && ls", "ls --this-flag-does-not-exist", "cat /no/such/file",
         "rm /no/such/file", "ls /nonexistent", "cp /nope /tmp/", "mkdir /proc/x"]


def test_live_cowrie_owned_traps_do_not_call_model(stack):
    c, fake = stack["cowrie"], stack["fake"]
    before = len(fake.calls)
    out = ssh_session(c.host, c.port, TRAPS + ["exit"])
    assert len(fake.calls) == before
    assert "No such file or directory" in out[0]


# ---- T0.6.6: gateway or model unavailable -------------------------------------------------

def test_live_gateway_unreachable(stack):
    env = {"VULNMAZE_ESCALATION": "all", "VULNMAZE_GATEWAY_URL": f"http://127.0.0.1:{free_port()}",
           "VULNMAZE_GATEWAY_TOKEN": TOKEN, "VULNMAZE_GATEWAY_TIMEOUT": "2"}
    with run_cowrie("vulnmaze", env=env) as dead:
        t = time.time()
        out = ssh_session(dead.host, dead.port, ["systemctl status nginx", "whoami", "exit"])
        assert time.time() - t < 8
        assert out[0] == "-bash: fork: Resource temporarily unavailable"
        assert out[1] == "root"                                   # the session carries on
        time.sleep(0.5)
        assert [e["outcome"] for e in llm_events(dead)] == ["gateway_unreachable"]


def test_live_slow_model_falls_back_before_cowrie_timeout(stack):
    c = stack["cowrie"]
    t = time.time()
    out = ssh_session(c.host, c.port, ["journalctl -u nginx -n 5", "exit"])
    assert time.time() - t < 8                     # gateway deadline 3 s < Cowrie timeout 8 s
    assert out[0] == "-bash: fork: Resource temporarily unavailable"


def test_ctrl_c_cancels_a_waiting_command(stack):
    c = stack["cowrie"]
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(c.host, c.port, username="root", password="x1234", look_for_keys=False, allow_agent=False)
    chan = client.invoke_shell()
    _read_until_prompt(chan)
    chan.send(b"journalctl -f\n")
    time.sleep(0.5)
    chan.send(b"\x03")
    t = time.time()
    assert b"^C" in _read_until_prompt(chan, timeout=3)
    assert time.time() - t < 3
    chan.send(b"echo rc=$?\n")
    assert b"rc=130" in _read_until_prompt(chan)
    client.close()


# ---- T0.6.7: every call is timed, and the digest sees it ------------------------------------

def test_llm_events_timed_and_counted_in_digest(stack, deid):
    import psycopg

    from vulnmaze.ingest.pipeline import Ingestor
    from vulnmaze.ingest.tailer import FileTailer

    c = stack["cowrie"]
    ssh_session(c.host, c.port, ["hostnamectl", "lsblk", "docker ps", "exit"], password="digest-check")
    time.sleep(0.5)
    events = llm_events(c)
    assert events and all(isinstance(e["latency_ms"], int) for e in events)
    with psycopg.connect(str(stack["dsn"]), autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS events, session_digests, ingest_checkpoints, ingest_errors CASCADE")
        from vulnmaze.db import apply_schema
        apply_schema(conn)
        tailer, ing = FileTailer(str(c.json_log)), Ingestor(conn, deid)
        while lines := tailer.poll():
            with conn.transaction():
                ing.ingest_lines(lines)
        row = conn.execute("""SELECT digest->'llm' FROM session_digests
                               WHERE digest->'commands' @> '[{"input": "hostnamectl"}]'""").fetchone()
        assert row is not None, "the hostnamectl session produced no digest row"
        llm = row[0]
        assert llm["calls"] == 3 and llm["not_installed"] == 1 and llm["generated"] + llm["pinned"] == 2
        counted = conn.execute("SELECT count(*) FROM llm_calls WHERE latency_ms IS NOT NULL").fetchone()
        assert counted is not None and counted[0] >= 3


def test_escalation_off_keeps_phase_a_behaviour(cowrie_server):
    """The v0.5 server runs without VULNMAZE_ESCALATION: nothing changes."""
    out = ssh_session(cowrie_server.host, cowrie_server.port, ["systemctl status nginx", "exit"])
    assert out[0] == "-bash: systemctl: command not found"
    assert not [e for e in cowrie_server.events() if e["eventid"] == "cowrie.vulnmaze.llm"]
