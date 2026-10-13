from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

from vulnmaze.db import dsn_from_env

C = r"(?:^|[;&|`(]|\$\()\s*(?:(?:sudo|busybox|/bin/busybox|nohup|exec|timeout\s+\d+)\s+)*"

RULES = [
    (name, tactic, severity, re.compile(pattern, re.I))
    for name, tactic, severity, pattern in [
        ("benign", "none", 0, C + r"(?:echo|printf|ls|cd|pwd|exit|logout|clear|true|export|sleep)\b"),
        (
            "recon_system",
            "Discovery",
            1,
            C
            + r"(?:uname|lscpu|nproc|uptime|hostname|hostnamectl|lsb_release|dmidecode|lspci|lsblk|free|df|top"
            r"|arch|getconf|mount|env|ssh\s+-V)\b|/proc/(?:cpuinfo|meminfo|version|mounts|uptime)|/etc/(?:os-release|issue|\S*-release)\b",
        ),
        (
            "recon_user",
            "Discovery",
            1,
            C
            + r"(?:whoami|id|w|who|last|lastlog|groups|users)(?=\s|$|[;&|)])|/etc/(?:passwd|group)\b|sudo\s+-l\b",
        ),
        (
            "recon_network",
            "Discovery",
            1,
            C + r"(?:ifconfig|ip\s+(?:a|addr|r|route|link)|netstat|ss|arp|route|iptables\s+-[LS])\b"
            r"|/etc/(?:hosts|resolv\.conf)\b|^/ip\s",
        ),
        (
            "recon_process",
            "Discovery",
            1,
            C + r"(?:ps|pgrep|lsof|crontab\s+-l|systemctl\s+(?:status|list-units)|service\s+--status-all)\b",
        ),
        ("recon_files", "Discovery", 1, C + r"(?:find|locate|which|type|command\s+-v)\b"),
        ("busybox_probe", "Discovery", 1, r"busybox\s+(?-i:[A-Z]{3,})\b"),
        (
            "cred_read",
            "Credential Access",
            3,
            r"/etc/g?shadow\b|\.ssh/id_\w+|\.bash_history|\.aws/credentials|\.docker/config\.json|wallet\.dat"
            r"|mimipenguin|\bgrep\b[^;|&]*\b(?:pass|pwd|secret|token)",
        ),
        (
            "account_change",
            "Persistence",
            4,
            C + r"(?:passwd|chpasswd|usermod|useradd|adduser|userdel|chage|gpasswd)\b",
        ),
        ("ssh_keys", "Persistence", 4, r"authorized_keys"),
        ("cron", "Persistence", 4, C + r"crontab(?!\s+-l\b)\b|/etc/cron|/var/spool/cron"),
        (
            "boot_persist",
            "Persistence",
            4,
            r"/etc/rc\.local|/etc/init\.d/|systemctl\s+enable|update-rc\.d|\.bashrc|\.profile\b|/etc/profile",
        ),
        (
            "download",
            "Command and Control",
            2,
            C + r"(?:wget|curl|tftp|ftpget|lwp-download|fetch|scp|sftp)\b|\b(?:https?|ftp|tftp)://",
        ),
        (
            "exec_fetched",
            "Execution",
            3,
            r"chmod\s+(?:-\w+\s+)*(?:[ugoa]*\+x|0?[0-7]*[1357][0-7]*\b)|(?:^|[;&|\s])\./\S+|\|\s*(?:ba|da|z)?sh\b|"
            + C
            + r"(?:ba|da)?sh\s+\S+|"
            + C
            + r"(?:perl|python[23]?|php|ruby|node)\s+-[ec]\b",
        ),
        (
            "priv_esc",
            "Privilege Escalation",
            4,
            C
            + r"(?:su|pkexec|doas)(?=\s|$)|chmod\s+(?:[ugoa]*\+s|[0-7]*[4-7][0-7]{3}\b)|/etc/sudoers|NOPASSWD",
        ),
        (
            "miner",
            "Impact",
            4,
            r"xmrig|minerd|cpuminer|stratum\+tcp|cryptonight|nicehash|kdevtmpfsi|kinsing|c3pool|nanopool|monero",
        ),
        ("kill", "Impact", 3, C + r"(?:pkill|killall|kill)\b"),
        (
            "cleanup_history",
            "Defense Evasion",
            3,
            r"history\s+-c|unset\s+HIST|HISTFILE=|HISTSIZE=0|\.bash_history|/var/log/|\bshred\b",
        ),
        (
            "impair_defenses",
            "Defense Evasion",
            3,
            C + r"(?:iptables\s+-[FX]|ufw\s+disable|setenforce\s+0|chattr|service\s+\S+\s+stop"
            r"|systemctl\s+(?:stop|disable))\b|/etc/ld\.so\.preload",
        ),
        ("remove_files", "Defense Evasion", 2, C + r"rm\s"),
        (
            "destroy",
            "Impact",
            4,
            C + r"(?:rm\s+(?:-\w+\s+)+/(?:\*|\s|$)|mkfs|dd\s+if=\S+\s+of=/dev/|shutdown|reboot|halt|poweroff)"
            r"|>\s*/dev/sd[a-z]\b|:\(\)\s*\{",
        ),
    ]
]
SCANNER_CLIENT = re.compile(r"^SSH-2\.0-(?:Go|libssh|ZGrab|Nmap|masscan|sshlib|JSCH|Ganymed)", re.I)


def label_command(line: str) -> tuple[str | None, int | None, list[str], bool]:
    """Label one command line with an ATT&CK tactic and an R0-R4 severity.

    Every rule in RULES is a labelling function that votes for one tactic and
    one severity or abstains. Severity follows the five-level risk scale of
    Touch et al.: R0 harmless (navigation, echo), R1 reconnaissance, R2
    staging (downloads, deleting files), R3 running fetched code, reading
    credentials, killing processes, evading defences, R4 persistence, account
    changes, privilege escalation, mining and destruction. The tactic is the
    one with most votes, where "none" only counts when nothing else fired;
    ties go to the rule with the higher severity, then the earlier rule in
    RULES. The severity is the highest one voted. Returns (None, None, [],
    False) when every rule abstains, and whether the voters disagreed.
    """
    fired = [(name, tactic, severity) for name, tactic, severity, rx in RULES if rx.search(line or "")]
    if not fired:
        return None, None, [], False
    voters = [f for f in fired if f[1] != "none"] or fired
    votes = Counter(tactic for _, tactic, _ in voters)
    top = max(votes.values())
    tactic = next(t for _, t, _ in sorted(voters, key=lambda f: -f[2]) if votes[t] == top)
    return tactic, max(f[2] for f in fired), [f[0] for f in fired], len(votes) > 1


def label_events(events, tiers: dict[str, str] | None = None) -> tuple[list[dict], list[dict], dict]:
    """Label command events and aggregate them per session.

    ``events`` are rows of the events table (source, session, eventid, ts,
    input, data) in session order. A session is multi-label: its tactics are
    the distinct tactics of its commands in the order first seen ("none" only
    if nothing else), its severity the highest of its commands. The attacker tier comes from
    ``tiers`` (session id to bot, llm_agent or human, written by the harness
    and for volunteer sessions), else "bot" for public data and scanner SSH
    clients, else None.
    """
    tiers = tiers or {}
    commands, sessions = [], {}
    stats = Counter()
    rules = Counter()
    for e in events:
        s = sessions.setdefault(
            (e["source"], e["session"]),
            {
                "source": e["source"],
                "session": e["session"],
                "client": None,
                "n": 0,
                "tactics": Counter(),
                "sev": [],
            },
        )
        if e["eventid"] == "cowrie.client.version":
            s["client"] = (e.get("data") or {}).get("version")
        if e["eventid"] != "cowrie.command.input" or not (e.get("input") or "").strip():
            continue
        tactic, severity, fired, conflict = label_command(e["input"])
        stats["commands"] += 1
        s["n"] += 1
        stats["labelled"] += tactic is not None
        stats["conflicts"] += conflict
        rules.update(fired)
        if tactic:
            s["tactics"][tactic] += 1
            s["sev"].append(severity)
        commands.append(
            {
                "source": e["source"],
                "session": e["session"],
                "ts": str(e["ts"]),
                "input": e["input"],
                "tactic": tactic,
                "severity": None if severity is None else f"R{severity}",
                "rules": fired,
                "conflict": conflict,
            }
        )
    out = []
    for s in sessions.values():
        tier = tiers.get(s["session"]) or (
            "bot" if s["source"].startswith("public:") or SCANNER_CLIENT.match(s["client"] or "") else None
        )
        out.append(
            {
                "source": s["source"],
                "session": s["session"],
                "tier": tier,
                "n_commands": s["n"],
                "tactics": [t for t in s["tactics"] if t != "none"] or list(s["tactics"]),
                "severity": f"R{max(s['sev'])}" if s["sev"] else None,
                "tactic_counts": dict(s["tactics"]),
            }
        )
    tier_of = {(s["source"], s["session"]): s["tier"] for s in out}
    for c in commands:
        c["tier"] = tier_of[(c["source"], c["session"])]
    n = stats["commands"]
    summary = {
        "commands": n,
        "labelled": stats["labelled"],
        "coverage": round(stats["labelled"] / n, 3) if n else 0.0,
        "conflicts": stats["conflicts"],
        "conflict_rate": round(stats["conflicts"] / n, 3) if n else 0.0,
        "sessions": len(out),
        "sessions_labelled": sum(1 for s in out if s["tactics"]),
        "tactics": dict(Counter(c["tactic"] for c in commands).most_common()),
        "session_tactics": dict(Counter(t for s in out for t in s["tactics"]).most_common()),
        "rules": dict(rules.most_common()),
        "tiers": dict(Counter(s["tier"] for s in out)),
    }
    return commands, out, summary


def main() -> None:
    ap = argparse.ArgumentParser(description="Weak-label commands and sessions with ATT&CK tactic and R0-R4.")
    ap.add_argument("--out", required=True, type=Path, help="directory for commands.jsonl and sessions.jsonl")
    ap.add_argument("--events", type=Path, help="JSONL export of events rows instead of the database")
    ap.add_argument("--source", default="%", help="SQL LIKE pattern on events.source, e.g. 'public:%%'")
    ap.add_argument("--tiers", type=Path, help="JSONL with session and tier, e.g. from the harness")
    args = ap.parse_args()
    tiers = {}
    if args.tiers:
        for line in args.tiers.read_text(encoding="utf-8").split("\n"):
            if line.strip():
                row = json.loads(line)
                tiers[row["session"]] = row["tier"]
    if args.events:
        lines = args.events.read_text(encoding="utf-8").split("\n")
        commands, sessions, summary = label_events([json.loads(x) for x in lines if x.strip()], tiers)
    else:
        with psycopg.connect(dsn_from_env(), row_factory=dict_row) as conn:
            rows = conn.execute(
                "SELECT source, session, eventid, ts, input, data FROM events "
                "WHERE eventid IN ('cowrie.command.input', 'cowrie.client.version') AND source LIKE %s "
                "ORDER BY source, session, ts, id",
                (args.source,),
            )
            commands, sessions, summary = label_events(rows, tiers)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, rows in (("commands", commands), ("sessions", sessions)):
        with (args.out / f"{name}.jsonl").open("w", encoding="utf-8") as fh:
            fh.writelines(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
