import gzip
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]


def _connect(session, ts):
    """A Cowrie session.connect line."""
    return json.dumps({"eventid": "cowrie.session.connect", "session": session, "timestamp": ts})


def _tag(tmp_path, lines, *extra):
    """Run the script on a gzipped log and return the sessions it tagged."""
    log = tmp_path / "cowrie.json.gz"
    with gzip.open(log, "wt", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    out = tmp_path / "tiers.jsonl"
    script = ROOT / "dev/scripts/tag_human_sessions.py"
    subprocess.run([sys.executable, str(script), str(log), "--out", str(out), *extra], check=True)
    return [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]


@pytest.mark.parametrize(
    "extra, expected",
    [
        ((), ["a1", "b2"]),
        (("--since", "2026-10-14T10:30:00+00:00"), ["b2"]),
        (("--until", "2026-10-14T10:30:00+00:00"), ["a1"]),
    ],
)
def test_sessions_in_the_window_are_tagged_human(tmp_path, extra, expected):
    """Every session that connected in the window is written once, as human."""
    lines = [_connect("a1", "2026-10-14T10:00:00.000000Z"), _connect("b2", "2026-10-14T11:00:00Z"), _connect("a1", "2026-10-14T10:00:01Z")]
    assert _tag(tmp_path, lines, *extra) == [{"session": s, "tier": "human"} for s in expected]


@pytest.mark.parametrize(
    "line",
    [
        "not json",
        json.dumps({"eventid": "cowrie.command.input", "session": "c3", "timestamp": "2026-10-14T10:00:00Z"}),
        json.dumps({"eventid": "cowrie.session.connect", "timestamp": "2026-10-14T10:00:00Z"}),
        json.dumps({"eventid": "cowrie.session.connect", "session": "d4", "timestamp": "yesterday"}),
    ],
)
def test_other_lines_are_ignored(tmp_path, line):
    """Malformed lines, non-connect events and events without a session or time tag nothing."""
    assert _tag(tmp_path, [line]) == []
