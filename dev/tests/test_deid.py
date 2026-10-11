import pytest

from vulnmaze.common.deid import REDACTED, SRC_IP_TOKEN, Deidentifier, DeidKeyMissing


def test_ip_pseudonym_is_stable_keyed_and_not_raw(deid):
    """The same IP maps to the same pseudonym, a different key maps it elsewhere, and the raw IP never appears."""
    other = Deidentifier(bytes.fromhex("22" * 32))
    assert deid.ip("203.0.113.7") == deid.ip("203.0.113.7")
    assert deid.ip("203.0.113.7") != other.ip("203.0.113.7")
    assert "203.0.113.7" not in deid.ip("203.0.113.7")


def test_ip_and_password_domains_are_separated(deid):
    """An IP and a password with the same text get different pseudonyms."""
    assert deid.ip("1.2.3.4") != deid.secret("1.2.3.4")


def test_prefix_is_coarse():
    """IPv4 collapses to /16, IPv6 to /32, and junk to None."""
    assert Deidentifier.prefix("203.0.113.7") == "203.0.0.0/16"
    assert Deidentifier.prefix("2001:db8::1") == "2001:db8::/32"
    assert Deidentifier.prefix("not-an-ip") is None


def test_redact_text_replaces_longest_secret_first_and_ignores_short_ones():
    """Passwords are replaced longest first, very short ones are kept, and the source IP is tokenised."""
    out = Deidentifier.redact_text("echo admin123 admin ab 10.0.0.5 110.0.0.55", ["admin", "admin123", "ab"], "10.0.0.5")
    assert out == f"echo {REDACTED} {REDACTED} ab {SRC_IP_TOKEN} 110.0.0.55"


def test_key_must_be_present_and_long(monkeypatch):
    """A missing, non-hex or short key fails closed."""
    monkeypatch.delenv("VULNMAZE_DEID_KEY", raising=False)
    with pytest.raises(DeidKeyMissing):
        Deidentifier.from_env()
    monkeypatch.setenv("VULNMAZE_DEID_KEY", "zz")
    with pytest.raises(DeidKeyMissing):
        Deidentifier.from_env()
    with pytest.raises(DeidKeyMissing):
        Deidentifier(b"short")
