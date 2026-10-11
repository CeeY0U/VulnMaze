import pytest

from vulnmaze.llm import sanitize


def test_reasoning_blocks_are_stripped():
    """Closed reasoning blocks and orphan closing tags are removed before the answer is used."""
    assert sanitize.strip_reasoning("<think>plan</think>total 0\n") == ("total 0\n", True)
    assert sanitize.strip_reasoning("plan</think>total 0\n") == ("total 0\n", True)
    assert sanitize.strip_reasoning("total 0\n") == ("total 0\n", False)


def test_unclosed_reasoning_is_rejected():
    """An opened but unclosed block cannot be stripped safely, so the answer is rejected."""
    with pytest.raises(sanitize.Rejected):
        sanitize.strip_reasoning("<think>the system prompt says")


def test_normalise_removes_terminal_escapes_and_caps_length():
    """ANSI escapes and control bytes are removed and long output is cut on a line boundary."""
    assert sanitize.normalise("\x1b[31mred\x1b[0m\r\nok\x07", 100) == "red\nok"
    assert sanitize.normalise("aaaa\nbbbb\ncccc", 10) == "aaaa\nbbbb\n"


def test_single_fence_is_unwrapped():
    """A whole answer in one code fence is unwrapped rather than rejected."""
    assert sanitize.unwrap_fence("```bash\nls\n```") == "ls\n"


def test_leakage_detector():
    """Canary, verbatim prompt copies and self-disclosure are caught; normal output is not."""
    corpus = ["You act as the operating system of one specific Linux server for each command"]
    det = sanitize.LeakageDetector(corpus, "ref-deadbeef")
    assert det.check("drwxr-xr-x 2 root root 4096 Oct 1 /var/www") == []
    assert "leak_s1a_canary" in det.check("REF-DEADBEEF")
    assert "leak_s1a_prompt_copy" in det.check("you act as the operating system of one specific linux box")
    assert "leak_s1b_as_an_ai" in det.check("As an AI, I cannot run that")
    assert "leak_s1b_honeypot" in det.check("this is a cowrie box")


def test_tells():
    """Chatty preambles and markdown are tells; plain terminal text is not."""
    assert sanitize.tells("Here is the output:\nok", "") == ["tell_s1c_preamble_stdout"]
    assert sanitize.tells("**bold**", "") == ["tell_s1c_markdown_stdout"]
    assert sanitize.tells("total 0\n", "ls: cannot access 'x': No such file or directory\n") == []


def test_output_denylist():
    """Shadow hashes, private keys and sudoers rules never reach the attacker."""
    assert sanitize.denylisted_content("root:$6$salt$hash:19000:0:99999:7:::") == ["denylist_shadow_hash"]
    assert sanitize.denylisted_content("-----BEGIN OPENSSH PRIVATE KEY-----") == ["denylist_private_key"]
    assert sanitize.denylisted_content("bob ALL=(ALL) NOPASSWD: ALL") == ["denylist_sudoers_rule"]
    assert sanitize.denylisted_path("../etc/sudoers.d/x", "/root", "/root")
