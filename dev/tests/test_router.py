import pytest

from vulnmaze.router import Route, classify_argv, classify_line, is_sensitive_path, split_pipeline, strictest


@pytest.mark.parametrize("argv", [
    ["sudo", "-l"],
    ["usermod", "-aG", "sudo", "bob"],
    ["/usr/sbin/useradd", "eve"],
    ["cat", "/etc/shadow"],
    ["cat", "/root/.ssh/id_rsa"],
    ["cat", "~/.ssh/authorized_keys"],
    ["ls", "/etc/sha*"],
    ["env", "X=1", "nohup", "cat", "/etc/shadow"],
    ["timeout", "5s", "passwd"],
    ["python", "-c", "open('/etc/shadow').read()"],
    ["dd", "if=/dev/mem", "of=/tmp/x"],
    ["chmod", "4755", "/tmp/x"],
    ["chmod", "u+s", "/tmp/x"],
])
def test_privilege_floor(argv):
    """Privilege commands and sensitive paths are always PRIVILEGE, whatever wraps or hides them."""
    assert classify_argv(argv).route is Route.PRIVILEGE


@pytest.mark.parametrize("argv", [["ls", "-la"], ["cd", "/tmp"], ["chmod", "755", "x"],
                                  ["wget", "http://example.test/etc/shadow"], ["X=1"]])
def test_deterministic(argv):
    """Commands Cowrie implements, builtins and URLs that merely look like paths stay deterministic."""
    assert classify_argv(argv).route is Route.DETERMINISTIC


@pytest.mark.parametrize("argv", [["lsblk"], ["systemctl", "status", "nginx"], ["$CMD", "x"]])
def test_escalate_candidates(argv):
    """Unimplemented or dynamically named commands are the only ones offered to the LLM."""
    assert classify_argv(argv).route is Route.ESCALATE_CANDIDATE


def test_relative_path_resolves_against_cwd():
    """A bare relative argument is judged at its resolved location."""
    assert classify_argv(["cat", "shadow"], cwd="/etc").route is Route.PRIVILEGE
    assert classify_argv(["cat", "shadow"], cwd="/tmp").route is Route.DETERMINISTIC


def test_root_home_itself_is_not_sensitive():
    """Only credential directories under a home count, not the home directory."""
    assert not is_sensitive_path("/root/notes.txt")
    assert is_sensitive_path("/home/bob/.gnupg/pubring.kbx")


@pytest.mark.parametrize("line", [
    "echo $(cat /etc/shadow)",
    "echo `cat /etc/shadow`",
    "bash -c 'usermod -aG sudo bob'",
    "uname -a; cat /etc/sudoers",
    "ls | sudo tee /x",
])
def test_offline_lines_take_the_strictest_route(line):
    """Substitutions, inner shells and every pipeline stage are classified, and PRIVILEGE wins."""
    assert strictest(classify_line(line)) is Route.PRIVILEGE


def test_offline_line_without_privilege():
    """A benign line containing an unimplemented command is an escalate candidate overall."""
    assert strictest(classify_line("uname -a && lsblk")) is Route.ESCALATE_CANDIDATE
    assert strictest(classify_line("")) is Route.DETERMINISTIC


def test_split_pipeline():
    """Pipelines split on | and |& and drop empty stages."""
    assert split_pipeline(["cat", "x", "|", "grep", "y", "|&", "wc"]) == [["cat", "x"], ["grep", "y"], ["wc"]]
