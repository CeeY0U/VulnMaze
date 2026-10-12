"""Print the command names the installed Cowrie answers itself.

Paste the output into src/vulnmaze/router/known_commands.py after bumping the
pinned Cowrie version, then run the v0.5 tests.
"""

from __future__ import annotations

from importlib import resources

from cowrie._version import __version__ as cowrie_version
from cowrie.shell.protocol import HoneyPotBaseProtocol


def main() -> None:
    names = {k.rsplit("/", 1)[-1] for k in HoneyPotBaseProtocol.commands}
    txt = resources.files("cowrie.data").joinpath("txtcmds")
    stack = [txt]
    while stack:
        node = stack.pop()
        for child in node.iterdir():
            if child.is_dir():
                stack.append(child)
            else:
                names.add(child.name)
    names -= {":", ">", "[", "__init__.py"}
    print(f"# Cowrie {cowrie_version}: {len(names)} commands")
    print(" ".join(sorted(names)))


if __name__ == "__main__":
    main()
