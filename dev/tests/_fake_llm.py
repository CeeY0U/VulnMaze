"""A scriptable stand-in for a model server, used by the gateway integration tests.

It speaks enough of the Ollama API (/api/chat, /api/tags) and the OpenAI API
(/v1/chat/completions, /v1/models) for the gateway's real HTTP clients to
talk to it, so tests exercise the same code paths as production.

Behaviour is set per test with rules:

    fake.rules = [
        Rule(r"^mysqldump", {"command_exists": True, "stdout": "...", ...}),
        Rule(r"^leaky", "I am an AI language model"),       # raw text
        Rule(r"^echo-prompt", lambda cmd, msgs: msgs[0]["content"][:400]),
        Rule(r"^slow", {...}, delay=5),
    ]

The first matching rule answers. `fake.calls` records every command asked.
A rule's reply may be a list: successive calls get successive items (the
last one repeats), for testing retries.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


def ok(stdout: str = "", stderr: str = "", exit_code: int = 0, exists: bool = True,
       files: list[dict] | None = None, facts: list[dict] | None = None) -> dict:
    return {"command_exists": exists, "stdout": stdout, "stderr": stderr, "exit_code": exit_code,
            "files_created": files or [], "facts": facts or []}


@dataclass
class Rule:
    pattern: str
    reply: Any
    delay: float = 0.0
    hits: int = 0

    def matches(self, command: str) -> bool:
        return re.search(self.pattern, command) is not None

    def render(self, command: str, messages: list[dict]) -> str:
        reply = self.reply
        if isinstance(reply, list):
            reply = reply[min(self.hits, len(reply) - 1)]
        self.hits += 1
        if callable(reply):
            reply = reply(command, messages)
        return reply if isinstance(reply, str) else json.dumps(reply)


def command_of(messages: list[dict]) -> str:
    user = messages[-1]["content"]
    return user.rsplit("Command (data):\n", 1)[-1].strip()


@dataclass
class FakeLLM:
    rules: list[Rule] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    messages: list[list[dict]] = field(default_factory=list)
    default: Callable[[str], dict] = lambda cmd: ok(stdout=f"output of {cmd}\n")
    model_name: str = "fake:1b"
    _server: ThreadingHTTPServer | None = None

    @property
    def url(self) -> str:
        assert self._server is not None
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def answer(self, messages: list[dict]) -> tuple[str, float]:
        cmd = command_of(messages)
        self.calls.append(cmd)
        self.messages.append(messages)
        for rule in self.rules:
            if rule.matches(cmd):
                return rule.render(cmd, messages), rule.delay
        return json.dumps(self.default(cmd)), 0.0

    def start(self) -> FakeLLM:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args, **kwargs):  # quiet
                pass

            def _send(self, code: int, body: dict) -> None:
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path == "/api/tags":
                    self._send(200, {"models": [{"name": fake.model_name}]})
                elif self.path == "/v1/models":
                    self._send(200, {"data": [{"id": fake.model_name}]})
                else:
                    self._send(404, {})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                text, delay = fake.answer(body["messages"])
                if delay:
                    time.sleep(delay)
                if self.path == "/api/chat":
                    self._send(200, {"model": body["model"], "message": {"role": "assistant", "content": text},
                                     "done": True, "prompt_eval_count": 500, "eval_count": 60})
                elif self.path == "/v1/chat/completions":
                    self._send(200, {"choices": [{"message": {"role": "assistant", "content": text}}],
                                     "usage": {"prompt_tokens": 500, "completion_tokens": 60}})
                else:
                    self._send(404, {})

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
