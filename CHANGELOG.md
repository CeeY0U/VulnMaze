# Changelog

## Unreleased
- Long answers timed out (#5): the 8 s gateway deadline was shorter than a 768-token answer takes to generate, and Cowrie gave up at 10 s. New defaults: deadline 15 s (`VULNMAZE_LLM_DEADLINE_S`), answers capped at 400 tokens (`VULNMAZE_LLM_MAX_TOKENS`, now passed to the container), Cowrie timeout 17 s (`VULNMAZE_GATEWAY_TIMEOUT`, now settable in `infra/.env`). Keep the Cowrie timeout about 2 s above the deadline.
- Ollama context window pinned to 4096 tokens (`VULNMAZE_LLM_NUM_CTX`); Ollama's own default varies by version and GPU memory.
- Local model never loaded (#4): loading takes longer than the 8 s gateway deadline, and Ollama aborts a load when the request gives up. The gateway now loads the model in the background at start-up with no deadline (`VULNMAZE_LLM_WARMUP_TIMEOUT_S`, default 300 s) and answers with the fallback (reason `model_loading`) until it is loaded. After `VULNMAZE_LLM_WARMUP_ATTEMPTS` failed loads (default 5, about 75 s of backoff) it gives up, logs an error, answers with the fallback (reason `model_failed`) and `/healthz` returns 503, so Docker marks `llm-gateway` unhealthy; restart the gateway to retry. With `VULNMAZE_ESCALATION=off` the model is never loaded. After a model error, if the model is no longer loaded, it loads it again before calling it.
- The model stays loaded while Ollama runs (`OLLAMA_KEEP_ALIVE=-1`) instead of unloading after 30 idle minutes.
- `/healthz`: `model_ready` now means the model is loaded (Ollama `/api/ps`, exact name and tag), not only downloaded.
- Leak filter rejected real output starting with `OK` or `Okay` (#7), such as `redis-cli set k v`. `ok` and `okay` now count as a chatty preamble only when a comma or exclamation mark follows (`OK, here you go`); bare `OK` is accepted.
- Empty LLM answers were accepted and pinned (#19): `lsblk` answered with no output and exit code 0 was stored for that attacker for good. A successful answer with no output is now rejected (reason `empty_output`, retried once, then the fallback, never pinned) for invocations that always print something: `--version`/`--help`, and show-type invocations of lsblk, vmstat, iostat, lsb_release, journalctl, ss, hostnamectl, timedatectl, systemctl, ip and openssl. Quiet flags and mutating subcommands (`ip addr add`, `hostnamectl set-hostname`) are not affected.

## v0.6.1: Fixes from the first full-stack run
- Ingester never committed (`ingest/service.py`): the connection was not in autocommit mode, so the first SELECT opened a transaction that never closed and every batch became a savepoint inside it. Logs said "inserted", but no other connection saw the rows and a restart lost them. Now `autocommit=True`; same for the public loader.
- Health checks spammed Cowrie's log with tracebacks: HAProxy's backend `check` and the Docker healthcheck connected without a PROXY header. HAProxy no longer health-checks the single backend; the Cowrie healthcheck reads `/proc/net/tcp` instead of connecting.
- UTF8 guard: `apply_schema` refuses a non-UTF8 database with a clear message.

## v0.6: Hardened local LLM gap-filler
- `vulnmaze.llm`: gateway with route re-check, existence and output pinning, prompt builder, Ollama and OpenAI-compatible backends (json and raw modes), reasoning stripping, anchored leakage detector, output and file-path denylist, persona and stored-fact contradiction checks, one retry, deterministic fallbacks, per-attacker rate limit, global concurrency cap, `llm_calls` log.
- Cowrie: escalation switch (`VULNMAZE_ESCALATION`, off by default), async LLM command, unimplemented binaries in standard bin directories now count as "Cowrie can't answer", LLM-created files loaded at login with early input (including EOF) held until loaded, `cowrie.vulnmaze.llm` events.
- State store: global facts (`cmd-exists:*`), prefix escaping in `list`.
- Digest v2: `llm` counts and `commands[].llm`.
- Infra: `llm-gateway`, `ollama`, `ollama-pull` (profile `models`), networks `hpgw`, `llm`, `egress`; `docker-compose.gpu.yml`; `infra/persona/persona.yml`.

## v0.5: Deterministic router
- `vulnmaze.router`: classifies every command stage as privilege / deterministic / escalate candidate.
- `twistd vulnmaze` plugin wraps Cowrie's command execution and logs `cowrie.vulnmaze.route` events.
- Fixed handlers for usermod, userdel, groupadd, groupdel, gpasswd, chage, setcap, pkexec; `sudo -l` and `sudo -V` answered from persona files.

## v0.4: Per-attacker state store
- `attacker_facts` table, write-once (ON CONFLICT DO NOTHING + UPDATE trigger).
- `StateStore` library and FastAPI service on the backend network.

## v0.3: Session digest builder
- Pure incremental digest builder, persisted in `session_digests` in the same transaction as the events.

## v0.2: Cowrie baseline and telemetry ingestion
- Ingester tails `cowrie.json` (rotation-safe, checkpointed, idempotent).
- De-identification: keyed HMAC of IPs and passwords, /16 prefix, password scrubbing in commands.
- Public dataset loader.

## v0.1: Scaffold and isolated infrastructure
- Repository layout and CI.
- Compose stack with `edge` / `dmz` (internal) / `backend` (internal) networks; HAProxy with PROXY protocol.
