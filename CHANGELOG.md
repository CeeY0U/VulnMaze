# Changelog

## Unreleased
- Long answers timed out (#5): the 8 s gateway deadline was shorter than a 768-token answer takes to generate, and Cowrie gave up at 10 s. New defaults: deadline 15 s (`VULNMAZE_LLM_DEADLINE_S`), answers capped at 400 tokens (`VULNMAZE_LLM_MAX_TOKENS`, now passed to the container), Cowrie timeout 17 s (`VULNMAZE_GATEWAY_TIMEOUT`, now settable in `infra/.env`). Keep the Cowrie timeout about 2 s above the deadline.
- Ollama context window pinned to 4096 tokens (`VULNMAZE_LLM_NUM_CTX`); Ollama's own default varies by version and GPU memory.
- Local model never loaded (#4): loading takes longer than the 8 s gateway deadline, and Ollama aborts a load when the request gives up. The gateway now loads the model in the background at start-up with no deadline (`VULNMAZE_LLM_WARMUP_TIMEOUT_S`, default 300 s) and answers with the fallback (reason `model_loading`) until it is loaded. After `VULNMAZE_LLM_WARMUP_ATTEMPTS` failed loads (default 5, about 75 s of backoff) it gives up, logs an error, answers with the fallback (reason `model_failed`) and `/healthz` returns 503, so Docker marks `llm-gateway` unhealthy; restart the gateway to retry. With `VULNMAZE_ESCALATION=off` the model is never loaded. After a model error, if the model is no longer loaded, it loads it again before calling it.
- The model stays loaded while Ollama runs (`OLLAMA_KEEP_ALIVE=-1`) instead of unloading after 30 idle minutes.
- `/healthz`: `model_ready` now means the model is loaded (Ollama `/api/ps`, exact name and tag), not only downloaded.
- Leak filter rejected real output starting with `OK` or `Okay` (#7), such as `redis-cli set k v`. `ok` and `okay` now count as a chatty preamble only when a comma or exclamation mark follows (`OK, here you go`); bare `OK` is accepted.
- Empty LLM answers were accepted and pinned (#19): `lsblk` answered with no output and exit code 0 was stored for that attacker for good. A successful answer with no output is now rejected (reason `empty_output`, retried once, then the fallback, never pinned) for invocations that always print something: `--version`/`--help`, and show-type invocations of lsblk, vmstat, iostat, lsb_release, journalctl, ss, hostnamectl, timedatectl, systemctl, ip and openssl. Quiet flags and mutating subcommands (`ip addr add`, `hostnamectl set-hostname`) are not affected.
- Retries now say what was wrong (#21): a rejected answer is regenerated with a one-line hint for its rejection group (JSON format, exit code, unclosed reasoning, created files, chatty output, empty output, command existence), in addition to the existing fixed values for contradictions. Leaks and denylisted content still get only the generic correction, so the model is never told what it leaked. Hints are part of the leak detector's corpus. Hints change how often retries succeed, so fidelity numbers from before and after this change are not comparable.
- Cowrie 3.0.14 rejected `head -1` and `tail -1` (#8), a common bot idiom and an easy fingerprint, as well as `--lines=N`, `-n -N` and options after file names, and returned exit code 0 on errors. Cowrie is upgraded to 3.1.2, whose `head`/`tail` accept the GNU option forms (upstream commit 2f9f923c) and which also fixes other shell fingerprints (exit codes 126/127, bash error prefixes, `sed`, `tr`). `KNOWN_COMMANDS` now lists `sed` and `tr`. Routing, the privilege handlers and LLM escalation were checked over SSH against the upgraded stack.
- Usernames were stored as typed (#10), so a password or personal name typed into the username field reached `events`, the session digests, `attacker_facts` and `llm_calls`. Usernames outside a list of common account names (`root`, `admin`, `ubuntu`, ...) are now replaced by `hmac:` plus a keyed HMAC before storage, like passwords; the same username always gets the same pseudonym. Rows stored before this change are not rewritten, and state stored under an uncommon username is no longer found for that attacker.
- Digest `timing.gaps_s` grew without a cap (#12), and the gap mean and standard deviation were recomputed over the whole list on every command (a 5,000-command session took 2.3 s to digest). The statistics are now kept with Welford's method over every gap, `gaps_s` keeps the first 2,000 gaps like `commands`, and the new `timing.n_gaps` counts all of them (the same session now takes 0.01 s). `DIGEST_VERSION` is 3; a stored version 2 digest is upgraded when its session gets its next gap.

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
