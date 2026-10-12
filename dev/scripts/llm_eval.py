"""Run the v0.6 golden command set against a real model (T0.6.5, T0.6.7, T0.6.8).

Uses the same Gateway class as production, with your development database,
and a fresh made-up attacker address per run so earlier pins don't hide the
model's behaviour.

    export VULNMAZE_DSN=postgresql://...  VULNMAZE_DEID_KEY=<hex>
    export VULNMAZE_LLM_URL=http://localhost:11434 VULNMAZE_LLM_MODEL=llama3.1:8b
    python scripts/llm_eval.py run   --out eval/results/
    # two people fill in rater_1 / rater_2 (1 = realistic, 0 = not) in the CSV
    python scripts/llm_eval.py score eval/results/<file>.csv
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


async def run(args) -> Path:
    from psycopg_pool import ConnectionPool

    from vulnmaze.common.deid import Deidentifier
    from vulnmaze.db import apply_schema, dsn_from_env
    from vulnmaze.llm import evaluation
    from vulnmaze.llm.backends import backend_from_env
    from vulnmaze.llm.gateway import CORRECTION, Db, Gateway, GatewayConfig
    from vulnmaze.llm.persona import Persona
    from vulnmaze.llm.sanitize import LeakageDetector
    from vulnmaze.llm.schema import EscalationRequest

    golden = evaluation.load_golden(args.golden)
    pool = ConnectionPool(dsn_from_env(), open=True, min_size=1, max_size=4, kwargs={"autocommit": True})
    with pool.connection() as conn:
        apply_schema(conn)
    backend = backend_from_env()
    persona = Persona.from_env()
    cfg = GatewayConfig(token="x" * 16, deadline_s=args.deadline, per_attacker_per_min=10_000, burst=10_000,
                        concurrency=1)
    gw = Gateway(cfg, Db(pool, Deidentifier.from_env()), backend, persona)
    detector = LeakageDetector(gw.prompts.leakage_corpus() + [CORRECTION], cfg.canary)
    # TEST-NET-3 address, new each run, so this run starts with no pins
    ip = f"203.0.113.{random.randint(1, 254)}"
    session = f"eval-{int(time.time())}"
    if not await backend.healthy():
        sys.exit(f"model {backend.name} not reachable or not pulled at {os.environ.get('VULNMAZE_LLM_URL')}")

    rows = []
    for i, g in enumerate(golden, 1):
        req = EscalationRequest(session=session, src_ip=ip, username="root", cwd="/root",
                                argv=g.argv, stdin=g.stdin)
        r = await gw.escalate(req)
        leak = evaluation.visible_leak(detector, r.stdout, r.stderr)
        rows.append({
            "id": g.id, "category": g.category, "command": json.dumps(g.argv), "outcome": r.outcome,
            "exit_code": r.exit_code, "stdout": r.stdout, "stderr": r.stderr, "latency_ms": r.latency_ms,
            "reasons": "|".join(r.reasons),
            "trap_violation": evaluation.trap_violation(g.category, r.outcome, r.exit_code),
            "visible_leak": "|".join(leak), "rater_1": "", "rater_2": "",
        })
        print(f"[{i:3}/{len(golden)}] {g.id:6} {r.outcome:13} {r.latency_ms:6} ms  {' '.join(g.argv)[:60]}")
    pool.close()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    name = f"{time.strftime('%Y%m%d-%H%M%S')}-{backend.name.replace(':', '_').replace('/', '_')}.csv"
    path = out_dir / name
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=evaluation.CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)
    summary = evaluation.summarise(rows)
    summary["model"] = backend.name
    (path.with_suffix(".summary.json")).write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    print(f"\nwrote {path}")
    return path


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--golden", default=str(ROOT / "eval/golden_commands.yml"))
    r.add_argument("--out", default=str(ROOT / "eval/results"))
    r.add_argument("--deadline", type=float, default=float(os.environ.get("VULNMAZE_LLM_DEADLINE_S", "8")))
    s = sub.add_parser("score")
    s.add_argument("csv")
    args = ap.parse_args()
    if args.cmd == "run":
        asyncio.run(run(args))
    else:
        from vulnmaze.llm.evaluation import score

        print(json.dumps(score(args.csv), indent=2))


if __name__ == "__main__":
    main()
