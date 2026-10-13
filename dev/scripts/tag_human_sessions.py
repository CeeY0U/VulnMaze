import argparse
import json
from datetime import datetime

from vulnmaze.ingest.public import iter_events


def human_sessions(paths: list[str], since: datetime | None = None, until: datetime | None = None) -> list[str]:
    """Session ids of the sessions that connected within [since, until] in Cowrie JSON logs (plain or .gz)."""
    found: dict[str, None] = {}
    for path in paths:
        for line in iter_events(path):
            try:
                event = json.loads(line)
                ts = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue
            if event.get("eventid") != "cowrie.session.connect" or not event.get("session"):
                continue
            if (since and ts < since) or (until and ts > until):
                continue
            found[event["session"]] = None
    return list(found)


def main() -> None:
    ap = argparse.ArgumentParser(description="Write a vulnmaze-label --tiers file marking sessions as human.")
    ap.add_argument("paths", nargs="+", help="cowrie.json files from volunteers or this honeypot")
    ap.add_argument("--since", type=datetime.fromisoformat, help="ISO time with offset, e.g. 2026-10-14T10:00+08:00")
    ap.add_argument("--until", type=datetime.fromisoformat)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    sessions = human_sessions(args.paths, args.since, args.until)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.writelines(json.dumps({"session": s, "tier": "human"}) + "\n" for s in sessions)
    print(f"{len(sessions)} human sessions written to {args.out}")


if __name__ == "__main__":
    main()
