"""Bounded, authenticated HTTPS read soak. Does not log tokens or response contents.

Requires an API bearer token in a private file. Replace that file atomically with a
refreshed token during a long run. Authentication failures stop the entire test.
This measures incident-query reads only, not ingestion, recovery, or accuracy.
"""

import argparse
import json
import math
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests


def origin(value):
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise argparse.ArgumentTypeError("Use an HTTPS origin without credentials or a path")
    return value.rstrip("/")


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else None


def run(url, token_file, seconds, workers, rps):
    started = time.monotonic()
    deadline = started + seconds
    stop = threading.Event()
    slots = threading.Lock()
    next_slot = started

    def worker():
        nonlocal next_slot
        successes, all_latency, statuses = [], [], Counter()
        with requests.Session() as session:
            while not stop.is_set():
                with slots:
                    slot = next_slot
                    next_slot += 1 / rps
                if slot >= deadline:
                    break
                if stop.wait(max(0, slot - time.monotonic())):
                    break
                if time.monotonic() >= deadline:
                    break
                try:
                    token = token_file.read_text(encoding="utf-8").strip()
                    if not token or any(character.isspace() for character in token):
                        raise ValueError("Invalid token file")
                except (OSError, ValueError):
                    statuses["credential_file_error"] += 1
                    stop.set()
                    break
                request_start = time.monotonic()
                try:
                    response = session.get(url + "/api/incidents?limit=50",
                                           headers={"Authorization": "Bearer " + token},
                                           timeout=(5, 15), allow_redirects=False)
                    elapsed = (time.monotonic() - request_start) * 1000
                    all_latency.append(elapsed)
                    statuses[str(response.status_code)] += 1
                    if response.status_code == 200:
                        successes.append(elapsed)
                    if response.status_code in (401, 403) or 300 <= response.status_code < 400:
                        stop.set()
                    response.close()
                except requests.RequestException:
                    statuses["transport_error"] += 1
        return successes, all_latency, statuses

    success_latency, latency, statuses = [], [], Counter()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for successful, measured, counts in executor.map(lambda _: worker(), range(workers)):
            success_latency.extend(successful)
            latency.extend(measured)
            statuses.update(counts)
    elapsed = time.monotonic() - started
    return {
        "completed_at": datetime.now(timezone.utc).isoformat(), "origin": url,
        "workload": "authenticated incident reads only", "requested_seconds": seconds,
        "elapsed_seconds": round(elapsed, 3), "workers": workers, "target_rps": rps,
        "stopped_early": stop.is_set(), "status_counts": dict(statuses),
        "successful_reads": len(success_latency),
        "successful_rps": round(len(success_latency) / max(elapsed, 0.001), 3),
        "successful_latency_ms": {name: percentile(success_latency, q)
                                  for name, q in (("p50", .5), ("p95", .95), ("p99", .99))},
        "all_http_latency_ms": {name: percentile(latency, q)
                                for name, q in (("p50", .5), ("p95", .95), ("p99", .99))},
        "clean_run": bool(success_latency) and not stop.is_set()
                     and set(statuses) == {"200"},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", type=origin, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=300)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--rps", type=float, default=1)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not (10 <= args.seconds <= 7200 and 1 <= args.workers <= 16 and 0.1 <= args.rps <= 20):
        parser.error("Use 10–7200 seconds, 1–16 workers and 0.1–20 requests/second")
    if args.output.exists() or args.output.resolve() == args.token_file.resolve():
        parser.error("Choose a new report path separate from the token file")
    # Reserve the output before sending traffic; never overwrite a previous run.
    with args.output.open("x", encoding="utf-8") as stream:
        result = run(args.origin, args.token_file, args.seconds, args.workers, args.rps)
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(f"Saved read-soak evidence to {args.output}; clean_run={result['clean_run']}")
    raise SystemExit(0 if result["clean_run"] else 1)


if __name__ == "__main__":
    main()
