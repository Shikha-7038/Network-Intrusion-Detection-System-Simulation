"""Continuously emits synthetic flow RECORDS (JSON lines). It never sends network packets.
Optional --post sends records to the LOCAL IDS backend only (localhost/127.0.0.1 enforced)."""
import argparse, json, random, time, urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse
from simulator.generate_dataset import make_flow, random_scenario

SPEEDS = {"slow": 1.0, "fast": 0.1}  # seconds between flows


def stream(mode="mixed", speed="slow", seed=None, count=None):
    rng, n = random.Random(seed), 0
    ratio = 0.0 if mode == "normal" else 0.2
    while count is None or n < count:
        n += 1
        ts = datetime.now(timezone.utc).replace(tzinfo=None)
        flow = make_flow(random_scenario(rng, ratio), rng, ts, f"SIM-{int(time.time() * 1000)}-{n}")
        yield flow
        time.sleep(SPEEDS[speed])


def post_local(url, flow):
    if urlparse(url).hostname not in ("127.0.0.1", "localhost"):
        raise SystemExit("Safety check: --post only allows localhost targets.")
    req = urllib.request.Request(url, json.dumps(flow).encode(), {"Content-Type": "application/json"})
    return urllib.request.urlopen(req, timeout=5).status


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["normal", "mixed"], default="mixed")
    ap.add_argument("--speed", choices=list(SPEEDS), default="slow")
    ap.add_argument("--count", type=int); ap.add_argument("--post", help="e.g. http://127.0.0.1:5000/api/flows")
    a = ap.parse_args()
    for fl in stream(a.mode, a.speed, count=a.count):
        print(json.dumps(fl))
        if a.post:
            post_local(a.post, fl)
