"""Synthetic flow generator. Produces DATA RECORDS only - no packets are ever sent.
All IPs come from RFC 5737 documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24)."""
import argparse, csv, os, random
from datetime import datetime, timedelta, timezone

CLIENTS = [f"192.0.2.{i}" for i in range(2, 60)]
SERVERS = [f"198.51.100.{i}" for i in range(2, 30)]
SUSPECT_SOURCES = [f"203.0.113.{i}" for i in (7, 15, 23, 42, 66, 99)]  # small pool -> meaningful "top sources"
NORMAL = ["NORMAL_WEB", "NORMAL_DNS", "NORMAL_SSH", "NORMAL_EMAIL", "NORMAL_DATABASE"]
SUSPICIOUS = ["HIGH_CONNECTION_RATE", "REPEATED_FAILED_CONNECTIONS", "MULTI_PORT_PROBING_PATTERN",
              "SYN_HEAVY_PATTERN", "UNUSUAL_PORT_ACTIVITY", "HIGH_TRAFFIC_VOLUME"]
COLUMNS = ["flow_id", "timestamp", "source_ip", "destination_ip", "source_port", "destination_port", "protocol",
           "packet_count", "byte_count", "duration_seconds", "connection_count", "failed_connection_count",
           "syn_count", "rst_count", "average_packet_size", "unique_destination_ports",
           "unique_destination_ips", "label", "scenario_type"]


def make_flow(scenario, rng, ts, fid):
    """Return one synthetic flow dict for a scenario name."""
    src, dst = rng.choice(CLIENTS), rng.choice(SERVERS)
    proto, dport, dur = "TCP", 443, rng.uniform(0.5, 6)
    pk, avg, conn, fail, syn, rst, uports, uips = rng.randint(8, 60), rng.uniform(350, 900), rng.randint(1, 4), 0, rng.randint(1, 3), 0, 1, 1
    label = "NORMAL"
    if scenario == "NORMAL_WEB":
        dport = rng.choice([80, 443, 443, 443])
    elif scenario == "NORMAL_DNS":
        proto, dport, pk, avg, dur, syn, conn = "UDP", 53, rng.randint(1, 4), rng.uniform(60, 120), rng.uniform(0.5, 3), 0, rng.randint(1, 3)
    elif scenario == "NORMAL_SSH":
        dport, dur, pk, avg, conn = 22, rng.uniform(20, 600), rng.randint(100, 900), rng.uniform(80, 200), 1
    elif scenario == "NORMAL_EMAIL":
        dport, pk = rng.choice([25, 587, 993]), rng.randint(10, 80)
    elif scenario == "NORMAL_DATABASE":
        dport, pk, avg = rng.choice([3306, 5432]), rng.randint(20, 200), rng.uniform(200, 600)
    else:
        label, src = "SUSPICIOUS", rng.choice(SUSPECT_SOURCES)
        if scenario == "HIGH_CONNECTION_RATE":
            conn, dur = rng.randint(80, 400), rng.uniform(1, 5)
            pk, avg, syn, fail = int(conn * rng.uniform(2, 4)), rng.uniform(60, 120), conn, rng.randint(0, 10)
        elif scenario == "REPEATED_FAILED_CONNECTIONS":
            conn, dport, dur = rng.randint(20, 80), rng.choice([22, 3389]), rng.uniform(5, 30)
            fail = int(conn * rng.uniform(0.6, 0.95)); rst, syn, pk, avg = fail, conn, conn * 3, rng.uniform(50, 90)
        elif scenario == "MULTI_PORT_PROBING_PATTERN":
            uports, dport, dur = rng.randint(25, 200), rng.choice([21, 22, 23, 80, 443, 3389, 8080]), rng.uniform(2, 20)
            conn = uports; fail = int(conn * rng.uniform(0.6, 0.9)); syn, rst, pk, avg = conn, fail, conn * 2, rng.uniform(40, 70)
        elif scenario == "SYN_HEAVY_PATTERN":
            syn, dur = rng.randint(150, 800), rng.uniform(1, 5)
            pk, avg, conn = syn + rng.randint(0, 20), rng.uniform(40, 64), rng.randint(20, 90)
            fail, rst = int(conn * rng.uniform(0.3, 0.6)), rng.randint(5, 40)
        elif scenario == "UNUSUAL_PORT_ACTIVITY":
            dport, dur, pk, avg = rng.choice([4444, 6667, 31337, 1337, 8888, 9001]), rng.uniform(30, 300), rng.randint(60, 600), rng.uniform(100, 400)
        elif scenario == "HIGH_TRAFFIC_VOLUME":
            dur, pk, avg = rng.uniform(5, 60), rng.randint(60000, 400000), rng.uniform(900, 1400)
            conn, syn = rng.randint(1, 5), rng.randint(1, 5)
        else:
            raise ValueError(f"unknown scenario {scenario}")
    if label == "NORMAL" and rng.random() < 0.03:  # occasional harmless failure
        fail, rst = 1, 1
    return {"flow_id": fid, "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S"), "source_ip": src, "destination_ip": dst,
            "source_port": rng.randint(49152, 65535), "destination_port": dport, "protocol": proto,
            "packet_count": pk, "byte_count": int(pk * avg), "duration_seconds": round(dur, 3),
            "connection_count": conn, "failed_connection_count": fail, "syn_count": syn, "rst_count": rst,
            "average_packet_size": round(avg, 1), "unique_destination_ports": uports, "unique_destination_ips": uips,
            "label": label, "scenario_type": scenario}


def random_scenario(rng, suspicious_ratio):
    return rng.choice(SUSPICIOUS) if rng.random() < suspicious_ratio else rng.choices(NORMAL, [50, 20, 8, 12, 10])[0]


def generate(n=6000, suspicious_ratio=0.2, seed=42, hours=24):
    rng = random.Random(seed)
    start = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)
    step = timedelta(hours=hours) / n
    return [make_flow(random_scenario(rng, suspicious_ratio), rng, start + step * i, f"FLW-{i + 1:07d}") for i in range(n)]


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Generate data/network_traffic.csv (synthetic, safe)")
    ap.add_argument("--rows", type=int, default=6000); ap.add_argument("--out", default="data/network_traffic.csv")
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    rows = generate(a.rows)
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS); w.writeheader(); w.writerows(rows)
    print(f"Wrote {len(rows)} synthetic flows -> {a.out}")
