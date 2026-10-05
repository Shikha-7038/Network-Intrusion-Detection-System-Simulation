"""Feature engineering with validation. Handles missing values, zero duration, bad IPs/ports/protocols."""
import ipaddress

VALID_PROTOCOLS = {"TCP", "UDP", "ICMP"}
ML_FEATURES = ["packet_count", "byte_count", "duration", "bytes_per_second", "packets_per_second",
               "connection_count", "failed_connection_count", "syn_count", "rst_count", "average_packet_size"]


def _ip(v, name):
    try:
        return str(ipaddress.ip_address(str(v).strip()))
    except ValueError:
        raise ValueError(f"invalid {name}: {v!r}")


def _port(v, name):
    try:
        p = int(v)
    except (TypeError, ValueError):
        raise ValueError(f"invalid {name}: {v!r}")
    if not 0 <= p <= 65535:
        raise ValueError(f"invalid {name}: {v!r}")
    return p


def _num(v, default=0.0):
    """Missing/NaN/negative -> default (missing-value handling)."""
    try:
        x = float(v)
    except (TypeError, ValueError):
        return default
    return default if x != x or x < 0 else x


def extract_network_features(flow: dict) -> dict:
    """Validate a raw flow and return engineered features (+ cleaned identifiers)."""
    proto = str(flow.get("protocol", "")).strip().upper()
    if proto not in VALID_PROTOCOLS:
        raise ValueError(f"unsupported protocol: {flow.get('protocol')!r}")
    pk, by = _num(flow.get("packet_count")), _num(flow.get("byte_count"))
    dur = max(_num(flow.get("duration_seconds", flow.get("duration"))), 0.001)  # avoid /0
    conn, fail = _num(flow.get("connection_count")), _num(flow.get("failed_connection_count"))
    syn, rst = _num(flow.get("syn_count")), _num(flow.get("rst_count"))
    return {
        "source_ip": _ip(flow.get("source_ip"), "source_ip"), "destination_ip": _ip(flow.get("destination_ip"), "destination_ip"),
        "source_port": _port(flow.get("source_port"), "source_port"), "destination_port": _port(flow.get("destination_port"), "destination_port"),
        "protocol": proto, "packet_count": pk, "byte_count": by, "duration": dur,
        "bytes_per_second": by / dur,                       # volume pressure (exfiltration / flooding)
        "packets_per_second": pk / dur,                     # packet rate (floods, scans)
        "average_packet_size": by / pk if pk else 0.0,      # tiny packets = probes, big = bulk transfer
        "connection_count": conn, "failed_connection_count": fail,
        "failure_ratio": fail / conn if conn else 0.0,      # brute force / probing leave many failures
        "syn_count": syn, "rst_count": rst,
        "syn_ratio": syn / pk if pk else 0.0,               # SYN-dominated flows rarely complete handshakes
        "unique_destination_ports": _num(flow.get("unique_destination_ports"), 1.0),  # port diversity (scans)
        "unique_destination_ips": _num(flow.get("unique_destination_ips"), 1.0),
        "connection_rate": conn / dur,                      # new connections per second
    }
