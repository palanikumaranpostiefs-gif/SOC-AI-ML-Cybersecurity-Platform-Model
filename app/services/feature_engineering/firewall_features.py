"""Feature extraction for firewall processed records.
All returned values are numeric (int/float). Missing or malformed values are encoded as -1.
"""

from typing import Dict, Any

from app.services.feature_engineering.feature_utils import (
    ip_to_int,
    hash_category,
    timestamp_to_features,
    safe_int,
)


def extract_firewall_features(record: Dict[str, Any]) -> Dict[str, Any]:
    # Preserve traceability
    features: Dict[str, Any] = {
        "event_id": safe_int(record.get("record_id")),
    }

    # IPs
    features["src_ip"] = ip_to_int(record.get("source_ip"))
    features["dst_ip"] = ip_to_int(record.get("destination_ip"))

    # Ports (may be None)
    features["src_port"] = safe_int(record.get("source_port"))
    features["dst_port"] = safe_int(record.get("destination_port"))

    # Categorical fields → deterministic hash
    features["protocol"] = hash_category(record.get("protocol"))
    features["action"] = hash_category(record.get("action"))
    features["event_type"] = hash_category(record.get("event_type"))
    features["severity"] = hash_category(record.get("severity"))

    # Connection details (flattened numeric where possible)
    conn = record.get("connection_details", {}) or {}
    features["bytes"] = safe_int(conn.get("bytes"))
    features["packets"] = safe_int(conn.get("packets"))
    features["interface"] = hash_category(conn.get("interface"))
    features["in_interface"] = hash_category(conn.get("in_interface"))
    features["out_interface"] = hash_category(conn.get("out_interface"))
    features["duration"] = safe_int(conn.get("duration"))
    features["rule"] = hash_category(conn.get("rule"))
    features["policy"] = hash_category(conn.get("policy"))

    # Timestamp derived features
    ts_features = timestamp_to_features(record.get("timestamp"))
    features.update(ts_features)

    return features
