"""Feature extraction for server processed records.
All returned values are numeric; missing fields become -1.
"""

from typing import Dict, Any

from app.services.feature_engineering.feature_utils import (
    ip_to_int,
    hash_category,
    timestamp_to_features,
    safe_int,
)


def extract_server_features(record: Dict[str, Any]) -> Dict[str, Any]:
    features: Dict[str, Any] = {
        "event_id": safe_int(record.get("record_id")),
    }
    # Hostname and username hashed
    features["hostname"] = hash_category(record.get("hostname"))
    features["username"] = hash_category(record.get("username"))

    # IPs
    features["src_ip"] = ip_to_int(record.get("source_ip"))
    features["dst_ip"] = ip_to_int(record.get("destination_ip"))

    # Service/auth details hashed
    features["service"] = hash_category(record.get("service"))
    auth = record.get("auth_details", {}) or {}
    # Flatten common auth fields (example keys)
    features["auth_method"] = hash_category(auth.get("auth_method"))
    features["auth_success"] = hash_category(str(auth.get("success")))

    # Categorical fields
    features["event_type"] = hash_category(record.get("event_type"))
    features["action"] = hash_category(record.get("action"))
    features["severity"] = hash_category(record.get("severity"))

    # Timestamp derived features
    ts_features = timestamp_to_features(record.get("timestamp"))
    features.update(ts_features)

    return features
