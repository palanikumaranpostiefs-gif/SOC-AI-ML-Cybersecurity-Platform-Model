"""Feature extraction for endpoint processed records.
All returned features are numeric; missing values become -1.
"""

from typing import Dict, Any

from app.services.feature_engineering.feature_utils import (
    hash_category,
    timestamp_to_features,
    safe_int,
)


def extract_endpoint_features(record: Dict[str, Any]) -> Dict[str, Any]:
    features: Dict[str, Any] = {
        "event_id": safe_int(record.get("record_id")),
    }
    # Hostname and username hashed
    features["hostname"] = hash_category(record.get("hostname"))
    features["username"] = hash_category(record.get("username"))

    # Process details flattened
    proc = record.get("process_details", {}) or {}
    features["process_name"] = hash_category(proc.get("process_name"))
    features["process_id"] = safe_int(proc.get("process_id"))
    features["parent_process"] = hash_category(proc.get("parent_process"))
    features["cmdline"] = hash_category(proc.get("cmdline"))
    features["image_path"] = hash_category(proc.get("image_path"))
    features["file_hash"] = hash_category(proc.get("file_hash"))
    features["agent_id"] = hash_category(proc.get("agent_id"))

    # Categorical fields (event type, action, severity)
    features["event_type"] = hash_category(record.get("event_type"))
    features["action"] = hash_category(record.get("action"))
    features["severity"] = hash_category(record.get("severity"))

    # Timestamp features
    ts_features = timestamp_to_features(record.get("timestamp"))
    features.update(ts_features)

    return features
