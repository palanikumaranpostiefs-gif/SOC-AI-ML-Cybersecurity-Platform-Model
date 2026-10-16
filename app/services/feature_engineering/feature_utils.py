"""
Utility functions for feature engineering.
"""
import ipaddress
import hashlib
from datetime import datetime
from typing import Any, Optional

def ip_to_int(ip: Optional[str]) -> int:
    """Convert an IPv4 address string to an integer. Return -1 if invalid or None."""
    if not ip:
        return -1
    try:
        return int(ipaddress.IPv4Address(ip))
    except Exception:
        return -1

def hash_category(value: Optional[Any]) -> int:
    """Deterministic hash for categorical values; returns a 32‑bit int.
    Returns -1 for missing values.
    """
    if value is None or value == "":
        return -1
    if not isinstance(value, str):
        if isinstance(value, dict):
            val_str = str(value.get("id") or value.get("name") or value.get("description") or value)
        else:
            val_str = str(value)
    else:
        val_str = value
    return int(hashlib.sha256(val_str.encode('utf-8')).hexdigest()[:8], 16)

def timestamp_to_features(ts: Optional[str]) -> dict:
    """Extract numeric time features from an ISO‑8601 timestamp.
    Returns hour, weekday, month, epoch (or -1 for missing).
    """
    if not ts:
        return {"hour": -1, "weekday": -1, "month": -1, "epoch": -1}
    try:
        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        return {"hour": dt.hour, "weekday": dt.weekday(), "month": dt.month, "epoch": int(dt.timestamp())}
    except Exception:
        return {"hour": -1, "weekday": -1, "month": -1, "epoch": -1}

def safe_int(value: Any) -> int:
    """Safely convert to int, -1 on failure."""
    try:
        return int(value)
    except Exception:
        return -1
