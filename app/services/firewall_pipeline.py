import uuid
from typing import Any, Dict
from app.schemas.pipelines import FirewallProcessedRecord


def process_firewall_record(record: Dict[str, Any]) -> FirewallProcessedRecord:
    """
    Processes a normalized Firewall security event into a structured Firewall record.
    """
    raw_ref = record.get("raw_data")
    rec_id = str(record.get("event_id") or uuid.uuid4().hex[:12])

    connection_details: Dict[str, Any] = {}

    if isinstance(raw_ref, dict):
        data = raw_ref.get("data") if isinstance(raw_ref.get("data"), dict) else {}
        for k in ["bytes", "packets", "interface", "in_interface", "out_interface", "duration", "rule", "policy"]:
            val = raw_ref.get(k) if raw_ref.get(k) is not None else data.get(k)
            if val is not None:
                connection_details[k] = val
        if "bytes" not in connection_details:
            bytes_val = data.get("sent_bytes") or raw_ref.get("sent_bytes")
            if bytes_val is not None:
                connection_details["bytes"] = bytes_val
        if "rule" not in connection_details:
            rule_val = data.get("fw_rule_id") or raw_ref.get("fw_rule_id")
            if rule_val is not None:
                connection_details["rule"] = rule_val
        if "policy" not in connection_details:
            pol_val = data.get("nat_rule_id") or raw_ref.get("nat_rule_id")
            if pol_val is not None:
                connection_details["policy"] = pol_val

    return FirewallProcessedRecord(
        record_id=rec_id,
        source="firewall",
        timestamp=record.get("timestamp"),
        source_ip=record.get("source_ip"),
        destination_ip=record.get("destination_ip"),
        source_port=record.get("source_port"),
        destination_port=record.get("destination_port"),
        protocol=record.get("protocol"),
        action=record.get("action"),
        event_type=record.get("event_type"),
        severity=record.get("severity"),
        connection_details=connection_details,
        raw_reference=raw_ref,
    )
