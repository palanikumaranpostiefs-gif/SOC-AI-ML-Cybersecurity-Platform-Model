import uuid
from typing import Any, Dict
from app.schemas.pipelines import ServerProcessedRecord


def process_server_record(record: Dict[str, Any]) -> ServerProcessedRecord:
    """
    Processes a normalized Server security event into a structured Server record.
    """
    raw_ref = record.get("raw_data")
    rec_id = str(record.get("event_id") or uuid.uuid4().hex[:12])

    auth_details: Dict[str, Any] = {}

    service_name = None
    if isinstance(raw_ref, dict):
        data = raw_ref.get("data") if isinstance(raw_ref.get("data"), dict) else {}
        service_name = raw_ref.get("service") or raw_ref.get("facility") or data.get("service") or data.get("facility")
        for k in ["service", "facility", "status", "syslog", "http_status", "url", "method", "user_agent"]:
            val = raw_ref.get(k) if raw_ref.get(k) is not None else data.get(k)
            if val is not None:
                auth_details[k] = val

    return ServerProcessedRecord(
        record_id=rec_id,
        source="server",
        timestamp=record.get("timestamp"),
        hostname=record.get("hostname"),
        username=record.get("user"),
        source_ip=record.get("source_ip"),
        destination_ip=record.get("destination_ip"),
        service=str(service_name) if service_name else None,
        event_type=record.get("event_type"),
        action=record.get("action"),
        severity=record.get("severity"),
        auth_details=auth_details,
        raw_reference=raw_ref,
    )
