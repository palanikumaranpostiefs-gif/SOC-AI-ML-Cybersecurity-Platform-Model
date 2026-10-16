import uuid
from typing import Any, Dict
from app.schemas.pipelines import EndpointProcessedRecord


def process_endpoint_record(record: Dict[str, Any]) -> EndpointProcessedRecord:
    """
    Processes a normalized Endpoint security event into a structured Endpoint record.
    """
    raw_ref = record.get("raw_data")
    rec_id = str(record.get("event_id") or uuid.uuid4().hex[:12])

    process_details: Dict[str, Any] = {}

    if isinstance(raw_ref, dict):
        data = raw_ref.get("data") if isinstance(raw_ref.get("data"), dict) else {}
        for k in ["process_name", "process_id", "parent_process", "cmdline", "image_path", "file_hash", "agent_id"]:
            val = raw_ref.get(k) if raw_ref.get(k) is not None else data.get(k)
            if val is not None:
                process_details[k] = val

    return EndpointProcessedRecord(
        record_id=rec_id,
        source="endpoint",
        timestamp=record.get("timestamp"),
        hostname=record.get("hostname"),
        username=record.get("user"),
        event_id=str(record.get("event_id")) if record.get("event_id") else None,
        event_type=record.get("event_type"),
        action=record.get("action"),
        severity=record.get("severity"),
        process_details=process_details,
        raw_reference=raw_ref,
    )
