import uuid
from typing import Any, Dict
from app.schemas.pipelines import UnknownProcessedRecord


def process_unknown_record(record: Dict[str, Any]) -> UnknownProcessedRecord:
    """
    Handles an unclassified/unknown log record, keeping it intact for future inspection.
    """
    raw_ref = record.get("raw_data") if isinstance(record, dict) else record
    rec_id = str(record.get("event_id") if isinstance(record, dict) and record.get("event_id") else uuid.uuid4().hex[:12])

    message = record.get("message") if isinstance(record, dict) else str(record)

    return UnknownProcessedRecord(
        record_id=rec_id,
        source="unknown",
        timestamp=record.get("timestamp") if isinstance(record, dict) else None,
        message=str(message) if message is not None else None,
        raw_reference=raw_ref,
    )
