import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException
from app.schemas.pipelines import (
    EndpointProcessedRecord,
    FirewallProcessedRecord,
    ProcessLogsResponse,
    ServerProcessedRecord,
    UnknownProcessedRecord,
)
from app.services.endpoint_pipeline import process_endpoint_record
from app.services.firewall_pipeline import process_firewall_record
from app.services.normalization_service import process_and_normalize_file
from app.services.server_pipeline import process_server_record
from app.services.unknown_pipeline import process_unknown_record


def route_record(record: Dict[str, Any]) -> Tuple[str, Any]:
    """
    Routes a single normalized record based on its 'source' field.
    Returns (source_type, processed_record_model).
    """
    if not isinstance(record, dict):
        processed = process_unknown_record({"message": str(record)})
        return "unknown", processed

    source_type = str(record.get("source", "unknown")).lower()

    if source_type == "firewall":
        processed = process_firewall_record(record)
        return "firewall", processed
    elif source_type == "endpoint":
        processed = process_endpoint_record(record)
        return "endpoint", processed
    elif source_type == "server":
        processed = process_server_record(record)
        return "server", processed
    else:
        processed = process_unknown_record(record)
        return "unknown", processed


def route_and_process_records(records: List[Dict[str, Any]]) -> ProcessLogsResponse:
    """
    Routes a list of normalized records through their respective source pipelines.
    """
    processed_outputs: Dict[str, List[Dict[str, Any]]] = {
        "firewall": [],
        "endpoint": [],
        "server": [],
        "unknown": [],
    }

    error_count = 0

    for rec in records:
        try:
            source_type, processed_model = route_record(rec)
            processed_dict = processed_model.model_dump()
            if source_type in processed_outputs:
                processed_outputs[source_type].append(processed_dict)
            else:
                processed_outputs["unknown"].append(processed_dict)
        except Exception:
            error_count += 1

    total_processed = len(records)
    summary = {st: len(records_list) for st, records_list in processed_outputs.items()}

    return ProcessLogsResponse(
        status="success",
        message="Source pipeline processing complete.",
        records_processed=total_processed,
        firewall_records=summary["firewall"],
        endpoint_records=summary["endpoint"],
        server_records=summary["server"],
        unknown_records=summary["unknown"],
        error_records=error_count,
        processed_summary=summary,
        pipeline_outputs=processed_outputs,
    )


def process_file_pipeline(file_path: str) -> ProcessLogsResponse:
    path = Path(file_path)

    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"File not found for pipeline processing: '{file_path}'"
        )

    records_to_process: List[Dict[str, Any]] = []

    # If already normalized JSON file or list
    if path.suffix.lower() == ".json":
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    records_to_process = data
                elif isinstance(data, dict):
                    # Check if it's a single normalized record or wrapper
                    records_to_process = [data]
        except Exception:
            records_to_process = []

    # If raw log file or jsonl/csv, perform normalization first
    if not records_to_process:
        norm_res = process_and_normalize_file(file_path)
        # Collect records from output files
        for out_file in norm_res.output_files.values():
            if out_file and Path(out_file).exists():
                with open(out_file, "r", encoding="utf-8") as f:
                    batch = json.load(f)
                    if isinstance(batch, list):
                        records_to_process.extend(batch)

    return route_and_process_records(records_to_process)
