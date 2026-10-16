from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel


class FirewallProcessedRecord(BaseModel):
    record_id: str
    source: str = "firewall"
    timestamp: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    action: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    connection_details: Dict[str, Any] = {}
    raw_reference: Any = None


class EndpointProcessedRecord(BaseModel):
    record_id: str
    source: str = "endpoint"
    timestamp: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    event_id: Optional[str] = None
    event_type: Optional[str] = None
    action: Optional[str] = None
    severity: Optional[str] = None
    process_details: Dict[str, Any] = {}
    raw_reference: Any = None


class ServerProcessedRecord(BaseModel):
    record_id: str
    source: str = "server"
    timestamp: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    service: Optional[str] = None
    event_type: Optional[str] = None
    action: Optional[str] = None
    severity: Optional[str] = None
    auth_details: Dict[str, Any] = {}
    raw_reference: Any = None


class UnknownProcessedRecord(BaseModel):
    record_id: str
    source: str = "unknown"
    timestamp: Optional[str] = None
    message: Optional[str] = None
    raw_reference: Any = None


class ProcessLogsRequest(BaseModel):
    file_path: Optional[str] = None
    # Accept both 'records' (legacy) and 'events' (new) as list of log dicts
    events: Optional[List[Dict[str, Any]]] = None
    records: Optional[List[Dict[str, Any]]] = None

    class Config:
        allow_population_by_field_name = True
        extra = "allow"
        # Populate 'events' from 'records' if 'events' missing
        @staticmethod
        def alias_generator(field_name: str) -> str:
            # No automatic aliasing; we'll handle in code
            return field_name


class PredictRequest(ProcessLogsRequest):
    name: Optional[str] = None
    model_name: Optional[str] = None
    features: Optional[List[Dict[str, Any]]] = None


class ProcessLogsResponse(BaseModel):
    status: str
    message: str
    records_processed: int
    firewall_records: int
    endpoint_records: int
    server_records: int
    unknown_records: int
    error_records: int
    processed_summary: Dict[str, int]
    pipeline_outputs: Dict[str, List[Dict[str, Any]]]
