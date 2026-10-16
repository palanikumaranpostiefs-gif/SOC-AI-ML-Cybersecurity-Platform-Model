from typing import Any, Dict, Optional, Union
from pydantic import BaseModel


class NormalizedLogRecord(BaseModel):
    event_id: Optional[str] = None
    timestamp: Optional[str] = None
    source: str = "unknown"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    user: Optional[str] = None
    hostname: Optional[str] = None
    action: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    message: Optional[str] = None
    raw_data: Union[Dict[str, Any], str, list, Any] = None


class NormalizeRequest(BaseModel):
    file_path: str
    source_hint: Optional[str] = None


class NormalizeResponse(BaseModel):
    status: str
    message: str
    raw_path: str
    records_processed: int
    firewall_records: int
    endpoint_records: int
    server_records: int
    unknown_records: int
    error_records: int
    output_files: Dict[str, Optional[str]]
