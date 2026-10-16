import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException
from app.schemas.normalization import NormalizedLogRecord, NormalizeResponse
from app.services.parser_service import parse_raw_file

PROCESSED_BASE_DIR = Path("data/processed")

# Regex pattern matchers
IP_ADDRESS_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
KEY_VALUE_PATTERN = re.compile(r"(\w+)=([^\s]+)")


def _extract_kv_pairs(text: str) -> Dict[str, str]:
    matches = KEY_VALUE_PATTERN.findall(text)
    return {k.lower(): v.strip('"\'') for k, v in matches}


def detect_source(record: Any, file_source_hint: Optional[str] = None) -> str:
    """
    Detects security log source type: 'firewall', 'endpoint', 'server', or 'unknown'.
    """
    rec_dict: Dict[str, Any] = {}

    if isinstance(record, dict):
        rec_dict = record
    elif isinstance(record, str):
        rec_dict = _extract_kv_pairs(record)
        rec_dict["message"] = record

    data_dict = rec_dict.get("data") if isinstance(rec_dict.get("data"), dict) else {}
    decoder_dict = rec_dict.get("decoder") if isinstance(rec_dict.get("decoder"), dict) else {}

    # 1. Explicit metadata fields (top-level or nested data)
    for field_name in ["source", "source_type", "log_type", "device_type", "product", "vendor"]:
        val = str(rec_dict.get(field_name) or data_dict.get(field_name) or "").lower()
        if any(w in val for w in ("firewall", "fw", "paloalto", "fortigate", "cisco_asa", "iptables")):
            return "firewall"
        if any(w in val for w in ("endpoint", "sysmon", "edr", "crowdstrike", "winlogbeat")):
            return "endpoint"
        if any(w in val for w in ("server", "syslog", "sshd", "apache", "nginx", "linux_server")):
            return "server"

    decoder_name = str(decoder_dict.get("name", "")).lower()
    if decoder_name:
        if any(w in decoder_name for w in ("firewall", "fw", "sophos-fw", "paloalto", "fortigate")):
            return "firewall"
        if any(w in decoder_name for w in ("sysmon", "endpoint", "edr", "crowdstrike")):
            return "endpoint"
        if any(w in decoder_name for w in ("server", "syslog", "sshd", "apache", "nginx")):
            return "server"

    keys = set(k.lower() for k in rec_dict.keys()) | set(k.lower() for k in data_dict.keys())

    # 2. Key patterns
    # Firewall
    has_src_ip = any(k in keys for k in ["src_ip", "source_ip", "src", "ip_src", "source_address"])
    has_dst_ip = any(k in keys for k in ["dst_ip", "destination_ip", "dst", "ip_dst", "destination_address"])
    has_net_action = any(k in keys for k in ["action", "proto", "protocol", "src_port", "dst_port", "sport", "dport", "status"])

    if has_src_ip and has_dst_ip and has_net_action:
        return "firewall"

    # Endpoint
    has_endpoint_keys = any(k in keys for k in ["process_name", "process_id", "parent_process", "cmdline", "image_path", "agent_id"])
    if has_endpoint_keys:
        return "endpoint"

    # Server
    has_server_keys = any(k in keys for k in ["service", "facility", "syslog", "http_status", "url", "method", "user_agent"])
    if has_server_keys:
        return "server"

    # 3. Message text signals
    msg = str(rec_dict.get("message") or rec_dict.get("full_log") or "").lower()
    if "firewall" in msg or ("allow" in msg or "deny" in msg or "drop" in msg) and len(IP_ADDRESS_PATTERN.findall(msg)) >= 2:
        return "firewall"
    if "sshd" in msg or "syslog" in msg or "kernel:" in msg or "systemd" in msg or "apache" in msg or "nginx" in msg:
        return "server"
    if "process" in msg or "powershell" in msg or "cmd.exe" in msg or "event_id" in msg:
        return "endpoint"

    # 4. Fallback to folder hint if confident context exists
    if file_source_hint and file_source_hint.lower() in ("firewall", "endpoint", "server"):
        return file_source_hint.lower()

    return "unknown"


def _safe_int(val: Any) -> Optional[int]:
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _first_match(data: Dict[str, Any], candidate_keys: List[str]) -> Optional[Any]:
    for key in candidate_keys:
        if key in data and data[key] is not None:
            return data[key]
    nested = data.get("data")
    if isinstance(nested, dict):
        for key in candidate_keys:
            if key in nested and nested[key] is not None:
                return nested[key]
    rule = data.get("rule")
    if isinstance(rule, dict):
        for key in candidate_keys:
            if key in rule and rule[key] is not None:
                return rule[key]
    return None


def normalize_record(raw_record: Any, file_source_hint: Optional[str] = None) -> NormalizedLogRecord:
    source = detect_source(raw_record, file_source_hint=file_source_hint)

    rec: Dict[str, Any] = {}
    if isinstance(raw_record, dict):
        rec = raw_record
    elif isinstance(raw_record, str):
        rec = _extract_kv_pairs(raw_record)
        rec["message"] = raw_record

    event_id = _first_match(rec, ["event_id", "id", "log_id", "seq"])
    timestamp = _first_match(rec, ["timestamp", "datetime", "time", "@timestamp", "date", "log_time"])
    source_ip = _first_match(rec, ["source_ip", "src_ip", "src", "ip_src", "client_ip", "source_address"])
    destination_ip = _first_match(rec, ["destination_ip", "dst_ip", "dst", "ip_dst", "server_ip", "destination_address"])
    source_port = _safe_int(_first_match(rec, ["source_port", "src_port", "sport", "src_p"]))
    destination_port = _safe_int(_first_match(rec, ["destination_port", "dst_port", "dport", "dst_p"]))
    protocol = _first_match(rec, ["protocol", "proto", "transport"])
    user = _first_match(rec, ["user", "username", "account", "user_name", "usr", "login_user"])
    hostname = _first_match(rec, ["hostname", "host", "device_name", "computer_name", "node"])
    action = _first_match(rec, ["action", "status", "disposition", "event_action", "result"])
    event_type = _first_match(rec, ["event_type", "type", "event_name", "category", "log_subtype", "log_component"])
    severity = _first_match(rec, ["severity", "level", "log_level", "priority"])
    message = _first_match(rec, ["message", "msg", "details", "description", "log", "full_log"])

    # Fallback IP extraction from message string if missing
    if not source_ip or not destination_ip:
        if message and isinstance(message, str):
            ips = IP_ADDRESS_PATTERN.findall(message)
            if len(ips) >= 1 and not source_ip:
                source_ip = ips[0]
            if len(ips) >= 2 and not destination_ip:
                destination_ip = ips[1]

    return NormalizedLogRecord(
        event_id=str(event_id) if event_id is not None else None,
        timestamp=str(timestamp) if timestamp is not None else None,
        source=source,
        source_ip=str(source_ip) if source_ip is not None else None,
        destination_ip=str(destination_ip) if destination_ip is not None else None,
        source_port=source_port,
        destination_port=destination_port,
        protocol=str(protocol).upper() if protocol is not None else None,
        user=str(user) if user is not None else None,
        hostname=str(hostname) if hostname is not None else None,
        action=str(action).upper() if action is not None else None,
        event_type=str(event_type) if event_type is not None else None,
        severity=str(severity) if severity is not None else None,
        message=str(message) if message is not None else None,
        raw_data=raw_record,
    )


def process_and_normalize_file(raw_file_path: str, source_hint: Optional[str] = None) -> NormalizeResponse:
    path = Path(raw_file_path)

    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Raw log file not found at path: '{raw_file_path}'"
        )

    if not source_hint:
        parent_dir_name = path.parent.name.lower()
        if parent_dir_name in ("firewall", "endpoint", "server"):
            source_hint = parent_dir_name

    raw_records, parse_error_count = parse_raw_file(path)

    normalized_by_source: Dict[str, List[Dict[str, Any]]] = {
        "firewall": [],
        "endpoint": [],
        "server": [],
        "unknown": [],
    }

    norm_error_count = 0

    for raw_rec in raw_records:
        try:
            norm_rec = normalize_record(raw_rec, file_source_hint=source_hint)
            source_key = norm_rec.source if norm_rec.source in normalized_by_source else "unknown"
            normalized_by_source[source_key].append(norm_rec.model_dump())
        except Exception:
            norm_error_count += 1

    total_processed = len(raw_records)
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    unique_id = uuid.uuid4().hex[:8]
    clean_stem = path.stem

    output_files: Dict[str, Optional[str]] = {
        "firewall": None,
        "endpoint": None,
        "server": None,
        "unknown": None,
    }

    for source_type, records in normalized_by_source.items():
        if not records:
            continue

        target_dir = PROCESSED_BASE_DIR / source_type
        target_dir.mkdir(parents=True, exist_ok=True)

        out_filename = f"{timestamp_str}_{unique_id}_{clean_stem}_normalized.json"
        out_path = target_dir / out_filename

        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2, ensure_ascii=False)
            output_files[source_type] = str(out_path).replace("\\", "/")
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to save normalized {source_type} records: {str(e)}"
            )

    return NormalizeResponse(
        status="success",
        message="Log normalization complete.",
        raw_path=str(path).replace("\\", "/"),
        records_processed=total_processed,
        firewall_records=len(normalized_by_source["firewall"]),
        endpoint_records=len(normalized_by_source["endpoint"]),
        server_records=len(normalized_by_source["server"]),
        unknown_records=len(normalized_by_source["unknown"]),
        error_records=parse_error_count + norm_error_count,
        output_files=output_files,
    )
