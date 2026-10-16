from typing import Dict, Any, List

from app.services.feature_engineering.firewall_features import (
    extract_firewall_features,
)
from app.services.feature_engineering.endpoint_features import (
    extract_endpoint_features,
)
from app.services.feature_engineering.server_features import (
    extract_server_features,
) 

class FeatureService:

    def generate(self, request) -> Dict[str, Any]:
        """
        Generate ML-ready numeric features from processed security events.
        """

        # Convert Pydantic request to dictionary
        if hasattr(request, "model_dump"):
            data = request.model_dump()

        elif hasattr(request, "dict"):
            data = request.dict()

        elif isinstance(request, dict):
            data = request

        else:
            raise ValueError("Invalid request format")

        # Get events (fallback to 'records' if 'events' missing). Accept dict or list.
        events = data.get("events", data.get("records", []))
        if isinstance(events, dict):
            # Single event provided, wrap into list for processing
            events = [events]
        # If no explicit events/records but payload contains other keys, treat entire payload as a single event
        if not events:
            wrapper_keys = {"file_path", "events", "records"}
            raw_event = {k: v for k, v in data.items() if k not in wrapper_keys}
            if raw_event:
                events = [raw_event]
        if not isinstance(events, list):
            raise ValueError("'events' must be a list or dict")

        results: List[Dict[str, Any]] = []

        # Process each security event
        for event in events:

            if not isinstance(event, dict):
                continue

            # If event is a raw security event, process it through normalization & source routing
            is_processed = event.get("source") in ("firewall", "endpoint", "server") and (
                "source_ip" in event or "hostname" in event or "record_id" in event
            )
            if not is_processed:
                from app.services.normalization_service import normalize_record
                from app.services.source_router import route_record
                norm = normalize_record(event)
                source_type, routed = route_record(norm.model_dump())
                event = routed.model_dump()

            # Determine log type – check source or explicit/nested log_type
            raw_type = (
                event.get("source")
                or event.get("log_type")
                or event.get("source_type")
                or event.get("type")
                or event.get("data", {}).get("log_type")
                or event.get("decoder", {}).get("name")
                or ""
            )
            # Normalise Sophos decoder names (e.g., "sophos-fw-ng") to "firewall"
            if raw_type and ("fw" in str(raw_type).lower() or "firewall" in str(raw_type).lower()):
                log_type = "firewall"
            else:
                log_type = str(raw_type).lower().strip()
            # Infer firewall logs when explicit type missing but typical fields are present
            if not log_type:
                if "source_ip" in event and "destination_ip" in event:
                    log_type = "firewall"
            log_type = str(log_type).lower().strip()

            # Firewall
            if log_type == "firewall":
                features = extract_firewall_features(event)

            # Endpoint
            elif log_type == "endpoint":
                features = extract_endpoint_features(event)

            # Server
            elif log_type == "server":
                features = extract_server_features(event)

            # Unknown
            else:
                raise ValueError(
                    f"Unsupported log type: {log_type}"
                )

            results.append(features)

        # Return generated features
        return {
            "status": "success",
            "count": len(results),
            "features": results,
        }