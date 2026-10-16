import csv
import io
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


def parse_raw_file(file_path: Path) -> Tuple[List[Any], int]:
    """
    Parses a raw log file based on its extension (.csv, .json, .jsonl, .txt).
    Returns a tuple of (parsed_records, error_count).
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    ext = file_path.suffix.lower()
    records: List[Any] = []
    error_count = 0

    if ext == ".csv":
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if any(row.values()):
                        records.append(dict(row))
        except Exception:
            error_count += 1

    elif ext == ".json":
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
                if isinstance(data, list):
                    records = data
                elif isinstance(data, dict):
                    records = [data]
                else:
                    records = [{"message": str(data)}]
        except Exception:
            error_count += 1

    elif ext in (".jsonl", ".txt"):
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = [line.strip() for line in f if line.strip()]

        if not lines:
            return [], 0

        # Attempt CSV parsing if text file has a header line with commas
        if ext == ".txt" and len(lines) > 1 and "," in lines[0] and not lines[0].startswith("{"):
            try:
                content = "\n".join(lines)
                reader = csv.DictReader(io.StringIO(content))
                fieldnames = reader.fieldnames
                if fieldnames and len(fieldnames) > 1:
                    for row in reader:
                        if any(row.values()):
                            records.append(dict(row))
                    return records, error_count
            except Exception:
                pass

        # Parse line by line (JSON or plain text)
        for line_str in lines:
            if line_str.startswith("{") or line_str.startswith("["):
                try:
                    obj = json.loads(line_str)
                    records.append(obj)
                    continue
                except Exception:
                    pass

            records.append({"message": line_str})

    else:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    records.append({"message": line_str})

    return records, error_count
