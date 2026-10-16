import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from fastapi import HTTPException, UploadFile
from app.schemas.upload import UploadResponse

SUPPORTED_EXTENSIONS = {".csv", ".json", ".jsonl", ".txt"}
BASE_RAW_DIR = Path("data/raw")

SOURCE_DIR_MAP = {
    "firewall": BASE_RAW_DIR / "firewall",
    "endpoint": BASE_RAW_DIR / "endpoint",
    "server": BASE_RAW_DIR / "server",
    "bulk": BASE_RAW_DIR / "bulk",
}


async def save_uploaded_log(file: UploadFile, source_type: str) -> UploadResponse:
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file was provided for upload.")

    # Prevent path traversal by extracting clean basename
    original_filename = Path(file.filename).name
    file_ext = Path(original_filename).suffix.lower()

    if file_ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{file_ext}'. Supported formats: CSV, JSON, JSONL, TXT.",
        )

    # Read file contents to validate size and empty files
    contents = await file.read()
    file_size = len(contents)

    if file_size == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty (0 bytes).")

    # Determine destination folder
    target_dir = SOURCE_DIR_MAP.get(source_type.lower(), BASE_RAW_DIR / source_type.lower())
    target_dir.mkdir(parents=True, exist_ok=True)

    # Generate unique filename to avoid overwrites
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    unique_id = uuid.uuid4().hex[:8]
    clean_stem = Path(original_filename).stem
    saved_filename = f"{timestamp_str}_{unique_id}_{clean_stem}{file_ext}"
    saved_path = target_dir / saved_filename

    # Save file contents securely
    try:
        with open(saved_path, "wb") as f:
            f.write(contents)
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to save uploaded file: {str(e)}"
        )

    upload_timestamp = datetime.now(timezone.utc).isoformat()

    return UploadResponse(
        status="success",
        message=f"{source_type.capitalize()} log file uploaded successfully.",
        original_filename=original_filename,
        saved_filename=saved_filename,
        saved_path=str(saved_path).replace("\\", "/"),
        source_type=source_type.lower(),
        file_type=file_ext.lstrip("."),
        upload_timestamp=upload_timestamp,
        file_size_bytes=file_size,
    )
