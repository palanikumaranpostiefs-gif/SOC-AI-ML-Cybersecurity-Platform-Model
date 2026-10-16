from pydantic import BaseModel


class UploadResponse(BaseModel):
    status: str
    message: str
    original_filename: str
    saved_filename: str
    saved_path: str
    source_type: str
    file_type: str
    upload_timestamp: str
    file_size_bytes: int
