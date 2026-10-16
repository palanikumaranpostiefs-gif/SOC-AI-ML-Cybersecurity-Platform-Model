from fastapi import APIRouter, File, UploadFile
from app.schemas.upload import UploadResponse
from app.services.upload_service import save_uploaded_log

router = APIRouter(prefix="/logs/upload", tags=["Log Upload"])


@router.post("/firewall", response_model=UploadResponse, summary="Upload Firewall Log")
async def upload_firewall_log(file: UploadFile = File(...)):
    return await save_uploaded_log(file, source_type="firewall")


@router.post("/endpoint", response_model=UploadResponse, summary="Upload Endpoint Log")
async def upload_endpoint_log(file: UploadFile = File(...)):
    return await save_uploaded_log(file, source_type="endpoint")


@router.post("/server", response_model=UploadResponse, summary="Upload Server Log")
async def upload_server_log(file: UploadFile = File(...)):
    return await save_uploaded_log(file, source_type="server")


@router.post("/bulk", response_model=UploadResponse, summary="Upload Bulk / Mixed Security Logs")
async def upload_bulk_log(file: UploadFile = File(...)):
    return await save_uploaded_log(file, source_type="bulk")
