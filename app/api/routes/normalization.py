from fastapi import APIRouter
from app.schemas.normalization import NormalizeRequest, NormalizeResponse
from app.services.normalization_service import process_and_normalize_file

router = APIRouter(prefix="/logs", tags=["Log Normalization"])


@router.post("/normalize", response_model=NormalizeResponse, summary="Normalize Raw Security Log File")
async def normalize_log(request: NormalizeRequest):
    return process_and_normalize_file(
        raw_file_path=request.file_path,
        source_hint=request.source_hint,
    )
