from fastapi import APIRouter, HTTPException
from app.schemas.pipelines import ProcessLogsRequest, ProcessLogsResponse
from app.services.source_router import process_file_pipeline, route_and_process_records

router = APIRouter(prefix="/logs", tags=["Source Pipelines"])


@router.post("/process", response_model=ProcessLogsResponse, summary="Process Normalized Logs through Source Pipelines")
async def process_logs(request: ProcessLogsRequest):
    if request.file_path:
        return process_file_pipeline(request.file_path)
    elif request.records is not None:
        return route_and_process_records(request.records)
    else:
        raise HTTPException(
            status_code=400,
            detail="Must provide either 'file_path' or 'records' in request payload."
        )
