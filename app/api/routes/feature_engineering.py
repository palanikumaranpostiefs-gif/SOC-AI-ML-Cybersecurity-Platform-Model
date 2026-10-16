from fastapi import APIRouter, HTTPException
from app.schemas.pipelines import ProcessLogsRequest
from app.services.feature_engineering.feature_service import FeatureService

router = APIRouter(prefix="/features", tags=["Feature Engineering"])

@router.post("/generate", summary="Generate ML features from processed security events")
async def generate_features(request: ProcessLogsRequest):
    try:
        response = FeatureService().generate(request)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
