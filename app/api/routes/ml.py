from typing import Optional
from fastapi import APIRouter, HTTPException, Body
from app.schemas.pipelines import ProcessLogsRequest, PredictRequest
from app.services.feature_engineering.feature_service import FeatureService
from app.services.ml.isolation_forest_service import IsolationForestService
from app.services.ml.xgboost_service import XGBoostService

router = APIRouter(prefix="/ml", tags=["ML"])

@router.post("/isolation-forest/train", summary="Train Isolation Forest on numeric features")
async def train_isolation_forest(request: dict = Body(...)):
    try:
        events = request.get("events", request.get("records", []))
        if isinstance(events, dict):
            events = [events]
        if not events:
            wrapper_keys = {"file_path", "events", "records"}
            raw_event = {k: v for k, v in request.items() if k not in wrapper_keys}
            if raw_event:
                events = [raw_event]
        if not isinstance(events, list):
            raise ValueError("'events' must be a list or dict")

        if len(events) < 2:
            raise ValueError(f"Isolation Forest training requires at least 2 records; received {len(events)}.")

        # Generate features from processed events
        feature_resp = FeatureService().generate(request)
        features = feature_resp.get("features", [])
        service = IsolationForestService()
        result = service.train(features)
        return result
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
@router.post("/xgboost/train", summary="Train XGBoost classifier on labeled data")
async def train_xgboost(request: ProcessLogsRequest):
    try:
        # Extract raw request dict for label handling
        if hasattr(request, "model_dump"):
            raw = request.model_dump()
        elif hasattr(request, "dict"):
            raw = request.dict()
        else:
            raw = request

        events = raw.get("events", raw.get("records", []))
        # Gather labels from events
        labels = []
        for ev in events:
            if isinstance(ev, dict):
                lbl = ev.get("label") or ev.get("attack_type")
                if lbl is not None:
                    labels.append(lbl)
        # Validate label values when present
        valid_labels = {"benign", "malicious"}
        for l in labels:
            if l not in valid_labels:
                raise ValueError(f"Unsupported label value: {l}")

        # If no labels or label count mismatches event count, return pending
        if not labels or len(labels) != len(events):
            return {
                "status": "pending",
                "detail": "No valid labeled dataset provided; supervised training not executed.",
                "model_type": "XGBoost",
                "records_used": len(events),
            }

        # Generate numeric features (may raise ValueError for unsupported log types)
        feature_resp = FeatureService().generate(request)
        features = feature_resp.get("features", [])

        # Ensure feature count matches label count
        if len(features) != len(labels):
            return {
                "status": "pending",
                "detail": "Feature extraction mismatch; supervised training not executed.",
                "model_type": "XGBoost",
                "records_used": len(features),
            }

        service = XGBoostService()
        result = service.train(features, labels)
        return result
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------------------------------------------------
# Model persistence endpoints (Phase 8)
# ---------------------------------------------------------------------

@router.post("/isolation-forest/save", summary="Persist trained Isolation Forest model")
async def save_isolation_forest(name: str = Body(..., embed=True)):
    service = IsolationForestService()
    if service._latest_model is None:
        raise HTTPException(status_code=400, detail="No trained Isolation Forest model available to save.")
    metadata = getattr(service.__class__, "_latest_metadata", {})
    service.save_model(name, metadata)
    return {"status": "saved", "model_name": name, "metadata": metadata}

@router.get("/isolation-forest/load/{name}", summary="Load persisted Isolation Forest model")

async def load_isolation_forest(name: str):
    service = IsolationForestService()
    try:
        result = service.load_model(name)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail="Failed to load model artifacts")
    return {"status": "loaded", "model_name": name, "metadata": result["metadata"]}

@router.post("/xgboost/save", summary="Persist trained XGBoost model")
async def save_xgboost(name: str = Body(..., embed=True)):
    service = XGBoostService()
    if service._latest_model is None:
        raise HTTPException(status_code=400, detail="No trained XGBoost model available to save.")
    metadata = getattr(service.__class__, "_latest_metadata", {})
    service.save_model(name, metadata)
    return {"status": "saved", "model_name": name, "metadata": metadata}

@router.get("/xgboost/load/{name}", summary="Load persisted XGBoost model")
async def load_xgboost(name: str):
    service = XGBoostService()
    try:
        result = service.load_model(name)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail="Failed to load model artifacts")
    return {"status": "loaded", "model_name": name, "metadata": result["metadata"]}

# ---------------------------------------------------------------------
# Prediction endpoints (Phase 9)
# ---------------------------------------------------------------------

@router.post("/isolation-forest/predict", summary="Predict with Isolation Forest model")
async def predict_isolation_forest(
    request: PredictRequest,
    name: Optional[str] = None,
):
    service = IsolationForestService()
    model_name = name or request.name or request.model_name
    if model_name:
        try:
            service.load_model(model_name)
        except FileNotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception:
            raise HTTPException(status_code=400, detail="Failed to load model artifacts")
    elif service.model is None or not hasattr(service.model, "estimators_"):
        raise HTTPException(
            status_code=400,
            detail="No trained or loaded Isolation Forest model available to predict.",
        )

    # Extract features: either explicit 'features' in request or via FeatureService
    if request.features:
        features = request.features
    else:
        try:
            feature_resp = FeatureService().generate(request)
            features = feature_resp.get("features", [])
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
        except Exception:
            raise HTTPException(status_code=400, detail="Failed to extract features.")

    if not features:
        raise HTTPException(status_code=400, detail="No features provided or generated for prediction.")

    try:
        result = service.predict(features)
        return result
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception:
        raise HTTPException(status_code=400, detail="Prediction failed.")


@router.post("/xgboost/predict", summary="Predict with XGBoost model")
async def predict_xgboost(
    request: PredictRequest,
    name: Optional[str] = None,
):
    service = XGBoostService()
    model_name = name or request.name or request.model_name
    if model_name:
        try:
            service.load_model(model_name)
        except FileNotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception:
            raise HTTPException(status_code=400, detail="Failed to load model artifacts")
    elif service.model is None or not hasattr(service.model, "n_classes_"):
        raise HTTPException(
            status_code=400,
            detail="No trained or loaded XGBoost model available to predict.",
        )

    if request.features:
        features = request.features
    else:
        try:
            feature_resp = FeatureService().generate(request)
            features = feature_resp.get("features", [])
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
        except Exception:
            raise HTTPException(status_code=400, detail="Failed to extract features.")

    if not features:
        raise HTTPException(status_code=400, detail="No features provided or generated for prediction.")

    try:
        result = service.predict(features)
        return result
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception:
        raise HTTPException(status_code=400, detail="Prediction failed.")