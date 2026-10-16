from fastapi import FastAPI
from app.api.routes.logs import router as logs_router
from app.api.routes.normalization import router as normalization_router
from app.api.routes.feature_engineering import router as feature_router
from app.api.routes.ml import router as ml_router
from app.api.routes.pipeline import router as pipeline_router

app = FastAPI(
    title="SOC AI-ML & Cybersecurity Model",
    description="SOC / Cybersecurity AI-ML Anomaly Detection + Agentic AI Investigation Platform",
    version="0.1.0",
)

app.include_router(logs_router)
app.include_router(normalization_router)
app.include_router(feature_router)
app.include_router(pipeline_router)
app.include_router(ml_router)


@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": "SOC AI-ML Backend"
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)



