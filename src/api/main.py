import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routes import upload, results

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("zenith")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Load models
    logger.info("Starting up Zenith Engine...")
    try:
        from .routes.upload import get_model_and_scaler
        get_model_and_scaler()
        logger.info("Models loaded successfully.")
    except Exception as e:
        logger.error(f"Failed to load models at startup: {e}")
    
    yield
    # Shutdown: Clean up resources if needed
    logger.info("Shutting down Zenith Engine...")

app = FastAPI(
    title="Zenith | Encrypted Traffic Detector",
    version="1.0.4",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(upload.router, prefix="/api")
app.include_router(results.router, prefix="/api")

@app.get("/health")
def health():
    return {"status": "online", "engine": "XGBoost-v1", "version": "1.0.4"}
