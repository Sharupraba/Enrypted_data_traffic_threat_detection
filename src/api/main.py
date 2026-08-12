import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from src.api.database import init_db
from src.detection.model import load_model_assets
from src.api.websocket import manager
from .routes import upload, capture, flows, alerts, analytics, reports, settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("threat_detector")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup tasks
    logger.info("Starting up Threat Detection Engine...")
    try:
        import os
        from src.api.routes.settings import load_system_config
        cfg = load_system_config()
        os.environ["ABUSEIPDB_API_KEY"] = cfg.get("abuseipdb_key", "")
        os.environ["VIRUSTOTAL_API_KEY"] = cfg.get("virustotal_key", "")
        
        # Initialize database tables & indexes
        await init_db()
        # Initialize model singletons into RAM
        load_model_assets()
        logger.info("Threat Detection Engine initialization successful.")
    except Exception as e:
        logger.error(f"Failed during Threat Detection Engine initialization: {e}")
    
    yield
    # Shutdown tasks
    logger.info("Shutting down Threat Detection Engine...")

app = FastAPI(
    title="NetFlow Security Monitor",
    version="1.1.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount REST API routers
app.include_router(upload.router, prefix="/api")
app.include_router(capture.router, prefix="/api")
app.include_router(flows.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(analytics.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(settings.router, prefix="/api")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    Real-time WebSocket endpoint for broadcasting flow analytics and alerts.
    """
    await manager.connect(websocket)
    try:
        while True:
            # Client can send heartbeats or custom query constraints
            data = await websocket.receive_text()
            # Respond to ping/heartbeats to keep connection active if needed
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket client connection encountered an error: {e}")
        manager.disconnect(websocket)

@app.get("/health")
def health():
    return {"status": "online", "engine": "XGBoost-v1", "version": "1.1.0"}

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "Encrypted Traffic Threat Detection API Gateway",
        "docs_url": "/docs",
        "health_check": "/health"
    }
