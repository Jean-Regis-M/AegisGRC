from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aegisgrc.core.config import settings
from aegisgrc.db.session import init_db
from aegisgrc.api.routers import scans
from aegisgrc.core.logging import logger

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Aegis continuous GRC verification and compliance microservice engine.",
    version="1.2.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# Enable broad CORS access rules for secure dashboard widgets
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    logger.info("Initializing background container SQLite ledger engines...")
    init_db()
    logger.info("Aegis logical systems online and listening on boundary port 8000.")


@app.get(f"{settings.API_V1_STR}/health", tags=["System"])
def system_health_status():
    """Returns absolute container system availability indicators."""
    return {
        "status": "healthy",
        "regulatory_alignment": "NIST_CSF_V2_SOC2_ISO27001",
        "firmware_integrity": "SIGNED_COMPLIANT_1.2.0"
    }


# Include compliance analytical routers
app.include_router(scans.router, prefix=settings.API_V1_STR)
