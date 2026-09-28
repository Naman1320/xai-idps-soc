"""
Main entry point for XAI-IDPS-SOC FastAPI Backend.
Integrates detection pipeline ingestion, explainability delivery,
incident case management, automated IPS prevention, AI copilot,
digital twin topology, and SOC analytics.
"""

import logging
from contextlib import asynccontextmanager

from app.config import settings
from app.database import Base, SessionLocal, engine
from app.routers import (
    alerts_router,
    analytics_router,
    auth_router,
    cases_router,
    copilot_router,
    feedback_router,
    geolocation_router,
    prevention_router,
    reports_router,
    settings_router,
    simulator_router,
    topology_router,
)
from app.services.seed_service import seed_database
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("soc-backend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup & shutdown lifecycle handler."""
    logger.info("Initializing database tables...")
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        seed_database(db)
        logger.info("Database initialized and demo security telemetry verified.")
    except Exception as e:
        logger.error(f"Error during database seed: {e}")
    finally:
        db.close()

    yield

    logger.info("Shutting down SOC Backend...")


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Full Cloud SOC Ingestion, Triage, Explainability, IPS Prevention & AI Copilot Platform",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API v1 Routers
api_v1_prefix = settings.API_V1_STR
app.include_router(auth_router, prefix=api_v1_prefix)
app.include_router(alerts_router, prefix=api_v1_prefix)
app.include_router(cases_router, prefix=api_v1_prefix)
app.include_router(feedback_router, prefix=api_v1_prefix)
app.include_router(analytics_router, prefix=api_v1_prefix)
app.include_router(settings_router, prefix=api_v1_prefix)
app.include_router(prevention_router, prefix=api_v1_prefix)
app.include_router(copilot_router, prefix=api_v1_prefix)
app.include_router(simulator_router, prefix=api_v1_prefix)
app.include_router(topology_router, prefix=api_v1_prefix)
app.include_router(reports_router, prefix=api_v1_prefix)
app.include_router(geolocation_router, prefix=api_v1_prefix)


@app.get("/health", tags=["System"])
def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": settings.PROJECT_NAME, "version": "2.0.0"}


@app.get("/", tags=["System"])
def root():
    """Root redirect / info endpoint."""
    return {
        "message": "XAI-IDPS-SOC Full Cloud Platform API",
        "docs": "/docs",
        "api_v1": settings.API_V1_STR,
    }
