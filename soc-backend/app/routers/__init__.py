"""
Router module exports.
"""

from app.routers.auth import router as auth_router
from app.routers.alerts import router as alerts_router
from app.routers.cases import router as cases_router
from app.routers.feedback import router as feedback_router
from app.routers.analytics import router as analytics_router
from app.routers.settings import router as settings_router
from app.routers.prevention import router as prevention_router
from app.routers.copilot import router as copilot_router
from app.routers.simulator import router as simulator_router
from app.routers.topology import router as topology_router
from app.routers.reports import router as reports_router
from app.routers.geolocation import router as geolocation_router

__all__ = [
    "auth_router",
    "alerts_router",
    "cases_router",
    "feedback_router",
    "analytics_router",
    "settings_router",
    "prevention_router",
    "copilot_router",
    "simulator_router",
    "topology_router",
    "reports_router",
    "geolocation_router",
]
