"""
Configuration settings for XAI-IDPS-SOC Backend.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "XAI-IDPS-SOC Platform"
    API_V1_STR: str = "/api/v1"

    # Security
    SECRET_KEY: str = "xai-idps-soc-super-secret-jwt-key-change-in-production-2025"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 hours

    # Machine-to-machine Ingestion API Key (Detection Pipeline -> Cloud SOC)
    INGESTION_API_KEY: str = "xai-soc-pipeline-key-cicids2017"

    # Database
    DATABASE_URL: str = "sqlite:///./soc.db"

    # CORS
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "http://localhost:8080",
        "http://localhost:8000",
        "*",
    ]

    # Initial Admin Seed
    DEFAULT_ADMIN_USERNAME: str = "admin"
    DEFAULT_ADMIN_PASSWORD: str = "admin123"

    # Detection Scoring Weights Defaults (4-Weight Extended Formula)
    WEIGHT_ML_CONFIDENCE: float = 0.45
    WEIGHT_ASSET_CRITICALITY: float = 0.25
    WEIGHT_ATTACK_SEVERITY: float = 0.15
    WEIGHT_THREAT_INTEL: float = 0.15

    # Alert Thresholds
    MIN_RISK_SCORE_ALERT: float = 0.30

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )


settings = Settings()
