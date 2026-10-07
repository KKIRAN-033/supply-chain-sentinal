import os
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Central application configuration for Supply-Chain Sentinel.
    
    All settings can be overridden via environment variables prefixed with SCS_.
    Supports development, testing, and production environments.
    """
    # Application & Environment
    APP_NAME: str = "Supply-Chain Sentinel"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"  # development, testing, production
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    WORKERS: int = 4

    # API Routing & Networking
    API_PREFIX: str = "/api/v1"
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]
    TRUSTED_HOSTS: list[str] = ["*"]

    # Security & Protection
    SECRET_KEY: str | None = None
    API_KEY: str | None = None
    API_KEY_HEADER: str = "X-API-Key"
    WEBHOOK_SECRET: str | None = None
    STRICT_TRANSPORT_SECURITY: bool = True
    HSTS_MAX_AGE: int = 31536000

    # Rate Limiting (High headroom to prevent throttling legitimate usage and rapid scans)
    ENABLE_RATE_LIMITING: bool = True
    RATE_LIMIT_PER_MINUTE: int = 1200
    SCAN_RATE_LIMIT_PER_MINUTE: int = 300

    # Storage & Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    DATA_DIR: Path = Path(__file__).resolve().parent.parent.parent / "data"
    ARTIFACT_STORAGE_DIR: str = "./data/artifacts"
    MAX_UPLOAD_SIZE_MB: int = 50

    # Database & Fallback
    DATABASE_URL: str = f"sqlite:///{(Path(__file__).resolve().parent.parent.parent / 'data' / 'sentinel.db').as_posix()}"
    JSON_FALLBACK_DIR: str = str((Path(__file__).resolve().parent.parent.parent / "data" / "json_fallback").as_posix())

    # Threat Intelligence Providers
    OSV_API_URL: str = "https://api.osv.dev/v1"
    OSV_TIMEOUT_SECONDS: float = 2.0
    ENABLE_OSV: bool = True
    ENABLE_NVD: bool = False
    ENABLE_GHSA: bool = False

    # AI Security Analyst (DeepSeek / LLM)
    DEEPSEEK_API_URL: str = "https://api.deepseek.com/chat/completions"
    DEEPSEEK_MODEL: str = "deepseek-v4.1-flash"
    DEEPSEEK_API_KEY: str | None = os.environ.get("DEEPSEEK_API_KEY")
    ENABLE_LLM: bool = bool(os.environ.get("DEEPSEEK_API_KEY"))

    model_config = {"env_prefix": "SCS_", "case_sensitive": True}


settings = Settings()
