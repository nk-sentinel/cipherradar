from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    All variables are prefixed with CBOM_ (e.g. CBOM_DATABASE_URL).
    """

    # Database
    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/cipherradar"

    # Redis
    redis_url: str = "redis://localhost:6379"

    # JWT (per ADR-013)
    jwt_secret_key: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 15
    jwt_refresh_token_expire_days: int = 7

    # App
    app_name: str = "CipherRadar"
    debug: bool = False

    # CBOM Store (per ADR-012: "postgres" for dev, "s3" for production)
    cbom_store_type: str = "postgres"

    model_config = {"env_prefix": "CBOM_"}


settings = Settings()
