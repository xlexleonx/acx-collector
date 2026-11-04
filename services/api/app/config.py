import os
from pathlib import Path


class Settings:
    database_url = os.getenv("DATABASE_URL", "sqlite:///./acx.db")
    master_key = os.getenv("ACX_MASTER_KEY", "")
    portal_url = os.getenv("PORTAL_URL", "").rstrip("/")
    portal_installation_id = os.getenv("PORTAL_INSTALLATION_ID", "")
    portal_sync_token = os.getenv("PORTAL_SYNC_TOKEN", "")
    retention_days = int(os.getenv("LOCAL_RETENTION_DAYS", "30"))
    bootstrap_token_file = Path(os.getenv("BOOTSTRAP_TOKEN_FILE", "/run/secrets/bootstrap_token"))


settings = Settings()

