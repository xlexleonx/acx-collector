import os
from pathlib import Path


class Settings:
    database_url = os.getenv("DATABASE_URL", "sqlite:///./acx.db")
    master_key = os.getenv("ACX_MASTER_KEY", "")
    collector_name = os.getenv("COLLECTOR_NAME", "ACROTIX Collector")
    retention_days = int(os.getenv("LOCAL_RETENTION_DAYS", "30"))
    bootstrap_token_file = Path(os.getenv("BOOTSTRAP_TOKEN_FILE", "/run/secrets/bootstrap_token"))


settings = Settings()

