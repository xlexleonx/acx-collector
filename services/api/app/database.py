from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from .config import settings

engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def ensure_schema() -> None:
    """Create the schema and apply tiny additive migrations for pilot installs."""
    Base.metadata.create_all(bind=engine)
    if inspect(engine).has_table("triggers"):
        columns = {column["name"] for column in inspect(engine).get_columns("triggers")}
        if "expression" not in columns:
            with engine.begin() as connection:
                connection.execute(text("ALTER TABLE triggers ADD COLUMN expression TEXT NOT NULL DEFAULT ''"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

