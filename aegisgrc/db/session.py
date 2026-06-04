from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from aegisgrc.core.config import settings
from aegisgrc.db.base import Base

# Setup SQLAlchemy SQLite engine or comparable PostgreSQL
engine = create_engine(
    settings.DATABASE_URL, 
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Initializes tables asynchronously on container boot."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """Context yield provider for endpoint dependency injections."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
