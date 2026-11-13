"""ARGUS Database Connection.

Manages SQLAlchemy engine and session factory for PostgreSQL.
Works with both local PostgreSQL and Supabase (hosted PostgreSQL).

Configuration is read from the DATABASE_URL environment variable.
"""

from __future__ import annotations

import logging
import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

logger = logging.getLogger("argus.database")

# Load environment variables from .env file
load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://argus:change_me@localhost:5432/argus",
)

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,  # Verify connections before using them
    pool_size=5,
    max_overflow=10,
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Session:
    """Create a new database session.

    Usage as a context manager:
        with get_db() as db:
            db.query(...)

    Usage as a FastAPI dependency:
        def endpoint(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables defined in models.py.

    Call this once at startup or during migration.
    """
    from argus.database.models import Base

    logger.info("Initializing database tables...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully.")
