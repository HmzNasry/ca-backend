import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# DATABASE_URL can be set to e.g. postgresql+asyncpg://user:pass@host/db
# For now we use a synchronous engine; FastAPI will handle threads for blocking calls.
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./chatapp.db")

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    # Needed for SQLite in multi-threaded env
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, echo=False, future=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()

def init_db():
    from . import db_models  # ensure models are imported before create_all
    Base.metadata.create_all(bind=engine)
