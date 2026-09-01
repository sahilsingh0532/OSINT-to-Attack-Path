import os
import shutil
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.config import settings


class Base(DeclarativeBase):
    pass


engine = create_async_engine(settings.database_url, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db():
    """Dependency that yields a database session."""
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def _migrate_sqlite_columns(conn):
    """Ensure newly added columns exist in existing SQLite databases."""
    from sqlalchemy import text
    try:
        res = await conn.execute(text("PRAGMA table_info(findings)"))
        existing_cols = {row[1] for row in res.fetchall()}
        
        needed_cols = [
            ("sources", "TEXT"),
            ("source_count", "INTEGER DEFAULT 1"),
            ("source_agreement", "FLOAT DEFAULT 1.0"),
            ("total_queried", "INTEGER DEFAULT 1"),
            ("evidence_per_source", "TEXT"),
            ("norm_value", "TEXT"),
            ("first_seen", "TIMESTAMP"),
            ("last_seen", "TIMESTAMP"),
        ]
        
        for col_name, col_type in needed_cols:
            if col_name not in existing_cols:
                await conn.execute(text(f"ALTER TABLE findings ADD COLUMN {col_name} {col_type}"))
    except Exception as e:
        print(f"Column migration warning: {e}")


async def init_db():
    """Create all tables and copy seed DB if running in temp directory."""
    if "sqlite" in settings.database_url and ("tmp" in settings.database_url or "temp" in settings.database_url):
        tmp_db_path = settings.database_url.replace("sqlite+aiosqlite:///", "")
        if not os.path.exists(tmp_db_path):
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            seed_db = os.path.join(base_dir, "osint_attack_path.db")
            if os.path.exists(seed_db):
                try:
                    shutil.copy2(seed_db, tmp_db_path)
                except Exception as e:
                    print(f"Could not copy seed database: {e}")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _migrate_sqlite_columns(conn)

