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

