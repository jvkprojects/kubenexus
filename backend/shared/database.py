"""
Shared database utilities for KubeNexus backend services.
Provides database connection management, session handling, and base models.
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional
from sqlalchemy import create_engine, MetaData, event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
from sqlalchemy.engine import Engine
import asyncpg

from .config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Database metadata
metadata = MetaData(
    naming_convention={
        "ix": "ix_%(column_0_label)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s"
    }
)

# Base model for SQLAlchemy models
Base = declarative_base(metadata=metadata)

# Database engines
engine: Optional[Engine] = None
async_engine = None

# Session makers
SessionLocal: Optional[sessionmaker] = None
AsyncSessionLocal: Optional[async_sessionmaker] = None


def create_sync_engine() -> Engine:
    """Create synchronous database engine."""
    return create_engine(
        settings.database_url,
        poolclass=QueuePool,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout,
        pool_recycle=settings.db_pool_recycle,
        pool_pre_ping=True,
        echo=settings.debug,
    )


def create_async_engine_instance():
    """Create asynchronous database engine."""
    # Convert PostgreSQL URL to async version
    async_url = settings.database_url.replace("postgresql://", "postgresql+asyncpg://")
    
    return create_async_engine(
        async_url,
        poolclass=QueuePool,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout,
        pool_recycle=settings.db_pool_recycle,
        pool_pre_ping=True,
        echo=settings.debug,
    )


def init_database():
    """Initialize database connections and session makers."""
    global engine, async_engine, SessionLocal, AsyncSessionLocal
    
    try:
        # Create engines
        engine = create_sync_engine()
        async_engine = create_async_engine_instance()
        
        # Create session makers
        SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=engine,
            expire_on_commit=False
        )
        
        AsyncSessionLocal = async_sessionmaker(
            async_engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        logger.info("Database connections initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize database connections: {e}")
        raise


async def close_database():
    """Close database connections."""
    global engine, async_engine
    
    try:
        if async_engine:
            await async_engine.dispose()
            logger.info("Async database engine disposed")
        
        if engine:
            engine.dispose()
            logger.info("Sync database engine disposed")
            
    except Exception as e:
        logger.error(f"Error closing database connections: {e}")


def get_db() -> Session:
    """
    Dependency function to get database session.
    Use this in FastAPI dependencies.
    """
    if not SessionLocal:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@asynccontextmanager
async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager to get database session.
    Use this in async functions.
    """
    if not AsyncSessionLocal:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_async_db_dependency() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency function for FastAPI to get async database session.
    """
    async with get_async_db() as session:
        yield session


class DatabaseManager:
    """Database management utility class."""
    
    def __init__(self):
        self.engine = None
        self.async_engine = None
        self.session_local = None
        self.async_session_local = None
    
    def initialize(self):
        """Initialize database connections."""
        init_database()
        self.engine = engine
        self.async_engine = async_engine
        self.session_local = SessionLocal
        self.async_session_local = AsyncSessionLocal
    
    async def close(self):
        """Close database connections."""
        await close_database()
    
    def get_session(self) -> Session:
        """Get synchronous database session."""
        if not self.session_local:
            raise RuntimeError("Database not initialized")
        return self.session_local()
    
    @asynccontextmanager
    async def get_async_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get asynchronous database session."""
        if not self.async_session_local:
            raise RuntimeError("Database not initialized")
        
        async with self.async_session_local() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()
    
    async def test_connection(self) -> bool:
        """Test database connection."""
        try:
            async with self.get_async_session() as session:
                await session.execute("SELECT 1")
                return True
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            return False
    
    async def get_database_info(self) -> dict:
        """Get database information."""
        try:
            async with self.get_async_session() as session:
                result = await session.execute("""
                    SELECT 
                        version() as version,
                        current_database() as database,
                        current_user as user,
                        inet_server_addr() as host,
                        inet_server_port() as port
                """)
                row = result.fetchone()
                return {
                    "version": row.version,
                    "database": row.database,
                    "user": row.user,
                    "host": row.host,
                    "port": row.port
                }
        except Exception as e:
            logger.error(f"Failed to get database info: {e}")
            return {}


# Global database manager instance
db_manager = DatabaseManager()


# Event listeners for connection management
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Set database-specific connection parameters."""
    # This is for PostgreSQL specific settings if needed
    pass


@event.listens_for(Engine, "before_cursor_execute")
def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    """Log SQL queries in debug mode."""
    if settings.debug and settings.log_level == "DEBUG":
        logger.debug(f"Executing SQL: {statement}")
        if parameters:
            logger.debug(f"Parameters: {parameters}")


# Health check utilities
import time
from datetime import datetime

async def check_database_health() -> dict:
    """Check database health status."""
    try:
        start_time = time.time()
        
        async with get_async_db() as session:
            # Test basic connectivity
            await session.execute("SELECT 1")
            
            # Get database stats
            result = await session.execute("""
                SELECT 
                    COUNT(*) as active_connections
                FROM pg_stat_activity 
                WHERE state = 'active'
            """)
            stats = result.fetchone()
            
            end_time = time.time()
            response_time = (end_time - start_time) * 1000  # ms
            
            return {
                "status": "healthy",
                "response_time_ms": round(response_time, 2),
                "active_connections": stats.active_connections if stats else 0,
                "database": settings.postgres_db,
                "timestamp": datetime.utcnow().isoformat()
            }
            
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }


# Database utilities
async def execute_raw_sql(sql: str, parameters: dict = None) -> list:
    """Execute raw SQL query and return results."""
    try:
        async with get_async_db() as session:
            result = await session.execute(sql, parameters or {})
            return result.fetchall()
    except Exception as e:
        logger.error(f"Failed to execute raw SQL: {e}")
        raise


async def get_table_row_count(table_name: str) -> int:
    """Get row count for a specific table."""
    try:
        async with get_async_db() as session:
            result = await session.execute(f"SELECT COUNT(*) FROM {table_name}")
            return result.scalar()
    except Exception as e:
        logger.error(f"Failed to get row count for table {table_name}: {e}")
        return 0


# Migration utilities
def run_migrations():
    """Run database migrations using Alembic."""
    try:
        from alembic.config import Config
        from alembic import command
        
        alembic_cfg = Config("alembic.ini")
        command.upgrade(alembic_cfg, "head")
        logger.info("Database migrations completed successfully")
        
    except Exception as e:
        logger.error(f"Failed to run migrations: {e}")
        raise


# Connection retry utilities
import asyncio

async def wait_for_database(max_retries: int = 30, delay: int = 2):
    """Wait for database to become available."""
    for attempt in range(max_retries):
        try:
            async with get_async_db() as session:
                await session.execute("SELECT 1")
                logger.info("Database connection established")
                return True
        except Exception as e:
            logger.warning(f"Database connection attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(delay)
            else:
                logger.error("Failed to connect to database after maximum retries")
                raise
    
    return False 