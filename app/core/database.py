from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import logging
import asyncio
from typing import Optional

from .config import settings

logger = logging.getLogger(__name__)

# Variables globales para engines
async_engine = None
sync_engine = None
AsyncSessionLocal = None
SessionLocal = None
database_connected = False

# Base para modelos
Base = declarative_base()

async def create_database_engines():
    """Crear engines de base de datos con múltiples estrategias de fallback"""
    global async_engine, sync_engine, AsyncSessionLocal, SessionLocal, database_connected
    
    # Estrategias de conexión en orden de preferencia
    connection_strategies = [
        {
            "name": "Session Pooler (5432)",
            "async_url": settings.async_database_url.replace(":6543/", ":5432/"),
            "sync_url": settings.database_url.replace(":6543/", ":5432/"),
            "connect_args": {
                "server_settings": {
                    "application_name": "sistema_asistencia",
                }
            }
        },
        {
            "name": "Session Pooler without prepared statements",
            "async_url": settings.async_database_url.replace(":6543/", ":5432/"),
            "sync_url": settings.database_url.replace(":6543/", ":5432/"),
            "connect_args": {
                "statement_cache_size": 0,
                "prepared_statement_cache_size": 0,
                "server_settings": {
                    "application_name": "sistema_asistencia",
                }
            }
        },
        {
            "name": "Transaction Pooler minimal",
            "async_url": settings.async_database_url,
            "sync_url": settings.database_url,
            "connect_args": {
                "statement_cache_size": 0,
                "prepared_statement_cache_size": 0,
            }
        }
    ]
    
    for strategy in connection_strategies:
        logger.info(f"🔄 Probando conexión: {strategy['name']}")
        
        try:
            # Crear engine async temporal para prueba
            test_async_engine = create_async_engine(
                strategy["async_url"],
                echo=False,
                pool_size=1,
                max_overflow=0,
                pool_timeout=10,
                connect_args=strategy["connect_args"]
            )
            
            # Probar conexión
            async with test_async_engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            
            logger.info(f"✅ Conexión exitosa con: {strategy['name']}")
            
            # Crear engines finales
            async_engine = create_async_engine(
                strategy["async_url"],
                echo=settings.debug,
                pool_size=5,
                max_overflow=10,
                pool_timeout=30,
                pool_recycle=1800,
                pool_pre_ping=True,
                connect_args=strategy["connect_args"]
            )
            
            sync_engine = create_engine(
                strategy["sync_url"],
                echo=settings.debug,
                pool_size=5,
                max_overflow=10,
                pool_timeout=30,
                pool_recycle=1800,
                pool_pre_ping=True,
            )
            
            # Crear sesiones
            AsyncSessionLocal = async_sessionmaker(
                async_engine, 
                class_=AsyncSession, 
                expire_on_commit=False
            )
            
            SessionLocal = sessionmaker(
                autocommit=False, 
                autoflush=False, 
                bind=sync_engine
            )
            
            database_connected = True
            await test_async_engine.dispose()
            return True
            
        except Exception as e:
            logger.warning(f"⚠️ Falló {strategy['name']}: {str(e)[:100]}...")
            if 'test_async_engine' in locals():
                await test_async_engine.dispose()
            continue
    
    logger.error("❌ Todas las estrategias de conexión fallaron")
    return False

# Dependencia para FastAPI con manejo de errores
async def get_db() -> AsyncSession:
    """Obtener sesión de base de datos con manejo de errores"""
    if not database_connected:
        raise RuntimeError("Base de datos no conectada. Revisa la configuración.")
    
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            logger.error(f"Error en sesión de BD: {e}")
            await session.rollback()
            raise
        finally:
            await session.close()

# Función para probar conexión
async def test_connection() -> bool:
    """Probar conexión a la base de datos"""
    return await create_database_engines()

# Función para obtener estado de la conexión
def get_database_status() -> dict:
    """Obtener estado actual de la base de datos"""
    return {
        "connected": database_connected,
        "async_engine_available": async_engine is not None,
        "sync_engine_available": sync_engine is not None,
        "session_makers_available": AsyncSessionLocal is not None and SessionLocal is not None
    }

# Función para reintentar conexión
async def retry_database_connection() -> bool:
    """Reintentar conexión a la base de datos"""
    logger.info("🔄 Reintentando conexión a la base de datos...")
    return await create_database_engines()