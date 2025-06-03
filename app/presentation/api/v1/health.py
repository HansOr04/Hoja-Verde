from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import time
import psutil
import logging

from app.core.database import get_db

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    """
    Endpoint de salud para monitoreo de Render
    Verifica conectividad de BD, memoria y CPU
    """
    start_time = time.time()
    health_status = {
        "status": "healthy",
        "timestamp": int(time.time()),
        "version": "1.0.0",
        "checks": {}
    }
    
    try:
        # Verificar base de datos
        db_start = time.time()
        await db.execute(text("SELECT 1"))
        db_time = time.time() - db_start
        
        health_status["checks"]["database"] = {
            "status": "up",
            "response_time_ms": round(db_time * 1000, 2)
        }
        
        # Verificar memoria
        memory = psutil.virtual_memory()
        health_status["checks"]["memory"] = {
            "status": "up" if memory.percent < 90 else "warning",
            "usage_percent": memory.percent
        }
        
        # Verificar CPU
        cpu_percent = psutil.cpu_percent(interval=1)
        health_status["checks"]["cpu"] = {
            "status": "up" if cpu_percent < 80 else "warning",
            "usage_percent": cpu_percent
        }
        
        # Tiempo total de respuesta
        total_time = time.time() - start_time
        health_status["response_time_ms"] = round(total_time * 1000, 2)
        
        # Determinar estado general
        all_checks_up = all(
            check["status"] == "up" 
            for check in health_status["checks"].values()
        )
        
        if not all_checks_up:
            health_status["status"] = "degraded"
        
        return health_status
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        health_status["status"] = "unhealthy"
        health_status["error"] = str(e)
        
        raise HTTPException(status_code=503, detail=health_status)

@router.get("/health/ready")
async def readiness_check(db: AsyncSession = Depends(get_db)):
    """Verificar si la aplicación está lista para recibir tráfico"""
    try:
        await db.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        raise HTTPException(
            status_code=503, 
            detail={"status": "not_ready", "error": str(e)}
        )

@router.get("/health/live")
async def liveness_check():
    """Verificar si la aplicación está viva"""
    return {"status": "alive", "timestamp": int(time.time())}