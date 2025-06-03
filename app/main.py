from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import logging
import time

from app.core.config import settings
from app.core.database import test_connection, get_database_status, retry_database_connection
from app.presentation.api.exception_handlers import exception_handlers
from app.presentation.api.v1 import empleados

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Configurar rate limiter
limiter = Limiter(key_func=get_remote_address)

# Crear aplicación FastAPI
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Sistema de control de asistencia para Florícola Hojaverde",
    debug=settings.debug,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
)

# Registrar manejadores de excepciones
for exception_type, handler in exception_handlers.items():
    app.add_exception_handler(exception_type, handler)

# Agregar rate limiter a la app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Middleware de seguridad
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"] if settings.debug else settings.allowed_hosts_list
)

# Middleware CORS - CORREGIDO para usar la property que convierte a lista
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,  # Cambiado a usar la property
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Middleware personalizado para logging de requests
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    
    # Log de request
    logger.info(f"📥 {request.method} {request.url}")
    
    # Procesar request
    response = await call_next(request)
    
    # Log de response
    process_time = time.time() - start_time
    logger.info(
        f"📤 {request.method} {request.url} - "
        f"Status: {response.status_code} - "
        f"Time: {process_time:.2f}s"
    )
    
    return response

# Evento de inicio - CON MEJOR MANEJO DE ERRORES Y MÚLTIPLES ESTRATEGIAS
@app.on_event("startup")
async def startup_event():
    logger.info("🚀 Iniciando Sistema de Asistencia Hojaverde...")
    
    # Probar conexión a la base de datos con múltiples estrategias
    db_connected = await test_connection()
    if not db_connected:
        logger.error("❌ No se pudo conectar a la base de datos con ninguna estrategia")
        logger.error("💡 Opciones:")
        logger.error("   1. Verifica tu conexión a internet")
        logger.error("   2. Revisa las credenciales en .env")
        logger.error("   3. Configura una base de datos local para desarrollo")
        logger.error("   4. Comenta 'exit(1)' para trabajar sin BD temporalmente")
        
        # En desarrollo, podrías comentar esta línea para continuar sin BD
        exit(1)
    else:
        logger.info("✅ Base de datos conectada correctamente")
    
    logger.info("✅ Sistema iniciado correctamente")

# Evento de cierre
@app.on_event("shutdown")
async def shutdown_event():
    logger.info("🛑 Cerrando Sistema de Asistencia Hojaverde...")

# Endpoints básicos
@app.get("/")
@limiter.limit("30/minute")
async def root(request: Request):
    return {
        "message": "Sistema de Control de Asistencia Hojaverde",
        "version": settings.app_version,
        "status": "running",
        "environment": settings.environment
    }

@app.get("/health")
async def health_check():
    """Health check con estado de base de datos"""
    db_status = get_database_status()
    
    return {
        "status": "healthy" if db_status["connected"] else "degraded",
        "timestamp": int(time.time()),
        "version": settings.app_version,
        "database": db_status
    }

@app.get("/database/retry")
async def retry_database():
    """Endpoint para reintentar conexión a la base de datos"""
    success = await retry_database_connection()
    
    return {
        "success": success,
        "message": "Conexión exitosa" if success else "Falló la reconexión",
        "timestamp": int(time.time())
    }

# Incluir routers
app.include_router(
    empleados.router, 
    prefix="/api/v1/empleados", 
    tags=["empleados"]
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level="info"
    )