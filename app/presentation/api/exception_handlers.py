from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
import logging

from app.core.exceptions import (
    BaseAppException, ValidationError, BusinessError, 
    NotFoundError, AuthenticationError, AuthorizationError, ConflictError
)

logger = logging.getLogger(__name__)

async def validation_exception_handler(request: Request, exc: ValidationError):
    """Manejar errores de validación"""
    logger.warning(f"Error de validación: {exc.message}")
    return JSONResponse(
        status_code=422,
        content={
            "error": "Validation Error",
            "message": exc.message,
            "code": exc.code
        }
    )

async def business_exception_handler(request: Request, exc: BusinessError):
    """Manejar errores de lógica de negocio"""
    logger.warning(f"Error de negocio: {exc.message}")
    return JSONResponse(
        status_code=400,
        content={
            "error": "Business Error",
            "message": exc.message,
            "code": exc.code
        }
    )

async def not_found_exception_handler(request: Request, exc: NotFoundError):
    """Manejar errores de recurso no encontrado"""
    logger.info(f"Recurso no encontrado: {exc.message}")
    return JSONResponse(
        status_code=404,
        content={
            "error": "Not Found",
            "message": exc.message,
            "code": exc.code
        }
    )

async def auth_exception_handler(request: Request, exc: AuthenticationError):
    """Manejar errores de autenticación"""
    logger.warning(f"Error de autenticación: {exc.message}")
    return JSONResponse(
        status_code=401,
        content={
            "error": "Authentication Error",
            "message": exc.message,
            "code": exc.code
        }
    )

async def authorization_exception_handler(request: Request, exc: AuthorizationError):
    """Manejar errores de autorización"""
    logger.warning(f"Error de autorización: {exc.message}")
    return JSONResponse(
        status_code=403,
        content={
            "error": "Authorization Error",
            "message": exc.message,
            "code": exc.code
        }
    )

async def conflict_exception_handler(request: Request, exc: ConflictError):
    """Manejar errores de conflicto"""
    logger.warning(f"Error de conflicto: {exc.message}")
    return JSONResponse(
        status_code=409,
        content={
            "error": "Conflict Error",
            "message": exc.message,
            "code": exc.code
        }
    )

async def integrity_exception_handler(request: Request, exc: IntegrityError):
    """Manejar errores de integridad de base de datos"""
    logger.error(f"Error de integridad de BD: {exc}")
    return JSONResponse(
        status_code=409,
        content={
            "error": "Data Integrity Error",
            "message": "Violación de restricción de integridad de datos",
            "code": "INTEGRITY_ERROR"
        }
    )

async def sqlalchemy_exception_handler(request: Request, exc: SQLAlchemyError):
    """Manejar errores generales de SQLAlchemy"""
    logger.error(f"Error de base de datos: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Database Error",
            "message": "Error interno de base de datos",
            "code": "DB_ERROR"
        }
    )

async def general_exception_handler(request: Request, exc: Exception):
    """Manejar errores generales no capturados"""
    logger.error(f"Error no manejado: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "Error interno del servidor",
            "code": "INTERNAL_ERROR"
        }
    )

# Diccionario de manejadores para registrar en FastAPI
exception_handlers = {
    ValidationError: validation_exception_handler,
    BusinessError: business_exception_handler,
    NotFoundError: not_found_exception_handler,
    AuthenticationError: auth_exception_handler,
    AuthorizationError: authorization_exception_handler,
    ConflictError: conflict_exception_handler,
    IntegrityError: integrity_exception_handler,
    SQLAlchemyError: sqlalchemy_exception_handler,
    Exception: general_exception_handler,
}