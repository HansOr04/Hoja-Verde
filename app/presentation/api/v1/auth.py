from fastapi import APIRouter, Depends, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
import logging

from app.core.database import get_db
from app.core.auth import get_current_user, get_auth_context, AuthContext, get_request_info
from app.domain.services.auth import auth_service
from app.infrastructure.database.models.usuario import Usuario
from app.presentation.schemas.usuario import (
    LoginRequest, PasswordResetRequest, PasswordResetConfirm
)
from app.presentation.schemas.auth import (
    AuthResponse, TokenResponse, RefreshTokenRequest, LogoutResponse, 
    LogoutAllResponse, SessionValidation, SessionInfo
)
from app.core.exceptions import AuthenticationError, ValidationError

logger = logging.getLogger(__name__)
router = APIRouter()

# === AUTENTICACIÓN BÁSICA ===

@router.post("/login", response_model=AuthResponse, status_code=200)
async def login(
    request: Request,
    login_data: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Realizar login de usuario
    
    - **email**: Email del usuario
    - **password**: Contraseña del usuario
    - **remember_me**: Mantener sesión por más tiempo
    """
    logger.info(f"Intento de login para: {login_data.email}")
    
    # Obtener información de la request
    request_info = get_request_info(request)
    
    # Realizar login
    auth_response = await auth_service.login(db, login_data, request_info)
    
    logger.info(f"Login exitoso para: {login_data.email}")
    return auth_response

@router.post("/refresh", response_model=TokenResponse, status_code=200)
async def refresh_token(
    refresh_data: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Renovar token de acceso usando refresh token
    
    - **refresh_token**: Token de refresh válido
    """
    logger.info("Solicitud de renovación de token")
    
    token_response = await auth_service.refresh_token(db, refresh_data.refresh_token)
    
    logger.info("Token renovado exitosamente")
    return token_response

@router.post("/logout", response_model=LogoutResponse, status_code=200)
async def logout(
    auth_context: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db)
):
    """
    Cerrar sesión actual del usuario
    """
    logger.info(f"Logout para usuario: {auth_context.email}")
    
    result = await auth_service.logout(db, auth_context.usuario)
    
    return LogoutResponse(
        message=result["message"],
        logged_out_at=result["logged_out_at"]
    )

@router.post("/logout-all", response_model=LogoutAllResponse, status_code=200)
async def logout_all_sessions(
    auth_context: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db)
):
    """
    Cerrar todas las sesiones del usuario
    """
    logger.info(f"Logout de todas las sesiones para usuario: {auth_context.email}")
    
    result = await auth_service.logout_all_sessions(db, auth_context.usuario)
    
    return LogoutAllResponse(
        message=result["message"],
        sessions_closed=result["sessions_closed"],
        logged_out_at=result["logged_out_at"]
    )

# === RESET DE CONTRASEÑA ===

@router.post("/reset-password", status_code=200)
async def request_password_reset(
    reset_data: PasswordResetRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Solicitar reset de contraseña
    
    - **email**: Email del usuario que solicita el reset
    
    Se enviará un email con instrucciones si el email existe en el sistema.
    """
    logger.info(f"Solicitud de reset de contraseña para: {reset_data.email}")
    
    result = await auth_service.request_password_reset(db, reset_data.email)
    
    return result

@router.post("/confirm-reset", status_code=200)
async def confirm_password_reset(
    reset_data: PasswordResetConfirm,
    db: AsyncSession = Depends(get_db)
):
    """
    Confirmar reset de contraseña con token
    
    - **token**: Token de reset recibido por email
    - **password_nuevo**: Nueva contraseña
    - **confirmar_password**: Confirmación de la nueva contraseña
    """
    logger.info("Confirmación de reset de contraseña")
    
    result = await auth_service.confirm_password_reset(
        db, reset_data.token, reset_data.password_nuevo
    )
    
    return result

# === VALIDACIÓN Y GESTIÓN DE SESIONES ===

@router.get("/validate", response_model=SessionValidation, status_code=200)
async def validate_session(
    auth_context: AuthContext = Depends(get_auth_context)
):
    """
    Validar sesión actual
    
    Endpoint para verificar si el token actual es válido y obtener información del usuario.
    """
    return SessionValidation(
        is_valid=True,
        user_id=auth_context.user_id,
        permissions=auth_context.permisos
    )

@router.get("/me", status_code=200)
async def get_current_user_info(
    auth_context: AuthContext = Depends(get_auth_context)
):
    """
    Obtener información del usuario actual
    """
    from app.presentation.schemas.usuario import UsuarioResponse
    
    # Convertir usuario a schema de respuesta
    usuario_response = UsuarioResponse.model_validate(auth_context.usuario)
    
    return {
        "user": usuario_response,
        "context": {
            "rol": auth_context.rol.value,
            "permisos": auth_context.permisos,
            "is_admin": auth_context.is_admin,
            "is_supervisor": auth_context.is_supervisor,
            "empleado_id": str(auth_context.empleado_id) if auth_context.empleado_id else None
        }
    }

@router.get("/sessions", status_code=200)
async def get_active_sessions(
    auth_context: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db)
):
    """
    Obtener lista de sesiones activas del usuario
    """
    logger.info(f"Obteniendo sesiones activas para usuario: {auth_context.email}")
    
    sessions = await auth_service.get_active_sessions(db, auth_context.usuario)
    
    return {
        "sessions": sessions,
        "total": len(sessions)
    }

@router.delete("/sessions/{session_id}", status_code=200)
async def revoke_session(
    session_id: str,
    auth_context: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db)
):
    """
    Revocar una sesión específica
    
    - **session_id**: ID de la sesión a revocar
    """
    logger.info(f"Revocando sesión {session_id} para usuario: {auth_context.email}")
    
    success = await auth_service.revoke_session(db, auth_context.usuario, session_id)
    
    if success:
        return {"message": "Sesión revocada exitosamente"}
    else:
        raise ValidationError("No se pudo revocar la sesión")

# === ENDPOINTS DE INFORMACIÓN ===

@router.get("/permissions", status_code=200)
async def get_user_permissions(
    auth_context: AuthContext = Depends(get_auth_context)
):
    """
    Obtener permisos del usuario actual
    """
    return {
        "rol": auth_context.rol.value,
        "permisos_adicionales": auth_context.permisos,
        "permisos_efectivos": auth_context.permisos + [
            f"rol.{auth_context.rol.value}"
        ],
        "capabilities": {
            "is_admin": auth_context.is_admin,
            "is_supervisor": auth_context.is_supervisor,
            "can_manage_employees": auth_context.usuario.can_manage_employees
        }
    }

@router.get("/check-permission/{permission}", status_code=200)
async def check_permission(
    permission: str,
    auth_context: AuthContext = Depends(get_auth_context)
):
    """
    Verificar si el usuario tiene un permiso específico
    
    - **permission**: Nombre del permiso a verificar
    """
    has_permission = auth_context.tiene_permiso(permission)
    
    return {
        "permission": permission,
        "granted": has_permission,
        "user_id": str(auth_context.user_id),
        "rol": auth_context.rol.value
    }

# === ENDPOINTS DE AUDITORÍA ===

@router.get("/audit/login-history", status_code=200)
async def get_login_history(
    auth_context: AuthContext = Depends(get_auth_context),
    limit: int = 10
):
    """
    Obtener historial de logins del usuario
    
    - **limit**: Número máximo de registros a devolver
    """
    # En una implementación completa, esto consultaría una tabla de auditoría
    logger.info(f"Obteniendo historial de logins para usuario: {auth_context.email}")
    
    # Por ahora devolvemos datos mock
    return {
        "login_history": [
            {
                "timestamp": "2025-06-02T10:00:00Z",
                "ip_address": "192.168.1.100",
                "user_agent": "Mozilla/5.0...",
                "success": True
            }
        ],
        "total": 1,
        "user_id": str(auth_context.user_id)
    }

# === ENDPOINTS DE CONFIGURACIÓN ===

@router.get("/security-settings", status_code=200)
async def get_security_settings(
    auth_context: AuthContext = Depends(get_auth_context)
):
    """
    Obtener configuraciones de seguridad del usuario
    """
    return {
        "two_factor_enabled": False,  # Placeholder para futuras implementaciones
        "password_last_changed": auth_context.usuario.password_cambiado_en.isoformat() if auth_context.usuario.password_cambiado_en else None,
        "failed_attempts": auth_context.usuario.intentos_fallidos or 0,
        "account_locked": auth_context.usuario.is_blocked,
        "active_sessions": len(auth_context.usuario.tokens_activos or [])
    }

# === ENDPOINTS ADMINISTRATIVOS ===

@router.post("/admin/force-logout/{user_id}", status_code=200)
async def admin_force_logout(
    user_id: str,
    auth_context: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db)
):
    """
    Forzar logout de un usuario (solo administradores)
    
    - **user_id**: ID del usuario a desconectar
    """
    if not auth_context.is_admin:
        raise AuthenticationError("Acceso denegado: se requieren permisos de administrador")
    
    from uuid import UUID
    from app.domain.services.usuario import usuario_service
    
    # Obtener usuario objetivo
    target_user = await usuario_service.get_by_id(db, UUID(user_id))
    if not target_user:
        raise ValidationError("Usuario no encontrado")
    
    # Forzar logout
    result = await auth_service.logout_all_sessions(db, target_user)
    
    logger.warning(f"Admin {auth_context.email} forzó logout de usuario: {target_user.email}")
    
    return {
        "message": f"Usuario {target_user.email} desconectado forzosamente",
        "sessions_closed": result["sessions_closed"],
        "admin_user": auth_context.email
    }

@router.get("/admin/active-users", status_code=200)
async def get_active_users_count(
    auth_context: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db)
):
    """
    Obtener cantidad de usuarios activos (solo administradores)
    """
    if not auth_context.is_admin:
        raise AuthenticationError("Acceso denegado: se requieren permisos de administrador")
    
    # En una implementación completa, esto consultaría estadísticas reales
    return {
        "active_sessions": 0,  # Placeholder
        "total_users": 0,      # Placeholder
        "online_users": 0,     # Placeholder
        "timestamp": "2025-06-02T10:00:00Z"
    }

# === HEALTH CHECK ===

@router.get("/health", status_code=200)
async def auth_health_check():
    """
    Health check del servicio de autenticación
    """
    return {
        "service": "authentication",
        "status": "healthy",
        "timestamp": "2025-06-02T10:00:00Z",
        "version": "1.0.0"
    }