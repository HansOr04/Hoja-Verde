from typing import Optional, List, Callable, Union
from datetime import datetime
import logging

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import security_manager
from app.domain.services.usuario import usuario_service
from app.infrastructure.database.models.usuario import Usuario, RolEnum
from app.core.exceptions import AuthenticationError, AuthorizationError

logger = logging.getLogger(__name__)

# Configurar esquema de seguridad Bearer
security = HTTPBearer()

class AuthContext:
    """Contexto de autenticación del usuario actual"""
    
    def __init__(self, usuario: Usuario):
        self.usuario = usuario
        self.user_id = usuario.id
        self.email = usuario.email
        self.rol = usuario.rol
        self.permisos = usuario.permisos_adicionales or []
        self.empleado_id = usuario.empleado_id
    
    @property
    def is_admin(self) -> bool:
        """Verificar si es administrador"""
        return self.usuario.is_admin
    
    @property
    def is_supervisor(self) -> bool:
        """Verificar si es supervisor o superior"""
        return self.usuario.is_supervisor
    
    def tiene_permiso(self, permiso: str) -> bool:
        """Verificar si tiene un permiso específico"""
        return self.usuario.tiene_permiso(permiso)
    
    def puede_acceder_empleado(self, empleado_id: Optional[str] = None) -> bool:
        """Verificar si puede acceder a información de un empleado específico"""
        # Super admin y admin pueden acceder a cualquier empleado
        if self.rol in [RolEnum.SUPER_ADMIN, RolEnum.ADMIN, RolEnum.RECURSOS_HUMANOS]:
            return True
        
        # Si es el mismo empleado
        if empleado_id and str(self.empleado_id) == str(empleado_id):
            return True
        
        return False

# === DEPENDENCIAS DE AUTENTICACIÓN ===

async def get_current_user_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> str:
    """
    Extraer token de las credenciales
    
    Returns:
        Token JWT
        
    Raises:
        HTTPException: Si no hay token
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de acceso requerido",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return credentials.credentials

async def get_current_user(
    token: str = Depends(get_current_user_token),
    db: AsyncSession = Depends(get_db)
) -> Usuario:
    """
    Obtener usuario actual desde el token JWT
    
    Args:
        token: Token JWT
        db: Sesión de base de datos
        
    Returns:
        Usuario autenticado
        
    Raises:
        HTTPException: Si el token es inválido o el usuario no existe
    """
    try:
        # Verificar token
        payload = security_manager.verify_token(token, "access")
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token inválido o expirado",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Extraer user_id del token
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token malformado",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Obtener usuario
        usuario = await usuario_service.get_by_id(db, user_id)
        if not usuario:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuario no encontrado",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Verificar que el usuario esté activo
        if not usuario.is_active or usuario.is_blocked:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuario inactivo o bloqueado",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Verificar que el token esté en la lista de tokens activos (opcional)
        token_jti = payload.get("jti")
        if token_jti and hasattr(usuario, 'tokens_activos'):
            if token_jti not in (usuario.tokens_activos or []):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Sesión invalidada",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        
        logger.debug(f"Usuario autenticado: {usuario.email}")
        return usuario
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en autenticación: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Error de autenticación",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_auth_context(
    current_user: Usuario = Depends(get_current_user)
) -> AuthContext:
    """
    Obtener contexto de autenticación
    
    Args:
        current_user: Usuario actual
        
    Returns:
        Contexto de autenticación
    """
    return AuthContext(current_user)

# === DEPENDENCIAS DE AUTORIZACIÓN ===

def require_roles(*roles: RolEnum) -> Callable:
    """
    Decorator para requerir roles específicos
    
    Args:
        roles: Roles permitidos
        
    Returns:
        Dependencia de FastAPI
    """
    async def check_roles(auth_context: AuthContext = Depends(get_auth_context)):
        if auth_context.rol not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Acceso denegado. Roles requeridos: {[r.value for r in roles]}",
            )
        return auth_context
    
    return check_roles

def require_permissions(*permissions: str) -> Callable:
    """
    Decorator para requerir permisos específicos
    
    Args:
        permissions: Permisos requeridos
        
    Returns:
        Dependencia de FastAPI
    """
    async def check_permissions(auth_context: AuthContext = Depends(get_auth_context)):
        for permission in permissions:
            if not auth_context.tiene_permiso(permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permiso requerido: {permission}",
                )
        return auth_context
    
    return check_permissions

def require_admin() -> Callable:
    """Requerir rol de administrador"""
    return require_roles(RolEnum.SUPER_ADMIN, RolEnum.ADMIN)

def require_supervisor() -> Callable:
    """Requerir rol de supervisor o superior"""
    return require_roles(RolEnum.SUPER_ADMIN, RolEnum.ADMIN, RolEnum.SUPERVISOR)

def require_hr() -> Callable:
    """Requerir acceso de recursos humanos"""
    return require_roles(RolEnum.SUPER_ADMIN, RolEnum.ADMIN, RolEnum.RECURSOS_HUMANOS)

# === DEPENDENCIAS OPCIONALES ===

async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
    db: AsyncSession = Depends(get_db)
) -> Optional[Usuario]:
    """
    Obtener usuario actual de forma opcional (no falla si no hay token)
    
    Args:
        credentials: Credenciales opcionales
        db: Sesión de base de datos
        
    Returns:
        Usuario si está autenticado, None si no
    """
    if not credentials or not credentials.credentials:
        return None
    
    try:
        # Usar la misma lógica pero sin lanzar excepciones
        payload = security_manager.verify_token(credentials.credentials, "access")
        if not payload:
            return None
        
        user_id = payload.get("sub")
        if not user_id:
            return None
        
        usuario = await usuario_service.get_by_id(db, user_id)
        if not usuario or not usuario.is_active or usuario.is_blocked:
            return None
        
        return usuario
        
    except Exception as e:
        logger.debug(f"Error en autenticación opcional: {e}")
        return None

# === VALIDADORES DE RECURSOS ===

def require_own_resource_or_admin(resource_user_field: str = "user_id") -> Callable:
    """
    Requerir que el recurso pertenezca al usuario o que sea admin
    
    Args:
        resource_user_field: Campo que contiene el ID del usuario propietario
        
    Returns:
        Dependencia de FastAPI
    """
    async def check_ownership(
        resource_user_id: str,
        auth_context: AuthContext = Depends(get_auth_context)
    ):
        # Admins pueden acceder a cualquier recurso
        if auth_context.is_admin:
            return auth_context
        
        # Verificar ownership
        if str(auth_context.user_id) != str(resource_user_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Solo puedes acceder a tus propios recursos",
            )
        
        return auth_context
    
    return check_ownership

def require_empleado_access(empleado_id: str = None) -> Callable:
    """
    Requerir acceso a un empleado específico
    
    Args:
        empleado_id: ID del empleado
        
    Returns:
        Dependencia de FastAPI
    """
    async def check_empleado_access(
        auth_context: AuthContext = Depends(get_auth_context)
    ):
        if not auth_context.puede_acceder_empleado(empleado_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No tienes acceso a este empleado",
            )
        
        return auth_context
    
    return check_empleado_access

# === MIDDLEWARE PARA AUDITORÍA ===

class AuditMiddleware:
    """Middleware para auditoría de acciones"""
    
    @staticmethod
    async def log_action(
        request: Request,
        auth_context: Optional[AuthContext] = None,
        action: str = None,
        resource_type: str = None,
        resource_id: str = None,
        details: dict = None
    ):
        """
        Registrar acción para auditoría
        
        Args:
            request: Request de FastAPI
            auth_context: Contexto de autenticación
            action: Acción realizada
            resource_type: Tipo de recurso
            resource_id: ID del recurso
            details: Detalles adicionales
        """
        try:
            audit_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "ip_address": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
                "method": request.method,
                "path": str(request.url.path),
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "details": details or {}
            }
            
            if auth_context:
                audit_data.update({
                    "user_id": str(auth_context.user_id),
                    "user_email": auth_context.email,
                    "user_role": auth_context.rol.value
                })
            
            # Log para auditoría (en producción esto iría a una base de datos)
            logger.info(f"AUDIT: {audit_data}")
            
        except Exception as e:
            logger.error(f"Error registrando auditoría: {e}")

# === DECORADORES DE CONVENIENCIA ===

def authenticated(func):
    """Decorator para marcar funciones que requieren autenticación"""
    func._requires_auth = True
    return func

def authorize(*roles_or_permissions):
    """Decorator para autorización"""
    def decorator(func):
        func._auth_requirements = roles_or_permissions
        return func
    return decorator

# === HELPERS PARA REFRESH TOKENS ===

async def get_refresh_token_user(
    token: str,
    db: AsyncSession = Depends(get_db)
) -> Usuario:
    """
    Obtener usuario desde refresh token
    
    Args:
        token: Refresh token
        db: Sesión de base de datos
        
    Returns:
        Usuario si el token es válido
        
    Raises:
        HTTPException: Si el token es inválido
    """
    try:
        # Verificar refresh token
        payload = security_manager.verify_token(token, "refresh")
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token inválido o expirado",
            )
        
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token malformado",
            )
        
        # Obtener usuario
        usuario = await usuario_service.get_by_id(db, user_id)
        if not usuario:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuario no encontrado",
            )
        
        # Verificar que esté activo
        if not usuario.is_active or usuario.is_blocked:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuario inactivo o bloqueado",
            )
        
        return usuario
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error validando refresh token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Error validando refresh token",
        )

# === UTILIDADES DE CONTEXTO ===

def get_request_info(request: Request) -> dict:
    """Obtener información de la request para auditoría"""
    return {
        "ip_address": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
        "method": request.method,
        "path": str(request.url.path),
        "query_params": dict(request.query_params),
    }

async def verify_api_key(api_key: str, db: AsyncSession) -> Optional[Usuario]:
    """
    Verificar API key (para integraciones)
    
    Args:
        api_key: API key a verificar
        db: Sesión de base de datos
        
    Returns:
        Usuario asociado a la API key o None
    """
    # Implementar lógica de API keys si es necesario
    # Por ahora retornamos None
    return None

# === CONTEXT MANAGERS ===

class AuthenticationContext:
    """Context manager para autenticación temporal"""
    
    def __init__(self, usuario: Usuario):
        self.usuario = usuario
        self.auth_context = AuthContext(usuario)
    
    def __enter__(self):
        return self.auth_context
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

# === VALIDADORES ADICIONALES ===

def validate_password_change_permission(
    target_user_id: str,
    auth_context: AuthContext
) -> bool:
    """
    Validar permisos para cambiar contraseña
    
    Args:
        target_user_id: ID del usuario cuya contraseña se quiere cambiar
        auth_context: Contexto de autenticación
        
    Returns:
        True si tiene permisos
    """
    # Puede cambiar su propia contraseña
    if str(auth_context.user_id) == str(target_user_id):
        return True
    
    # Admins pueden cambiar contraseñas de otros
    if auth_context.is_admin:
        return True
    
    return False

def validate_user_management_permission(
    target_user_role: RolEnum,
    auth_context: AuthContext
) -> bool:
    """
    Validar permisos para gestionar usuarios
    
    Args:
        target_user_role: Rol del usuario objetivo
        auth_context: Contexto de autenticación
        
    Returns:
        True si tiene permisos
    """
    # Solo super admins pueden gestionar otros super admins
    if target_user_role == RolEnum.SUPER_ADMIN:
        return auth_context.rol == RolEnum.SUPER_ADMIN
    
    # Admins pueden gestionar roles inferiores
    if auth_context.is_admin:
        return True
    
    return False

# === EXCEPCIONES PERSONALIZADAS ===

class InsufficientPermissionException(Exception):
    """Excepción para permisos insuficientes"""
    def __init__(self, required_permission: str):
        self.required_permission = required_permission
        super().__init__(f"Permiso requerido: {required_permission}")

class InvalidTokenException(Exception):
    """Excepción para tokens inválidos"""
    def __init__(self, message: str = "Token inválido"):
        self.message = message
        super().__init__(message)

# === FUNCIONES DE UTILIDAD ===

def extract_bearer_token(authorization_header: str) -> Optional[str]:
    """
    Extraer token Bearer del header Authorization
    
    Args:
        authorization_header: Header Authorization
        
    Returns:
        Token sin el prefijo "Bearer " o None
    """
    if not authorization_header:
        return None
    
    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    
    return parts[1]

def is_public_endpoint(path: str) -> bool:
    """
    Verificar si un endpoint es público (no requiere autenticación)
    
    Args:
        path: Path del endpoint
        
    Returns:
        True si es público
    """
    public_paths = [
        "/",
        "/health",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/api/v1/auth/login",
        "/api/v1/auth/refresh",
        "/api/v1/auth/reset-password",
        "/api/v1/auth/confirm-reset"
    ]
    
    return path in public_paths or path.startswith("/static/")

# === LOGGING HELPERS ===

def log_authentication_attempt(email: str, success: bool, reason: str = None):
    """Log intento de autenticación"""
    status = "SUCCESS" if success else "FAILED"
    message = f"AUTH {status}: {email}"
    if reason:
        message += f" - {reason}"
    
    if success:
        logger.info(message)
    else:
        logger.warning(message)

def log_authorization_check(user_id: str, permission: str, granted: bool):
    """Log verificación de autorización"""
    status = "GRANTED" if granted else "DENIED"
    logger.info(f"AUTHZ {status}: User {user_id} - Permission '{permission}'")