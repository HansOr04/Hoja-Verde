from datetime import datetime
from typing import Optional, Dict, Any, List
from uuid import UUID
from pydantic import BaseModel, Field

# === TOKEN SCHEMAS ===

class Token(BaseModel):
    """Schema básico para token"""
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    """Schema para datos del token"""
    user_id: Optional[UUID] = None
    email: Optional[str] = None
    rol: Optional[str] = None
    permisos: Optional[List[str]] = Field(default_factory=list)

class TokenResponse(BaseModel):
    """Schema completo para respuesta de token"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_expires_in: int
    scope: str = "read write"

# === REQUEST SCHEMAS ===

class RefreshTokenRequest(BaseModel):
    """Schema para solicitud de refresh token"""
    refresh_token: str = Field(..., description="Token de refresh")

class PasswordResetRequest(BaseModel):
    """Schema para solicitud de reset de contraseña"""
    email: str = Field(..., description="Email del usuario")

class PasswordResetConfirm(BaseModel):
    """Schema para confirmación de reset de contraseña"""
    token: str = Field(..., description="Token de reset")
    new_password: str = Field(..., min_length=8, description="Nueva contraseña")

class ChangePasswordRequest(BaseModel):
    """Schema para cambio de contraseña"""
    current_password: str = Field(..., description="Contraseña actual")
    new_password: str = Field(..., min_length=8, description="Nueva contraseña")

# === AUTENTICACIÓN ===

class AuthResponse(BaseModel):
    """Schema para respuesta de autenticación exitosa"""
    message: str = "Autenticación exitosa"
    user: "UsuarioResponse"
    tokens: TokenResponse
    session_info: Optional[Dict[str, Any]] = None

class LogoutResponse(BaseModel):
    """Schema para respuesta de logout"""
    message: str = "Sesión cerrada exitosamente"
    logged_out_at: datetime

class LogoutAllResponse(BaseModel):
    """Schema para logout de todas las sesiones"""
    message: str = "Todas las sesiones han sido cerradas"
    sessions_closed: int
    logged_out_at: datetime

# === RESET DE CONTRASEÑA ===

class PasswordResetResponse(BaseModel):
    """Schema para respuesta de solicitud de reset"""
    message: str = "Si el email existe, se enviarán instrucciones de reset"
    reset_token: Optional[str] = None  # Solo en desarrollo

class PasswordResetConfirmResponse(BaseModel):
    """Schema para respuesta de confirmación de reset"""
    message: str = "Contraseña cambiada exitosamente"
    reset_at: datetime

class ChangePasswordResponse(BaseModel):
    """Schema para respuesta de cambio de contraseña"""
    message: str = "Contraseña cambiada exitosamente"
    changed_at: datetime

# === VALIDACIÓN DE SESIÓN ===

class SessionValidation(BaseModel):
    """Schema para validación de sesión"""
    is_valid: bool
    user_id: Optional[UUID] = None
    email: Optional[str] = None
    rol: Optional[str] = None
    expires_at: Optional[datetime] = None
    permissions: Optional[List[str]] = Field(default_factory=list)
    reason: Optional[str] = None

class SessionInfo(BaseModel):
    """Schema para información de sesión"""
    token_id: str
    created_at: datetime
    last_activity: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    is_current: bool = False

class ActiveSessionsResponse(BaseModel):
    """Schema para respuesta de sesiones activas"""
    sessions: List[SessionInfo]
    total: int

class RevokeSessionRequest(BaseModel):
    """Schema para revocar sesión"""
    token_id: str = Field(..., description="ID del token a revocar")

class RevokeSessionResponse(BaseModel):
    """Schema para respuesta de revocación de sesión"""
    message: str = "Sesión revocada exitosamente"
    revoked_at: datetime

# === MIDDLEWARE DE AUTENTICACIÓN ===

class AuthContext(BaseModel):
    """Schema para contexto de autenticación"""
    user_id: UUID
    email: str
    rol: str
    permisos: List[str]
    empleado_id: Optional[UUID] = None
    session_id: str
    
    model_config = {
        'from_attributes': True
    }

# === ERRORES DE AUTENTICACIÓN ===

class AuthError(BaseModel):
    """Schema para errores de autenticación"""
    error: str
    error_description: str
    error_code: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class AuthErrorResponse(BaseModel):
    """Schema para respuesta de error de autenticación"""
    detail: AuthError
    status_code: int = 401

# === AUDITORÍA ===

class AuthAuditLog(BaseModel):
    """Schema para logs de auditoría de autenticación"""
    event: str
    user_id: Optional[UUID] = None
    email: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    success: bool
    reason: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

# === PERMISOS ===

class PermissionCheck(BaseModel):
    """Schema para verificación de permisos"""
    permission: str
    resource: Optional[str] = None
    action: Optional[str] = None

class PermissionResponse(BaseModel):
    """Schema para respuesta de verificación de permisos"""
    has_permission: bool
    permission: str
    reason: Optional[str] = None

# Importar UsuarioResponse para evitar referencias circulares
# Esto debe ir al final para evitar import circular
try:
    from app.presentation.schemas.usuario import UsuarioResponse
    AuthResponse.model_rebuild()
except ImportError:
    # Si hay import circular, se resolverá más tarde
    pass