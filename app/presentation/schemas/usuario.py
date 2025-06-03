from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field, field_validator

from app.infrastructure.database.models.usuario import RolEnum, EstadoUsuarioEnum

# === SCHEMAS BASE ===

class UsuarioBase(BaseModel):
    """Schema base para Usuario"""
    email: EmailStr
    nombres: str = Field(..., min_length=2, max_length=100)
    apellidos: str = Field(..., min_length=2, max_length=100)
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    rol: RolEnum = RolEnum.USUARIO

class UsuarioCreate(UsuarioBase):
    """Schema para crear usuario"""
    password: str = Field(..., min_length=8, max_length=128)
    empleado_id: Optional[UUID] = None
    debe_cambiar_password: bool = False
    
    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v):
        """Validar fortaleza de la contraseña"""
        from app.core.security import security_manager
        
        is_strong, errors = security_manager.is_password_strong(v)
        if not is_strong:
            raise ValueError(f"Contraseña débil: {', '.join(errors)}")
        return v
    
    @field_validator('email')
    @classmethod
    def validate_email_format(cls, v):
        """Validaciones adicionales del email"""
        if len(v) > 255:
            raise ValueError("Email demasiado largo")
        return v.lower().strip()
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        """Validar username si se proporciona"""
        if v:
            v = v.strip().lower()
            if not v.replace('_', '').replace('.', '').isalnum():
                raise ValueError("Username solo puede contener letras, números, puntos y guiones bajos")
        return v

class UsuarioUpdate(BaseModel):
    """Schema para actualizar usuario"""
    email: Optional[EmailStr] = None
    nombres: Optional[str] = Field(None, min_length=2, max_length=100)
    apellidos: Optional[str] = Field(None, min_length=2, max_length=100)
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    rol: Optional[RolEnum] = None
    estado: Optional[EstadoUsuarioEnum] = None
    is_active: Optional[bool] = None
    permisos_adicionales: Optional[List[str]] = None
    empleado_id: Optional[UUID] = None
    
    @field_validator('email')
    @classmethod
    def validate_email_format(cls, v):
        if v:
            return v.lower().strip()
        return v

class UsuarioUpdatePassword(BaseModel):
    """Schema para cambio de contraseña"""
    password_actual: str = Field(..., min_length=1)
    password_nuevo: str = Field(..., min_length=8, max_length=128)
    confirmar_password: str = Field(..., min_length=8, max_length=128)
    
    @field_validator('confirmar_password')
    @classmethod
    def passwords_match(cls, v, info):
        if info.data.get('password_nuevo') and v != info.data['password_nuevo']:
            raise ValueError('Las contraseñas no coinciden')
        return v
    
    @field_validator('password_nuevo')
    @classmethod
    def validate_password_strength(cls, v):
        from app.core.security import security_manager
        is_strong, errors = security_manager.is_password_strong(v)
        if not is_strong:
            raise ValueError(f"Contraseña débil: {', '.join(errors)}")
        return v

class UsuarioResponse(UsuarioBase):
    """Schema de respuesta para Usuario"""
    id: UUID
    estado: EstadoUsuarioEnum
    is_active: bool
    ultimo_acceso: Optional[datetime] = None
    debe_cambiar_password: bool
    empleado_id: Optional[UUID] = None
    created_at: datetime
    updated_at: datetime
    
    # Información del empleado relacionado (si existe)
    empleado_nombres: Optional[str] = None
    empleado_apellidos: Optional[str] = None
    empleado_area: Optional[str] = None
    empleado_cargo: Optional[str] = None
    
    @property
    def nombre_completo(self) -> str:
        return f"{self.nombres} {self.apellidos}".strip()
    
    model_config = {
        'from_attributes': True
    }

# === SCHEMAS DE AUTENTICACIÓN ===

class LoginRequest(BaseModel):
    """Schema para request de login"""
    email: EmailStr
    password: str = Field(..., min_length=1)
    remember_me: bool = False
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        return v.lower().strip()

class LoginResponse(BaseModel):
    """Schema para respuesta de login"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UsuarioResponse

class RefreshTokenRequest(BaseModel):
    """Schema para refresh token"""
    refresh_token: str = Field(..., min_length=1)

class RefreshTokenResponse(BaseModel):
    """Schema para respuesta de refresh token"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class PasswordResetRequest(BaseModel):
    """Schema para solicitar reset de contraseña"""
    email: EmailStr
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        return v.lower().strip()

class PasswordResetConfirm(BaseModel):
    """Schema para confirmar reset de contraseña"""
    token: str = Field(..., min_length=1)
    password_nuevo: str = Field(..., min_length=8, max_length=128)
    confirmar_password: str = Field(..., min_length=8, max_length=128)
    
    @field_validator('confirmar_password')
    @classmethod
    def passwords_match(cls, v, info):
        if info.data.get('password_nuevo') and v != info.data['password_nuevo']:
            raise ValueError('Las contraseñas no coinciden')
        return v
    
    @field_validator('password_nuevo')
    @classmethod
    def validate_password_strength(cls, v):
        from app.core.security import security_manager
        is_strong, errors = security_manager.is_password_strong(v)
        if not is_strong:
            raise ValueError(f"Contraseña débil: {', '.join(errors)}")
        return v

# === SCHEMAS DE PERMISOS ===

class PermisosResponse(BaseModel):
    """Schema para respuesta de permisos"""
    rol: RolEnum
    permisos_adicionales: List[str]
    permisos_efectivos: List[str]
    
    model_config = {
        'from_attributes': True
    }

class AsignarPermisosRequest(BaseModel):
    """Schema para asignar permisos"""
    permisos: List[str] = Field(..., min_items=1)
    accion: str = Field(..., pattern="^(agregar|remover)$")

# === SCHEMAS DE SESIÓN ===

class SesionActiva(BaseModel):
    """Schema para sesión activa"""
    token_id: str
    fecha_creacion: datetime
    ultimo_uso: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    is_current: bool = False

class SesionesActivasResponse(BaseModel):
    """Schema para listar sesiones activas"""
    sesiones: List[SesionActiva]
    total: int

# === SCHEMAS DE AUDITORÍA ===

class EventoAuditoria(BaseModel):
    """Schema para eventos de auditoría"""
    evento: str
    usuario_id: UUID
    timestamp: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    detalles: Optional[Dict[str, Any]] = None

class AuditoriaResponse(BaseModel):
    """Schema para respuesta de auditoría"""
    eventos: List[EventoAuditoria]
    total: int
    page: int
    size: int

# === SCHEMAS DE CONFIGURACIÓN ===

class ConfiguracionUsuario(BaseModel):
    """Schema para configuraciones del usuario"""
    tema: str = "light"
    idioma: str = "es"
    zona_horaria: str = "America/Guayaquil"
    notificaciones_email: bool = True
    notificaciones_push: bool = True
    formato_fecha: str = "DD/MM/YYYY"
    formato_hora: str = "24h"
    
class ActualizarConfiguracion(BaseModel):
    """Schema para actualizar configuraciones"""
    configuraciones: ConfiguracionUsuario

# === VALIDADORES GLOBALES ===

def validate_permisos_list(permisos: List[str]) -> List[str]:
    """Validar lista de permisos"""
    permisos_validos = [
        # Empleados
        "empleados.crear", "empleados.leer", "empleados.actualizar", "empleados.eliminar",
        # Usuarios
        "usuarios.crear", "usuarios.leer", "usuarios.actualizar", "usuarios.eliminar",
        # Registros
        "registros.crear", "registros.leer", "registros.actualizar", "registros.eliminar",
        # Reportes
        "reportes.generar", "reportes.exportar", "reportes.avanzados",
        # Configuración
        "configuracion.leer", "configuracion.actualizar",
        # Auditoría
        "auditoria.leer", "auditoria.exportar"
    ]
    
    permisos_invalidos = [p for p in permisos if p not in permisos_validos]
    if permisos_invalidos:
        raise ValueError(f"Permisos inválidos: {', '.join(permisos_invalidos)}")
    
    return permisos

class AsignarPermisosRequestWithValidator(AsignarPermisosRequest):
    @field_validator('permisos')
    @classmethod
    def validate_permisos(cls, v):
        return validate_permisos_list(v)

AsignarPermisosRequest = AsignarPermisosRequestWithValidator