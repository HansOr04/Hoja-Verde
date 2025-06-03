from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text, Enum, Index, Integer
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
import enum
from datetime import datetime, timedelta

from app.infrastructure.database.base import Base
class RolEnum(str, enum.Enum):
    """Roles del sistema"""
    SUPER_ADMIN = "super_admin"      # Acceso total al sistema
    ADMIN = "admin"                  # Administrador general
    SUPERVISOR = "supervisor"        # Supervisor de área
    RECURSOS_HUMANOS = "rrhh"       # Personal de recursos humanos
    USUARIO = "usuario"              # Usuario básico (empleado)

class EstadoUsuarioEnum(str, enum.Enum):
    """Estados del usuario"""
    ACTIVO = "activo"
    INACTIVO = "inactivo"
    SUSPENDIDO = "suspendido"
    BLOQUEADO = "bloqueado"

class Usuario(Base):
    """
    Modelo de Usuario del sistema
    
    Representa a los usuarios que pueden acceder al sistema,
    incluyendo empleados y personal administrativo.
    """
    __tablename__ = "usuarios"
    
    # Identificación
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(50), unique=True, index=True, nullable=True)
    
    # Autenticación
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    estado = Column(Enum(EstadoUsuarioEnum), default=EstadoUsuarioEnum.ACTIVO, nullable=False)
    
    # Roles y permisos
    rol = Column(Enum(RolEnum), default=RolEnum.USUARIO, nullable=False)
    permisos_adicionales = Column(ARRAY(String), default=list, nullable=False)
    
    # Información personal
    nombres = Column(String(100), nullable=False)
    apellidos = Column(String(100), nullable=False)
    
    # Relación con empleado (si aplica)
    empleado_id = Column(UUID(as_uuid=True), ForeignKey("empleados.id"), nullable=True, unique=True)
    empleado = relationship("Empleado", back_populates="usuario", lazy="joined")
    
    # Configuraciones del usuario
    configuraciones = Column(Text, nullable=True)  # JSON con configuraciones personales
    ultimo_acceso = Column(DateTime(timezone=True), nullable=True)
    
    # Seguridad
    intentos_fallidos = Column(Integer, default=0, nullable=False)
    bloqueado_hasta = Column(DateTime(timezone=True), nullable=True)
    debe_cambiar_password = Column(Boolean, default=False, nullable=False)
    password_cambiado_en = Column(DateTime(timezone=True), nullable=True)
    
    # Tokens de sesión activos (para invalidar sesiones)
    tokens_activos = Column(ARRAY(String), default=list, nullable=False)
    
    # Auditoría
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    created_by = Column(UUID(as_uuid=True), ForeignKey("usuarios.id"), nullable=True)
    updated_by = Column(UUID(as_uuid=True), ForeignKey("usuarios.id"), nullable=True)
    
    # Relaciones de auditoría
    creator = relationship("Usuario", remote_side=[id], foreign_keys=[created_by])
    updater = relationship("Usuario", remote_side=[id], foreign_keys=[updated_by])
    
    # Índices para optimización
    __table_args__ = (
        Index('idx_usuario_email_activo', 'email', 'is_active'),
        Index('idx_usuario_rol_estado', 'rol', 'estado'),
        Index('idx_usuario_empleado', 'empleado_id'),
        Index('idx_usuario_ultimo_acceso', 'ultimo_acceso'),
    )
    
    @property
    def nombre_completo(self) -> str:
        """Obtener nombre completo del usuario"""
        return f"{self.nombres} {self.apellidos}".strip()
    
    @property
    def is_admin(self) -> bool:
        """Verificar si el usuario es administrador"""
        return self.rol in [RolEnum.SUPER_ADMIN, RolEnum.ADMIN]
    
    @property
    def is_supervisor(self) -> bool:
        """Verificar si el usuario es supervisor o superior"""
        return self.rol in [RolEnum.SUPER_ADMIN, RolEnum.ADMIN, RolEnum.SUPERVISOR]
    
    @property
    def can_manage_employees(self) -> bool:
        """Verificar si puede gestionar empleados"""
        return self.rol in [RolEnum.SUPER_ADMIN, RolEnum.ADMIN, RolEnum.RECURSOS_HUMANOS]
    
    @property
    def is_blocked(self) -> bool:
        """Verificar si el usuario está bloqueado"""
        if self.estado == EstadoUsuarioEnum.BLOQUEADO:
            return True
        if self.bloqueado_hasta and datetime.utcnow() < self.bloqueado_hasta:
            return True
        return False
    
    def tiene_permiso(self, permiso: str) -> bool:
        """
        Verificar si el usuario tiene un permiso específico
        
        Args:
            permiso: Nombre del permiso a verificar
            
        Returns:
            True si tiene el permiso
        """
        # Super admin tiene todos los permisos
        if self.rol == RolEnum.SUPER_ADMIN:
            return True
        
        # Verificar permisos adicionales
        return permiso in (self.permisos_adicionales or [])
    
    def agregar_permiso(self, permiso: str) -> None:
        """Agregar un permiso adicional al usuario"""
        if not self.permisos_adicionales:
            self.permisos_adicionales = []
        if permiso not in self.permisos_adicionales:
            self.permisos_adicionales.append(permiso)
    
    def remover_permiso(self, permiso: str) -> None:
        """Remover un permiso adicional del usuario"""
        if self.permisos_adicionales and permiso in self.permisos_adicionales:
            self.permisos_adicionales.remove(permiso)
    
    def registrar_acceso_exitoso(self) -> None:
        """Registrar un acceso exitoso y limpiar intentos fallidos"""
        self.ultimo_acceso = func.now()
        self.intentos_fallidos = 0
        self.bloqueado_hasta = None
    
    def registrar_intento_fallido(self) -> None:
        """Registrar un intento de acceso fallido"""
        self.intentos_fallidos = (self.intentos_fallidos or 0) + 1
        
        # Bloquear después de 5 intentos fallidos
        if self.intentos_fallidos >= 5:
            self.bloqueado_hasta = func.now() + timedelta(minutes=15)
            self.estado = EstadoUsuarioEnum.BLOQUEADO
    
    def agregar_token_activo(self, token_jti: str) -> None:
        """Agregar un token a la lista de tokens activos"""
        if not self.tokens_activos:
            self.tokens_activos = []
        if token_jti not in self.tokens_activos:
            self.tokens_activos.append(token_jti)
    
    def remover_token_activo(self, token_jti: str) -> None:
        """Remover un token de la lista de tokens activos"""
        if self.tokens_activos and token_jti in self.tokens_activos:
            self.tokens_activos.remove(token_jti)
    
    def invalidar_todos_los_tokens(self) -> None:
        """Invalidar todos los tokens activos (logout de todas las sesiones)"""
        self.tokens_activos = []
    
    def __repr__(self) -> str:
        return f"<Usuario(id={self.id}, email='{self.email}', rol='{self.rol}')>"

# Modelo para historial de cambios de contraseña (opcional, pero recomendado)
class HistorialPassword(Base):
    """Historial de cambios de contraseña para evitar reutilización"""
    __tablename__ = "historial_passwords"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    usuario_id = Column(UUID(as_uuid=True), ForeignKey("usuarios.id", ondelete="CASCADE"), nullable=False)
    password_hash = Column(String(255), nullable=False)
    fecha_cambio = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relación
    usuario = relationship("Usuario", backref="historial_passwords")
    
    # Índices
    __table_args__ = (
        Index('idx_historial_usuario_fecha', 'usuario_id', 'fecha_cambio'),
    )