from typing import Optional, List, Dict, Any, Tuple
from uuid import UUID
from datetime import datetime, timedelta
import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.repositories.usuario import usuario_repository
from app.infrastructure.database.repositories.empleado import empleado_repository
from app.infrastructure.database.models.usuario import Usuario, RolEnum, EstadoUsuarioEnum
from app.presentation.schemas.usuario import (
    UsuarioCreate, UsuarioUpdate, UsuarioUpdatePassword
)
from app.core.exceptions import (
    NotFoundError, ValidationError, BusinessError, ConflictError, AuthenticationError
)
from app.core.security import security_manager

logger = logging.getLogger(__name__)

class UsuarioService:
    """Servicio de dominio para operaciones de Usuario"""
    
    def __init__(self):
        self.repository = usuario_repository
        self.empleado_repository = empleado_repository
    
    # === OPERACIONES CRUD ===
    
    async def create_usuario(
        self, 
        db: AsyncSession, 
        usuario_data: UsuarioCreate,
        created_by: Optional[UUID] = None
    ) -> Usuario:
        """
        Crear un nuevo usuario con validaciones de negocio
        
        Args:
            db: Sesión de base de datos
            usuario_data: Datos del usuario
            created_by: ID del usuario que crea
            
        Returns:
            Usuario creado
            
        Raises:
            ConflictError: Si el email o username ya existe
            ValidationError: Si los datos son inválidos
            NotFoundError: Si el empleado_id no existe
        """
        try:
            # Validar que el email no exista
            existing_user = await self.repository.get_by_email(db, usuario_data.email)
            if existing_user:
                raise ConflictError(f"Ya existe un usuario con el email: {usuario_data.email}")
            
            # Validar username si se proporciona
            if usuario_data.username:
                existing_username = await self.repository.get_by_username(db, usuario_data.username)
                if existing_username:
                    raise ConflictError(f"Ya existe un usuario con el username: {usuario_data.username}")
            
            # Validar empleado_id si se proporciona
            if usuario_data.empleado_id:
                empleado = await self.empleado_repository.get_by_id(db, usuario_data.empleado_id)
                if not empleado:
                    raise NotFoundError("Empleado", str(usuario_data.empleado_id))
                
                # Verificar que el empleado no tenga ya un usuario
                existing_usuario_empleado = await self.repository.get_by_empleado_id(db, usuario_data.empleado_id)
                if existing_usuario_empleado:
                    raise ConflictError(f"El empleado ya tiene un usuario asignado")
            
            # Validar permisos para crear usuarios con ciertos roles
            await self._validate_role_assignment(db, usuario_data.rol, created_by)
            
            # Crear usuario
            usuario = await self.repository.create_usuario(db, usuario_data, created_by)
            
            logger.info(f"Usuario creado exitosamente: {usuario.email} (ID: {usuario.id})")
            return usuario
            
        except (ConflictError, ValidationError, NotFoundError) as e:
            raise e
        except Exception as e:
            logger.error(f"Error creando usuario: {e}")
            raise BusinessError(f"Error interno creando usuario")
    
    async def get_by_id(self, db: AsyncSession, usuario_id: UUID) -> Optional[Usuario]:
        """Obtener usuario por ID"""
        try:
            usuario = await self.repository.get_by_id(db, usuario_id)
            if usuario:
                logger.debug(f"Usuario obtenido: {usuario_id}")
            return usuario
            
        except Exception as e:
            logger.error(f"Error obteniendo usuario {usuario_id}: {e}")
            return None
    
    async def get_by_email(self, db: AsyncSession, email: str) -> Optional[Usuario]:
        """Obtener usuario por email"""
        try:
            return await self.repository.get_by_email(db, email)
        except Exception as e:
            logger.error(f"Error obteniendo usuario por email {email}: {e}")
            return None
    
    async def update_usuario(
        self, 
        db: AsyncSession, 
        usuario_id: UUID, 
        usuario_data: UsuarioUpdate,
        updated_by: Optional[UUID] = None
    ) -> Optional[Usuario]:
        """
        Actualizar usuario con validaciones
        
        Args:
            db: Sesión de base de datos
            usuario_id: ID del usuario a actualizar
            usuario_data: Datos de actualización
            updated_by: ID del usuario que actualiza
            
        Returns:
            Usuario actualizado o None si no se encontró
        """
        try:
            # Verificar que el usuario existe
            usuario = await self.repository.get_by_id(db, usuario_id)
            if not usuario:
                raise NotFoundError("Usuario", str(usuario_id))
            
            # Validar email único si se está actualizando
            if usuario_data.email and usuario_data.email != usuario.email:
                existing_email = await self.repository.get_by_email(db, usuario_data.email)
                if existing_email and existing_email.id != usuario_id:
                    raise ConflictError(f"Ya existe un usuario con el email: {usuario_data.email}")
            
            # Validar username único si se está actualizando
            if usuario_data.username and usuario_data.username != usuario.username:
                existing_username = await self.repository.get_by_username(db, usuario_data.username)
                if existing_username and existing_username.id != usuario_id:
                    raise ConflictError(f"Ya existe un usuario con el username: {usuario_data.username}")
            
            # Validar cambio de rol
            if usuario_data.rol and usuario_data.rol != usuario.rol:
                await self._validate_role_assignment(db, usuario_data.rol, updated_by)
            
            # Validar empleado_id si se está actualizando
            if usuario_data.empleado_id and usuario_data.empleado_id != usuario.empleado_id:
                empleado = await self.empleado_repository.get_by_id(db, usuario_data.empleado_id)
                if not empleado:
                    raise NotFoundError("Empleado", str(usuario_data.empleado_id))
                
                existing_usuario_empleado = await self.repository.get_by_empleado_id(db, usuario_data.empleado_id)
                if existing_usuario_empleado and existing_usuario_empleado.id != usuario_id:
                    raise ConflictError(f"El empleado ya tiene un usuario asignado")
            
            # Actualizar
            update_data = usuario_data.model_dump(exclude_unset=True)
            update_data['updated_by'] = updated_by
            
            updated_usuario = await self.repository.update(db, usuario_id, update_data)
            
            if updated_usuario:
                logger.info(f"Usuario actualizado: {usuario_id}")
            
            return updated_usuario
            
        except (ConflictError, ValidationError, NotFoundError) as e:
            raise e
        except Exception as e:
            logger.error(f"Error actualizando usuario {usuario_id}: {e}")
            raise BusinessError("Error interno actualizando usuario")
    
    async def deactivate_usuario(
        self, 
        db: AsyncSession, 
        usuario_id: UUID,
        updated_by: Optional[UUID] = None
    ) -> bool:
        """
        Desactivar usuario (no eliminar físicamente)
        
        Args:
            db: Sesión de base de datos
            usuario_id: ID del usuario
            updated_by: ID del usuario que desactiva
            
        Returns:
            True si se desactivó exitosamente
        """
        try:
            usuario = await self.repository.get_by_id(db, usuario_id)
            if not usuario:
                raise NotFoundError("Usuario", str(usuario_id))
            
            # No permitir auto-desactivación de super admins
            if usuario.rol == RolEnum.SUPER_ADMIN and usuario_id == updated_by:
                raise BusinessError("No puedes desactivar tu propia cuenta de super administrador")
            
            # Invalidar todas las sesiones
            await self.repository.invalidate_all_tokens(db, usuario_id)
            
            # Desactivar
            update_data = {
                "is_active": False,
                "estado": EstadoUsuarioEnum.INACTIVO,
                "updated_by": updated_by
            }
            
            updated_usuario = await self.repository.update(db, usuario_id, update_data)
            
            if updated_usuario:
                logger.info(f"Usuario desactivado: {usuario_id}")
                return True
            
            return False
            
        except (NotFoundError, BusinessError) as e:
            raise e
        except Exception as e:
            logger.error(f"Error desactivando usuario {usuario_id}: {e}")
            raise BusinessError("Error interno desactivando usuario")
    
    # === AUTENTICACIÓN ===
    
    async def authenticate_user(
        self, 
        db: AsyncSession, 
        email: str, 
        password: str
    ) -> Tuple[Optional[Usuario], str]:
        """
        Autenticar usuario
        
        Args:
            db: Sesión de base de datos
            email: Email del usuario
            password: Contraseña
            
        Returns:
            Tupla (usuario, mensaje)
        """
        try:
            usuario = await self.repository.authenticate(db, email, password)
            
            if not usuario:
                return None, "Credenciales inválidas"
            
            if not usuario.is_active:
                return None, "Usuario inactivo"
            
            if usuario.estado != EstadoUsuarioEnum.ACTIVO:
                return None, f"Usuario {usuario.estado.value}"
            
            if usuario.is_blocked:
                tiempo_restante = ""
                if usuario.bloqueado_hasta:
                    minutos = int((usuario.bloqueado_hasta - datetime.utcnow()).total_seconds() / 60)
                    tiempo_restante = f" (desbloqueado en {minutos} minutos)"
                return None, f"Usuario bloqueado{tiempo_restante}"
            
            logger.info(f"Autenticación exitosa para: {email}")
            return usuario, "Autenticación exitosa"
            
        except Exception as e:
            logger.error(f"Error en autenticación: {e}")
            return None, "Error interno de autenticación"
    
    async def change_password(
        self, 
        db: AsyncSession, 
        usuario_id: UUID, 
        password_data: UsuarioUpdatePassword
    ) -> bool:
        """
        Cambiar contraseña del usuario
        
        Args:
            db: Sesión de base de datos
            usuario_id: ID del usuario
            password_data: Datos del cambio de contraseña
            
        Returns:
            True si se cambió exitosamente
        """
        try:
            usuario = await self.repository.get_by_id(db, usuario_id)
            if not usuario:
                raise NotFoundError("Usuario", str(usuario_id))
            
            # Verificar contraseña actual
            if not security_manager.verify_password(password_data.password_actual, usuario.hashed_password):
                raise AuthenticationError("Contraseña actual incorrecta")
            
            # Cambiar contraseña
            success = await self.repository.update_password(
                db, usuario_id, password_data.password_nuevo, usuario_id
            )
            
            if success:
                # Invalidar todas las sesiones excepto la actual
                await self.repository.invalidate_all_tokens(db, usuario_id)
                logger.info(f"Contraseña cambiada para usuario: {usuario_id}")
            
            return success
            
        except (NotFoundError, AuthenticationError) as e:
            raise e
        except Exception as e:
            logger.error(f"Error cambiando contraseña: {e}")
            raise BusinessError("Error interno cambiando contraseña")
    
    async def reset_password(
        self, 
        db: AsyncSession, 
        email: str
    ) -> str:
        """
        Generar token de reset de contraseña
        
        Args:
            db: Sesión de base de datos
            email: Email del usuario
            
        Returns:
            Token de reset
        """
        try:
            usuario = await self.repository.get_by_email(db, email)
            if not usuario:
                # Por seguridad, no revelar si el email existe
                logger.warning(f"Solicitud de reset para email inexistente: {email}")
                return security_manager.generate_password_reset_token("dummy@email.com")
            
            if not usuario.is_active:
                raise BusinessError("Usuario inactivo")
            
            token = security_manager.generate_password_reset_token(email)
            logger.info(f"Token de reset generado para: {email}")
            
            return token
            
        except BusinessError as e:
            raise e
        except Exception as e:
            logger.error(f"Error generando token de reset: {e}")
            raise BusinessError("Error interno generando token de reset")
    
    async def confirm_password_reset(
        self, 
        db: AsyncSession, 
        token: str, 
        new_password: str
    ) -> bool:
        """
        Confirmar reset de contraseña con token
        
        Args:
            db: Sesión de base de datos
            token: Token de reset
            new_password: Nueva contraseña
            
        Returns:
            True si se reseteo exitosamente
        """
        try:
            email = security_manager.verify_password_reset_token(token)
            if not email:
                raise ValidationError("Token de reset inválido o expirado")
            
            usuario = await self.repository.get_by_email(db, email)
            if not usuario:
                raise NotFoundError("Usuario", email)
            
            # Cambiar contraseña
            success = await self.repository.update_password(db, usuario.id, new_password)
            
            if success:
                # Invalidar todas las sesiones
                await self.repository.invalidate_all_tokens(db, usuario.id)
                logger.info(f"Contraseña reseteada para: {email}")
            
            return success
            
        except (ValidationError, NotFoundError) as e:
            raise e
        except Exception as e:
            logger.error(f"Error confirmando reset de contraseña: {e}")
            raise BusinessError("Error interno reseteando contraseña")
    
    # === GESTIÓN DE PERMISOS ===
    
    async def add_permission(
        self, 
        db: AsyncSession, 
        usuario_id: UUID, 
        permission: str,
        granted_by: Optional[UUID] = None
    ) -> bool:
        """Agregar permiso a usuario"""
        try:
            usuario = await self.repository.get_by_id(db, usuario_id)
            if not usuario:
                raise NotFoundError("Usuario", str(usuario_id))
            
            usuario.agregar_permiso(permission)
            
            update_data = {
                "permisos_adicionales": usuario.permisos_adicionales,
                "updated_by": granted_by
            }
            
            updated_usuario = await self.repository.update(db, usuario_id, update_data)
            
            if updated_usuario:
                logger.info(f"Permiso '{permission}' agregado a usuario: {usuario_id}")
                return True
            
            return False
            
        except NotFoundError as e:
            raise e
        except Exception as e:
            logger.error(f"Error agregando permiso: {e}")
            raise BusinessError("Error interno agregando permiso")
    
    async def remove_permission(
        self, 
        db: AsyncSession, 
        usuario_id: UUID, 
        permission: str,
        revoked_by: Optional[UUID] = None
    ) -> bool:
        """Remover permiso de usuario"""
        try:
            usuario = await self.repository.get_by_id(db, usuario_id)
            if not usuario:
                raise NotFoundError("Usuario", str(usuario_id))
            
            usuario.remover_permiso(permission)
            
            update_data = {
                "permisos_adicionales": usuario.permisos_adicionales,
                "updated_by": revoked_by
            }
            
            updated_usuario = await self.repository.update(db, usuario_id, update_data)
            
            if updated_usuario:
                logger.info(f"Permiso '{permission}' removido de usuario: {usuario_id}")
                return True
            
            return False
            
        except NotFoundError as e:
            raise e
        except Exception as e:
            logger.error(f"Error removiendo permiso: {e}")
            raise BusinessError("Error interno removiendo permiso")
    
    # === CONSULTAS AVANZADAS ===
    
    async def search_usuarios(
        self,
        db: AsyncSession,
        search_term: str = "",
        rol: Optional[RolEnum] = None,
        estado: Optional[EstadoUsuarioEnum] = None,
        page: int = 1,
        size: int = 10
    ) -> Dict[str, Any]:
        """Búsqueda avanzada de usuarios"""
        try:
            return await self.repository.search_usuarios(
                db, search_term, rol, estado, page, size
            )
        except Exception as e:
            logger.error(f"Error en búsqueda de usuarios: {e}")
            return {
                "items": [],
                "total": 0,
                "page": page,
                "size": size,
                "pages": 0,
                "has_next": False,
                "has_prev": False
            }
    
    async def get_users_by_role(
        self, 
        db: AsyncSession, 
        rol: RolEnum,
        include_inactive: bool = False
    ) -> List[Usuario]:
        """Obtener usuarios por rol"""
        try:
            return await self.repository.get_users_by_rol(db, rol, include_inactive)
        except Exception as e:
            logger.error(f"Error obteniendo usuarios por rol: {e}")
            return []
    
    async def get_inactive_users(self, db: AsyncSession, days: int = 30) -> List[Usuario]:
        """Obtener usuarios inactivos por días"""
        try:
            return await self.repository.get_usuarios_sin_acceso_reciente(db, days)
        except Exception as e:
            logger.error(f"Error obteniendo usuarios inactivos: {e}")
            return []
    
    async def get_estadisticas(self, db: AsyncSession) -> Dict[str, Any]:
        """Obtener estadísticas de usuarios"""
        try:
            return await self.repository.get_estadisticas_usuarios(db)
        except Exception as e:
            logger.error(f"Error obteniendo estadísticas: {e}")
            return {}
    
    # === MÉTODOS AUXILIARES ===
    
    async def _validate_role_assignment(
        self, 
        db: AsyncSession, 
        rol: RolEnum,
        assigned_by: Optional[UUID]
    ) -> None:
        """
        Validar que el usuario que asigna tiene permisos para el rol
        
        Args:
            db: Sesión de base de datos
            rol: Rol a asignar
            assigned_by: ID del usuario que asigna
            
        Raises:
            BusinessError: Si no tiene permisos
        """
        if not assigned_by:
            return  # Sistema puede asignar cualquier rol
        
        asignador = await self.repository.get_by_id(db, assigned_by)
        if not asignador:
            raise BusinessError("Usuario asignador no encontrado")
        
        # Solo super admins pueden crear otros super admins
        if rol == RolEnum.SUPER_ADMIN and asignador.rol != RolEnum.SUPER_ADMIN:
            raise BusinessError("Solo super administradores pueden asignar el rol de super administrador")
        
        # Solo admins o superior pueden crear admins
        if rol == RolEnum.ADMIN and not asignador.is_admin:
            raise BusinessError("Solo administradores pueden asignar el rol de administrador")
        
        # Solo supervisores o superior pueden crear supervisores
        if rol == RolEnum.SUPERVISOR and not asignador.is_supervisor:
            raise BusinessError("Solo supervisores o superior pueden asignar el rol de supervisor")
    
    async def validate_usuario_exists(self, db: AsyncSession, usuario_id: UUID) -> bool:
        """Validar que un usuario existe y está activo"""
        usuario = await self.repository.get_by_id(db, usuario_id)
        return usuario is not None and usuario.is_active

# Instancia global del servicio
usuario_service = UsuarioService()