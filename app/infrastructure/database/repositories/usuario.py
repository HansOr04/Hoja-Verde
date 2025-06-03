from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime, timedelta
from sqlalchemy import select, update, delete, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, joinedload
import logging

from app.infrastructure.database.repositories.base import BaseRepository
from app.infrastructure.database.models.usuario import Usuario, HistorialPassword, RolEnum, EstadoUsuarioEnum
from app.infrastructure.database.models.empleado import Empleado
from app.presentation.schemas.usuario import UsuarioCreate, UsuarioUpdate

logger = logging.getLogger(__name__)

class UsuarioRepository(BaseRepository[Usuario, UsuarioCreate, UsuarioUpdate]):
    """Repositorio para operaciones de Usuario"""
    
    def __init__(self):
        super().__init__(Usuario)
    
    # === OPERACIONES BÁSICAS ===
    
    async def create_usuario(
        self, 
        db: AsyncSession, 
        usuario_data: UsuarioCreate,
        created_by: Optional[UUID] = None
    ) -> Usuario:
        """
        Crear un nuevo usuario
        
        Args:
            db: Sesión de base de datos
            usuario_data: Datos del usuario
            created_by: ID del usuario que crea
            
        Returns:
            Usuario creado
        """
        try:
            from app.core.security import security_manager
            
            # Crear usuario
            usuario_dict = usuario_data.model_dump(exclude={'password'})
            usuario_dict['hashed_password'] = security_manager.hash_password(usuario_data.password)
            usuario_dict['created_by'] = created_by
            
            usuario = Usuario(**usuario_dict)
            db.add(usuario)
            await db.flush()
            
            # Guardar en historial de passwords
            historial = HistorialPassword(
                usuario_id=usuario.id,
                password_hash=usuario.hashed_password
            )
            db.add(historial)
            
            await db.commit()
            await db.refresh(usuario)
            
            logger.info(f"Usuario creado: {usuario.email} (ID: {usuario.id})")
            return usuario
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error creando usuario: {e}")
            raise
    
    async def get_by_email(self, db: AsyncSession, email: str) -> Optional[Usuario]:
        """Obtener usuario por email"""
        try:
            query = select(Usuario).where(
                Usuario.email == email.lower().strip()
            ).options(
                joinedload(Usuario.empleado)
            )
            
            result = await db.execute(query)
            usuario = result.scalar_one_or_none()
            
            if usuario:
                logger.debug(f"Usuario encontrado por email: {email}")
            
            return usuario
            
        except Exception as e:
            logger.error(f"Error obteniendo usuario por email {email}: {e}")
            return None
    
    async def get_by_username(self, db: AsyncSession, username: str) -> Optional[Usuario]:
        """Obtener usuario por username"""
        try:
            query = select(Usuario).where(
                Usuario.username == username.lower().strip()
            ).options(
                joinedload(Usuario.empleado)
            )
            
            result = await db.execute(query)
            return result.scalar_one_or_none()
            
        except Exception as e:
            logger.error(f"Error obteniendo usuario por username {username}: {e}")
            return None
    
    async def get_by_empleado_id(self, db: AsyncSession, empleado_id: UUID) -> Optional[Usuario]:
        """Obtener usuario por ID de empleado"""
        try:
            query = select(Usuario).where(
                Usuario.empleado_id == empleado_id
            ).options(
                joinedload(Usuario.empleado)
            )
            
            result = await db.execute(query)
            return result.scalar_one_or_none()
            
        except Exception as e:
            logger.error(f"Error obteniendo usuario por empleado_id {empleado_id}: {e}")
            return None
    
    # === OPERACIONES DE AUTENTICACIÓN ===
    
    async def authenticate(
        self, 
        db: AsyncSession, 
        email: str, 
        password: str
    ) -> Optional[Usuario]:
        """
        Autenticar usuario con email y contraseña
        
        Args:
            db: Sesión de base de datos
            email: Email del usuario
            password: Contraseña en texto plano
            
        Returns:
            Usuario si la autenticación es exitosa, None si no
        """
        try:
            from app.core.security import security_manager
            
            usuario = await self.get_by_email(db, email)
            
            if not usuario:
                logger.warning(f"Intento de login con email inexistente: {email}")
                return None
            
            # Verificar si está bloqueado
            if usuario.is_blocked:
                logger.warning(f"Intento de login con usuario bloqueado: {email}")
                return None
            
            # Verificar contraseña
            if not security_manager.verify_password(password, usuario.hashed_password):
                # Registrar intento fallido
                usuario.registrar_intento_fallido()
                await db.commit()
                logger.warning(f"Contraseña incorrecta para usuario: {email}")
                return None
            
            # Autenticación exitosa
            usuario.registrar_acceso_exitoso()
            await db.commit()
            
            logger.info(f"Autenticación exitosa para usuario: {email}")
            return usuario
            
        except Exception as e:
            logger.error(f"Error en autenticación para {email}: {e}")
            return None
    
    async def update_password(
        self, 
        db: AsyncSession, 
        usuario_id: UUID, 
        new_password: str,
        updated_by: Optional[UUID] = None
    ) -> bool:
        """
        Actualizar contraseña de usuario
        
        Args:
            db: Sesión de base de datos
            usuario_id: ID del usuario
            new_password: Nueva contraseña en texto plano
            updated_by: ID del usuario que actualiza
            
        Returns:
            True si se actualizó exitosamente
        """
        try:
            from app.core.security import security_manager
            
            # Verificar que no sea una contraseña usada recientemente
            if await self._is_password_recently_used(db, usuario_id, new_password):
                logger.warning(f"Intento de reusar contraseña reciente para usuario: {usuario_id}")
                return False
            
            # Hashear nueva contraseña
            new_hash = security_manager.hash_password(new_password)
            
            # Actualizar usuario
            query = update(Usuario).where(
                Usuario.id == usuario_id
            ).values(
                hashed_password=new_hash,
                password_cambiado_en=func.now(),
                debe_cambiar_password=False,
                updated_by=updated_by,
                updated_at=func.now()
            )
            
            result = await db.execute(query)
            
            if result.rowcount > 0:
                # Agregar al historial
                historial = HistorialPassword(
                    usuario_id=usuario_id,
                    password_hash=new_hash
                )
                db.add(historial)
                
                await db.commit()
                logger.info(f"Contraseña actualizada para usuario: {usuario_id}")
                return True
            
            return False
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error actualizando contraseña para usuario {usuario_id}: {e}")
            return False
    
    async def _is_password_recently_used(
        self, 
        db: AsyncSession, 
        usuario_id: UUID, 
        password: str,
        check_last_n: int = 5
    ) -> bool:
        """
        Verificar si una contraseña fue usada recientemente
        
        Args:
            db: Sesión de base de datos
            usuario_id: ID del usuario
            password: Contraseña a verificar
            check_last_n: Cantidad de contraseñas recientes a verificar
            
        Returns:
            True si la contraseña fue usada recientemente
        """
        try:
            from app.core.security import security_manager
            
            # Obtener últimas contraseñas
            query = select(HistorialPassword.password_hash).where(
                HistorialPassword.usuario_id == usuario_id
            ).order_by(
                HistorialPassword.fecha_cambio.desc()
            ).limit(check_last_n)
            
            result = await db.execute(query)
            hashes_recientes = [row[0] for row in result.fetchall()]
            
            # Verificar contra cada hash reciente
            for hash_reciente in hashes_recientes:
                if security_manager.verify_password(password, hash_reciente):
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error verificando historial de contraseñas: {e}")
            return False
    
    # === OPERACIONES DE SESIÓN ===
    
    async def add_active_token(
        self, 
        db: AsyncSession, 
        usuario_id: UUID, 
        token_jti: str
    ) -> bool:
        """Agregar token a la lista de tokens activos"""
        try:
            usuario = await self.get_by_id(db, usuario_id)
            if usuario:
                usuario.agregar_token_activo(token_jti)
                await db.commit()
                return True
            return False
            
        except Exception as e:
            logger.error(f"Error agregando token activo: {e}")
            return False
    
    async def remove_active_token(
        self, 
        db: AsyncSession, 
        usuario_id: UUID, 
        token_jti: str
    ) -> bool:
        """Remover token de la lista de tokens activos"""
        try:
            usuario = await self.get_by_id(db, usuario_id)
            if usuario:
                usuario.remover_token_activo(token_jti)
                await db.commit()
                return True
            return False
            
        except Exception as e:
            logger.error(f"Error removiendo token activo: {e}")
            return False
    
    async def invalidate_all_tokens(self, db: AsyncSession, usuario_id: UUID) -> bool:
        """Invalidar todos los tokens del usuario"""
        try:
            usuario = await self.get_by_id(db, usuario_id)
            if usuario:
                usuario.invalidar_todos_los_tokens()
                await db.commit()
                logger.info(f"Todos los tokens invalidados para usuario: {usuario_id}")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Error invalidando tokens: {e}")
            return False
    
    # === CONSULTAS AVANZADAS ===
    
    async def get_users_by_rol(
        self, 
        db: AsyncSession, 
        rol: RolEnum,
        include_inactive: bool = False
    ) -> List[Usuario]:
        """Obtener usuarios por rol"""
        try:
            query = select(Usuario).where(Usuario.rol == rol)
            
            if not include_inactive:
                query = query.where(
                    and_(
                        Usuario.is_active == True,
                        Usuario.estado == EstadoUsuarioEnum.ACTIVO
                    )
                )
            
            query = query.options(joinedload(Usuario.empleado))
            
            result = await db.execute(query)
            return result.scalars().all()
            
        except Exception as e:
            logger.error(f"Error obteniendo usuarios por rol {rol}: {e}")
            return []
    
    async def search_usuarios(
        self,
        db: AsyncSession,
        search_term: str,
        rol: Optional[RolEnum] = None,
        estado: Optional[EstadoUsuarioEnum] = None,
        page: int = 1,
        size: int = 10
    ) -> Dict[str, Any]:
        """Búsqueda avanzada de usuarios"""
        try:
            # Query base
            query = select(Usuario)
            
            # Filtros de búsqueda
            if search_term:
                search_filter = or_(
                    Usuario.nombres.ilike(f"%{search_term}%"),
                    Usuario.apellidos.ilike(f"%{search_term}%"),
                    Usuario.email.ilike(f"%{search_term}%"),
                    Usuario.username.ilike(f"%{search_term}%")
                )
                query = query.where(search_filter)
            
            if rol:
                query = query.where(Usuario.rol == rol)
            
            if estado:
                query = query.where(Usuario.estado == estado)
            
            # Contar total
            count_query = select(func.count()).select_from(query.subquery())
            total_result = await db.execute(count_query)
            total = total_result.scalar()
            
            # Paginación
            offset = (page - 1) * size
            query = query.offset(offset).limit(size)
            query = query.options(joinedload(Usuario.empleado))
            
            # Ejecutar consulta
            result = await db.execute(query)
            usuarios = result.scalars().all()
            
            pages = (total + size - 1) // size
            
            return {
                "items": usuarios,
                "total": total,
                "page": page,
                "size": size,
                "pages": pages,
                "has_next": page < pages,
                "has_prev": page > 1
            }
            
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
    
    async def get_usuarios_sin_acceso_reciente(
        self,
        db: AsyncSession,
        dias: int = 30
    ) -> List[Usuario]:
        """Obtener usuarios que no han accedido recientemente"""
        try:
            fecha_limite = datetime.utcnow() - timedelta(days=dias)
            
            query = select(Usuario).where(
                or_(
                    Usuario.ultimo_acceso < fecha_limite,
                    Usuario.ultimo_acceso.is_(None)
                )
            ).where(
                Usuario.is_active == True
            )
            
            result = await db.execute(query)
            return result.scalars().all()
            
        except Exception as e:
            logger.error(f"Error obteniendo usuarios sin acceso reciente: {e}")
            return []
    
    # === ESTADÍSTICAS ===
    
    async def get_estadisticas_usuarios(self, db: AsyncSession) -> Dict[str, Any]:
        """Obtener estadísticas de usuarios"""
        try:
            # Total por estado
            query_estados = select(
                Usuario.estado,
                func.count(Usuario.id).label('count')
            ).group_by(Usuario.estado)
            
            result_estados = await db.execute(query_estados)
            por_estado = {row.estado: row.count for row in result_estados}
            
            # Total por rol
            query_roles = select(
                Usuario.rol,
                func.count(Usuario.id).label('count')
            ).group_by(Usuario.rol)
            
            result_roles = await db.execute(query_roles)
            por_rol = {row.rol: row.count for row in result_roles}
            
            # Total general
            total_query = select(func.count(Usuario.id))
            total_result = await db.execute(total_query)
            total = total_result.scalar()
            
            # Usuarios activos
            activos_query = select(func.count(Usuario.id)).where(
                and_(
                    Usuario.is_active == True,
                    Usuario.estado == EstadoUsuarioEnum.ACTIVO
                )
            )
            activos_result = await db.execute(activos_query)
            activos = activos_result.scalar()
            
            return {
                "total": total,
                "activos": activos,
                "por_estado": por_estado,
                "por_rol": por_rol
            }
            
        except Exception as e:
            logger.error(f"Error obteniendo estadísticas de usuarios: {e}")
            return {}

# Instancia global del repositorio
usuario_repository = UsuarioRepository()