from fastapi import APIRouter, Depends, Query, Path
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from uuid import UUID
import logging

from app.core.database import get_db
from app.core.auth import (
    get_auth_context, AuthContext, require_admin, require_supervisor
)
from app.domain.services.usuario import usuario_service
from app.infrastructure.database.models.usuario import RolEnum, EstadoUsuarioEnum
from app.presentation.schemas.usuario import (
    UsuarioCreate, UsuarioUpdate, UsuarioResponse, UsuarioUpdatePassword,
    AsignarPermisosRequest, PermisosResponse
)
from app.presentation.schemas.base import PaginatedResponse, PaginationParams
from app.core.exceptions import NotFoundError, AuthorizationError

logger = logging.getLogger(__name__)
router = APIRouter()

# === CRUD DE USUARIOS ===

@router.post("/", response_model=UsuarioResponse, status_code=201)
async def crear_usuario(
    usuario_data: UsuarioCreate,
    db: AsyncSession = Depends(get_db),
    auth_context: AuthContext = Depends(require_admin())
):
    """
    Crear un nuevo usuario (solo administradores)
    
    - **email**: Email único del usuario
    - **password**: Contraseña (debe cumplir políticas de seguridad)
    - **nombres**: Nombres del usuario
    - **apellidos**: Apellidos del usuario
    - **rol**: Rol del usuario
    - **empleado_id**: ID del empleado relacionado (opcional)
    """
    logger.info(f"Creando usuario: {usuario_data.email}")
    
    usuario = await usuario_service.create_usuario(
        db, usuario_data, auth_context.user_id
    )
    
    return UsuarioResponse.model_validate(usuario)

@router.get("/", response_model=PaginatedResponse)
async def listar_usuarios(
    pagination: PaginationParams = Depends(),
    search: Optional[str] = Query(None, description="Término de búsqueda"),
    rol: Optional[RolEnum] = Query(None, description="Filtrar por rol"),
    estado: Optional[EstadoUsuarioEnum] = Query(None, description="Filtrar por estado"),
    db: AsyncSession = Depends(get_db),
    auth_context: AuthContext = Depends(require_supervisor())
):
    """
    Listar usuarios con paginación y filtros (supervisores o superior)
    """
    logger.info(f"Listando usuarios - Página: {pagination.page}")
    
    result = await usuario_service.search_usuarios(
        db,
        search_term=search or "",
        rol=rol,
        estado=estado,
        page=pagination.page,
        size=pagination.size
    )
    
    # Convertir usuarios a schemas de respuesta
    usuarios_response = [
        UsuarioResponse.model_validate(user) for user in result["items"]
    ]
    
    return PaginatedResponse(
        items=usuarios_response,
        total=result["total"],
        page=result["page"],
        size=result["size"],
        pages=result["pages"],
        has_next=result["has_next"],
        has_prev=result["has_prev"]
    )

@router.get("/{usuario_id}", response_model=UsuarioResponse)
async def obtener_usuario(
    usuario_id: UUID = Path(..., description="ID del usuario"),
    db: AsyncSession = Depends(get_db),
    auth_context: AuthContext = Depends(get_auth_context)
):
    """
    Obtener usuario por ID
    
    Los usuarios pueden ver su propia información.
    Los supervisores pueden ver usuarios de su área.
    Los administradores pueden ver cualquier usuario.
    """
    logger.info(f"Obteniendo usuario: {usuario_id}")
    
    usuario = await usuario_service.get_by_id(db, usuario_id)
    if not usuario:
        raise NotFoundError("Usuario", str(usuario_id))
    
    # Verificar permisos
    if not auth_context.is_supervisor and str(auth_context.user_id) != str(usuario_id):
        raise AuthorizationError("No tienes permisos para ver este usuario")
    
    return UsuarioResponse.model_validate(usuario)

@router.put("/{usuario_id}", response_model=UsuarioResponse)
async def actualizar_usuario(
    usuario_id: UUID = Path(..., description="ID del usuario"),
    usuario_data: UsuarioUpdate = ...,
    db: AsyncSession = Depends(get_db),
    auth_context: AuthContext = Depends(get_auth_context)
):
    """
    Actualizar usuario
    
    Los usuarios pueden actualizar su propia información básica.
    Los administradores pueden actualizar cualquier usuario.
    """
    logger.info(f"Actualizando usuario: {usuario_id}")
    
    # Verificar permisos
    can_update_others = auth_context.is_admin
    is_own_profile = str(auth_context.user_id) == str(usuario_id)
    
    if not can_update_others and not is_own_profile:
        raise AuthorizationError("No tienes permisos para actualizar este usuario")
    
    # Si no es admin, no puede cambiar ciertos campos
    if not auth_context.is_admin and is_own_profile:
        # Los usuarios solo pueden cambiar información básica
        restricted_fields = ["rol", "estado", "is_active", "permisos_adicionales"]
        update_dict = usuario_data.model_dump(exclude_unset=True)
        
        for field in restricted_fields:
            if field in update_dict:
                raise AuthorizationError(f"No tienes permisos para cambiar el campo: {field}")
    
    usuario = await usuario_service.update_usuario(
        db, usuario_id, usuario_data, auth_context.user_id
    )
    
    if not usuario:
        raise NotFoundError("Usuario", str(usuario_id))
    
    return UsuarioResponse.model_validate(usuario)

@router.delete("/{usuario_id}", status_code=204)
async def desactivar_usuario(
    usuario_id: UUID = Path(..., description="ID del usuario"),
    db: AsyncSession = Depends(get_db),
    auth_context: AuthContext = Depends(require_admin())
):
    """
    Desactivar usuario (solo administradores)
    
    No elimina físicamente el usuario, solo lo desactiva.
    """
    logger.info(f"Desactivando usuario: {usuario_id}")
    
    success = await usuario_service.deactivate_usuario(
        db, usuario_id, auth_context.user_id
    )
    
    if not success:
        raise NotFoundError("Usuario", str(usuario_id))

# === GESTIÓN DE CONTRASEÑAS ===

@router.put("/{usuario_id}/password", status_code=200)
async def cambiar_password(
    usuario_id: UUID = Path(..., description="ID del usuario"),
    password_data: UsuarioUpdatePassword = ...,
    db: AsyncSession = Depends(get_db),
    auth_context: AuthContext = Depends(get_auth_context)
):
    """
    Cambiar contraseña del usuario
    
    Los usuarios pueden cambiar su propia contraseña.
    Los administradores pueden cambiar contraseñas de otros usuarios.
    """
    logger.info(f"Cambio de contraseña para usuario: {usuario_id}")
    
    # Verificar permisos
    can_change_others = auth_context.is_admin
    is_own_password = str(auth_context.user_id) == str(usuario_id)
    
    if not can_change_others and not is_own_password:
        raise AuthorizationError("No tienes permisos para cambiar esta contraseña")
    
    # Solo el usuario puede cambiar su propia contraseña con validación de contraseña actual
    if is_own_password:
        success = await usuario_service.change_password(db, usuario_id, password_data)
    else:
        # Los admins pueden cambiar contraseñas sin validar la actual
        from app.presentation.schemas.usuario import UsuarioUpdatePassword
        admin_password_data = UsuarioUpdatePassword(
            password_actual="",  # No se valida para admins
            password_nuevo=password_data.password_nuevo,
            confirmar_password=password_data.confirmar_password
        )
        success = await usuario_service.change_password(db, usuario_id, admin_password_data)
    
    if success:
        return {"message": "Contraseña cambiada exitosamente"}
    else:
        raise NotFoundError("Usuario", str(usuario_id))

@router.post("/{usuario_id}/reset-password", status_code=200)
async def admin_reset_password(
    usuario_id: UUID = Path(..., description="ID del usuario"),
    db: AsyncSession = Depends(get_db),
    auth_context: AuthContext = Depends(require_admin())
):
    """
    Resetear contraseña de usuario (solo administradores)
    
    Genera una contraseña temporal que el usuario debe cambiar en el próximo login.
    """
    logger.info(f"Reset de contraseña por admin para usuario: {usuario_id}")
    
    usuario = await usuario_service.get_by_id(db, usuario_id)
    if not usuario:
        raise NotFoundError("Usuario", str(usuario_id))
    
    # Generar contraseña temporal
    import secrets
    import string
    temp_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
    
    # Actualizar contraseña
    success = await usuario_service.repository.update_password(
        db, usuario_id, temp_password, auth_context.user_id
    )
    
    if success:
        # Marcar que debe cambiar contraseña
        await usuario_service.repository.update(
            db, usuario_id, {"debe_cambiar_password": True}
        )
        
        return {
            "message": "Contraseña reseteada exitosamente",
            "temp_password": temp_password,  # En producción, esto se enviaría por email seguro
            "must_change": True
        }
    else:
        raise NotFoundError("Usuario", str(usuario_id))

# === GESTIÓN DE PERMISOS ===

@router.get("/{usuario_id}/permissions", response_model=PermisosResponse)
async def obtener_permisos(
    usuario_id: UUID = Path(..., description="ID del usuario"),
    db: AsyncSession = Depends(get_db),
    auth_context: AuthContext = Depends(require_supervisor())
):
    """
    Obtener permisos de un usuario (supervisores o superior)
    """
    logger.info(f"Obteniendo permisos para usuario: {usuario_id}")
    
    usuario = await usuario_service.get_by_id(db, usuario_id)
    if not usuario:
        raise NotFoundError("Usuario", str(usuario_id))
    
    # Calcular permisos efectivos
    permisos_base_por_rol = {
        RolEnum.SUPER_ADMIN: ["*"],  # Todos los permisos
        RolEnum.ADMIN: ["empleados.*", "usuarios.*", "reportes.*"],
        RolEnum.SUPERVISOR: ["empleados.leer", "reportes.leer"],
        RolEnum.RECURSOS_HUMANOS: ["empleados.*", "reportes.empleados"],
        RolEnum.USUARIO: ["empleados.leer"]
    }
    
    permisos_efectivos = permisos_base_por_rol.get(usuario.rol, [])
    if usuario.permisos_adicionales:
        permisos_efectivos.extend(usuario.permisos_adicionales)
    
    return PermisosResponse(
        rol=usuario.rol,
        permisos_adicionales=usuario.permisos_adicionales or [],
        permisos_efectivos=list(set(permisos_efectivos))
    )

@router.post("/{usuario_id}/permissions", status_code=200)
async def gestionar_permisos(
    usuario_id: UUID = Path(..., description="ID del usuario"),
    permisos_data: AsignarPermisosRequest = ...,
    db: AsyncSession = Depends(get_db),
    auth_context: AuthContext = Depends(require_admin())
):
    """
    Agregar o remover permisos de un usuario (solo administradores)
    
    - **permisos**: Lista de permisos a gestionar
    - **accion**: "agregar" o "remover"
    """
    logger.info(f"Gestionando permisos para usuario: {usuario_id}")
    
    if permisos_data.accion == "agregar":
        for permiso in permisos_data.permisos:
            await usuario_service.add_permission(
                db, usuario_id, permiso, auth_context.user_id
            )
    elif permisos_data.accion == "remover":
        for permiso in permisos_data.permisos:
            await usuario_service.remove_permission(
                db, usuario_id, permiso, auth_context.user_id
            )
    
    return {"message": f"Permisos {permisos_data.accion}dos exitosamente"}

# === CONSULTAS ESPECIALES ===

@router.get("/roles/{rol}", response_model=list[UsuarioResponse])
async def obtener_usuarios_por_rol(
    rol: RolEnum = Path(..., description="Rol a filtrar"),
    include_inactive: bool = Query(False, description="Incluir usuarios inactivos"),
    db: AsyncSession = Depends(get_db),
    auth_context: AuthContext = Depends(require_supervisor())
):
    """
    Obtener usuarios por rol específico (supervisores o superior)
    """
    logger.info(f"Obteniendo usuarios con rol: {rol}")
    
    usuarios = await usuario_service.get_users_by_role(db, rol, include_inactive)
    
    return [UsuarioResponse.model_validate(user) for user in usuarios]

@router.get("/inactive/{days}")
async def obtener_usuarios_inactivos(
    days: int = Path(..., description="Días sin acceso", ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    auth_context: AuthContext = Depends(require_admin())
):
    """
    Obtener usuarios que no han accedido en X días (solo administradores)
    """
    logger.info(f"Obteniendo usuarios inactivos por {days} días")
    
    usuarios = await usuario_service.get_inactive_users(db, days)
    
    return {
        "days": days,
        "count": len(usuarios),
        "users": [
            {
                "id": str(user.id),
                "email": user.email,
                "nombres": user.nombres,
                "apellidos": user.apellidos,
                "ultimo_acceso": user.ultimo_acceso.isoformat() if user.ultimo_acceso else None
            }
            for user in usuarios
        ]
    }

# === ESTADÍSTICAS ===

@router.get("/stats/general")
async def obtener_estadisticas_usuarios(
    db: AsyncSession = Depends(get_db),
    auth_context: AuthContext = Depends(require_supervisor())
):
    """
    Obtener estadísticas de usuarios (supervisores o superior)
    """
    logger.info("Obteniendo estadísticas de usuarios")
    
    estadisticas = await usuario_service.get_estadisticas(db)
    
    return estadisticas

# === UTILIDADES ===

@router.post("/{usuario_id}/activate", status_code=200)
async def activar_usuario(
    usuario_id: UUID = Path(..., description="ID del usuario"),
    db: AsyncSession = Depends(get_db),
    auth_context: AuthContext = Depends(require_admin())
):
    """
    Activar usuario desactivado (solo administradores)
    """
    logger.info(f"Activando usuario: {usuario_id}")
    
    update_data = {
        "is_active": True,
        "estado": EstadoUsuarioEnum.ACTIVO,
        "intentos_fallidos": 0,
        "bloqueado_hasta": None
    }
    
    usuario = await usuario_service.update_usuario(
        db, usuario_id, UsuarioUpdate(**update_data), auth_context.user_id
    )
    
    if usuario:
        return {"message": "Usuario activado exitosamente"}
    else:
        raise NotFoundError("Usuario", str(usuario_id))

@router.post("/{usuario_id}/unlock", status_code=200)
async def desbloquear_usuario(
    usuario_id: UUID = Path(..., description="ID del usuario"),
    db: AsyncSession = Depends(get_db),
    auth_context: AuthContext = Depends(require_admin())
):
    """
    Desbloquear usuario bloqueado por intentos fallidos (solo administradores)
    """
    logger.info(f"Desbloqueando usuario: {usuario_id}")
    
    update_data = {
        "intentos_fallidos": 0,
        "bloqueado_hasta": None,
        "estado": EstadoUsuarioEnum.ACTIVO
    }
    
    usuario = await usuario_service.update_usuario(
        db, usuario_id, UsuarioUpdate(**update_data), auth_context.user_id
    )
    
    if usuario:
        return {"message": "Usuario desbloqueado exitosamente"}
    else:
        raise NotFoundError("Usuario", str(usuario_id))