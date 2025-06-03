from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID
import qrcode
import io
import base64
import secrets
import logging

from .base import BaseService
from app.infrastructure.database.repositories.empleado import EmpleadoRepository, empleado_repository
from app.infrastructure.database.models.empleado import Empleado
from app.presentation.schemas.empleado import EmpleadoCreate, EmpleadoUpdate
from app.core.exceptions import BusinessError, ValidationError

logger = logging.getLogger(__name__)

class EmpleadoService(BaseService[Empleado, EmpleadoRepository]):
    """Servicio de dominio para empleados"""
    
    def __init__(self):
        super().__init__(empleado_repository)
    
    async def create_empleado(
        self, 
        db: AsyncSession, 
        empleado_data: EmpleadoCreate,
        created_by: Optional[UUID] = None
    ) -> Empleado:
        """Crear empleado con validaciones específicas"""
        # Validar que la cédula sea única
        existing_empleado = await self.repository.get_by_cedula(db, empleado_data.cedula)
        if existing_empleado:
            raise ValidationError(f"Ya existe un empleado con la cédula {empleado_data.cedula}")
        
        # Crear empleado
        empleado = await self.repository.create(db, empleado_data, created_by)
        
        # Generar código QR
        codigo_qr = await self._generate_qr_code(empleado)
        
        # Actualizar con código QR
        await self.repository.update(
            db, 
            empleado, 
            {"codigo_qr": codigo_qr}
        )
        
        logger.info(f"Empleado creado: {empleado.nombres} {empleado.apellidos} (ID: {empleado.id})")
        return empleado
    
    async def update_empleado(
        self, 
        db: AsyncSession, 
        empleado_id: UUID, 
        empleado_data: EmpleadoUpdate,
        updated_by: Optional[UUID] = None
    ) -> Optional[Empleado]:
        """Actualizar empleado con validaciones"""
        # Verificar que existe
        empleado = await self.repository.get_by_id(db, empleado_id)
        if not empleado:
            raise BusinessError("Empleado no encontrado")
        
        # Si se está cambiando la cédula, validar unicidad
        if hasattr(empleado_data, 'cedula') and empleado_data.cedula:
            is_unique = await self.repository.validate_cedula_unique(
                db, empleado_data.cedula, empleado_id
            )
            if not is_unique:
                raise ValidationError(f"La cédula {empleado_data.cedula} ya está en uso")
        
        # Actualizar
        updated_empleado = await self.repository.update(db, empleado, empleado_data, updated_by)
        
        logger.info(f"Empleado actualizado: {updated_empleado.nombres} {updated_empleado.apellidos}")
        return updated_empleado
    
    async def deactivate_empleado(
        self, 
        db: AsyncSession, 
        empleado_id: UUID,
        updated_by: Optional[UUID] = None
    ) -> bool:
        """Desactivar empleado (soft delete)"""
        empleado = await self.repository.get_by_id(db, empleado_id)
        if not empleado:
            return False
        
        # Verificar que no tenga registros pendientes
        # TODO: Implementar verificación con repositorio de registros
        
        # Desactivar
        await self.repository.update(
            db, 
            empleado, 
            {"estado": "inactivo"}, 
            updated_by
        )
        
        logger.info(f"Empleado desactivado: {empleado.nombres} {empleado.apellidos}")
        return True
    
    async def search_empleados(
        self, 
        db: AsyncSession, 
        search_term: str = "", 
        area: Optional[str] = None,
        cargo: Optional[str] = None,
        page: int = 1,
        size: int = 20
    ) -> Dict[str, Any]:
        """Búsqueda avanzada de empleados"""
        skip = (page - 1) * size
        
        empleados = await self.repository.search(
            db, 
            search_term=search_term,
            area=area,
            cargo=cargo,
            skip=skip,
            limit=size
        )
        
        # Contar total para paginación
        # Aquí se podría implementar un método count_search en el repositorio
        total = len(empleados)  # Temporal - mejorar para grandes volúm
        # Contar total para paginación (implementación mejorada)
        filters = {"estado": "activo"}
        if area:
            filters["area"] = area
        if cargo:
            filters["cargo"] = cargo
        
        total = await self.repository.count(db, filters)
        pages = (total + size - 1) // size
        
        return {
            "items": empleados,
            "total": total,
            "page": page,
            "size": size,
            "pages": pages,
            "has_next": page < pages,
            "has_prev": page > 1
        }
    
    async def get_empleados_by_area(self, db: AsyncSession, area: str) -> List[Empleado]:
        """Obtener empleados activos por área"""
        return await self.repository.get_by_area(db, area)
    
    async def get_estadisticas(self, db: AsyncSession) -> Dict[str, Any]:
        """Obtener estadísticas de empleados"""
        try:
            # Total de empleados activos
            total_activos = await self.repository.count(db, {"estado": "activo"})
            
            # Total por área
            por_area = await self.repository.count_by_area(db)
            
            # Total general
            total_general = await self.repository.count(db)
            
            return {
                "total_activos": total_activos,
                "total_general": total_general,
                "por_area": por_area,
                "inactivos": total_general - total_activos
            }
        except Exception as e:
            logger.error(f"Error obteniendo estadísticas de empleados: {e}")
            return {}
    
    async def validate_empleado_exists(self, db: AsyncSession, empleado_id: UUID) -> bool:
        """Validar que un empleado existe y está activo"""
        empleado = await self.repository.get_by_id(db, empleado_id)
        return empleado is not None and empleado.estado == "activo"
    
    async def _generate_qr_code(self, empleado: Empleado) -> str:
        """Generar código QR único para el empleado"""
        try:
            # Crear datos únicos para el QR
            qr_data = f"EMP_{empleado.id}_{secrets.token_hex(8)}"
            
            # Generar QR
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=10,
                border=4,
            )
            qr.add_data(qr_data)
            qr.make(fit=True)
            
            # Crear imagen en memoria
            img_buffer = io.BytesIO()
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(img_buffer, format='PNG')
            img_buffer.seek(0)
            
            # Convertir a base64
            img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
            
            logger.info(f"Código QR generado para empleado {empleado.id}")
            return qr_data
            
        except Exception as e:
            logger.error(f"Error generando código QR: {e}")
            return f"QR_{empleado.id}_{secrets.token_hex(4)}"

    # Instancia global del servicio
empleado_service = EmpleadoService()