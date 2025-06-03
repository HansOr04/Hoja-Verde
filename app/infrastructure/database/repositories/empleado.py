from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import and_, or_, func
from uuid import UUID

from .base import BaseRepository
from app.infrastructure.database.models.empleado import Empleado
from app.presentation.schemas.empleado import EmpleadoCreate, EmpleadoUpdate

class EmpleadoRepository(BaseRepository[Empleado, EmpleadoCreate, EmpleadoUpdate]):
    """Repositorio específico para empleados"""
    
    def __init__(self):
        super().__init__(Empleado)
    
    async def get_by_cedula(self, db: AsyncSession, cedula: str) -> Optional[Empleado]:
        """Obtener empleado por cédula"""
        try:
            query = select(self.model).where(self.model.cedula == cedula)
            result = await db.execute(query)
            return result.scalar_one_or_none()
        except Exception as e:
            logger.error(f"Error obteniendo empleado por cédula {cedula}: {e}")
            return None
    
    async def search(
        self, 
        db: AsyncSession, 
        search_term: str, 
        area: Optional[str] = None,
        cargo: Optional[str] = None,
        estado: str = "activo",
        skip: int = 0,
        limit: int = 100
    ) -> List[Empleado]:
        """Búsqueda avanzada de empleados"""
        try:
            query = select(self.model)
            
            # Filtro por estado
            query = query.where(self.model.estado == estado)
            
            # Búsqueda por término (nombres, apellidos, cédula)
            if search_term:
                search_filter = or_(
                    self.model.nombres.ilike(f"%{search_term}%"),
                    self.model.apellidos.ilike(f"%{search_term}%"),
                    self.model.cedula.like(f"%{search_term}%")
                )
                query = query.where(search_filter)
            
            # Filtros adicionales
            if area:
                query = query.where(self.model.area == area)
            if cargo:
                query = query.where(self.model.cargo == cargo)
            
            # Ordenar por apellidos y nombres
            query = query.order_by(self.model.apellidos, self.model.nombres)
            
            # Paginación
            query = query.offset(skip).limit(limit)
            
            result = await db.execute(query)
            return result.scalars().all()
        except Exception as e:
            logger.error(f"Error en búsqueda de empleados: {e}")
            return []
    
    async def get_by_area(self, db: AsyncSession, area: str) -> List[Empleado]:
        """Obtener empleados por área"""
        try:
            query = select(self.model).where(
                and_(
                    self.model.area == area,
                    self.model.estado == "activo"
                )
            ).order_by(self.model.apellidos, self.model.nombres)
            
            result = await db.execute(query)
            return result.scalars().all()
        except Exception as e:
            logger.error(f"Error obteniendo empleados por área {area}: {e}")
            return []
    
    async def get_activos(self, db: AsyncSession) -> List[Empleado]:
        """Obtener todos los empleados activos"""
        return await self.get_multi(
            db, 
            filters={"estado": "activo"},
            order_by="apellidos"
        )
    
    async def count_by_area(self, db: AsyncSession) -> dict:
        """Contar empleados por área"""
        try:
            query = select(
                self.model.area,
                func.count(self.model.id).label('total')
            ).where(
                self.model.estado == "activo"
            ).group_by(self.model.area)
            
            result = await db.execute(query)
            return {area: total for area, total in result.all()}
        except Exception as e:
            logger.error(f"Error contando empleados por área: {e}")
            return {}
    
    async def validate_cedula_unique(
        self, 
        db: AsyncSession, 
        cedula: str, 
        exclude_id: Optional[UUID] = None
    ) -> bool:
        """Validar que la cédula sea única"""
        try:
            query = select(self.model.id).where(self.model.cedula == cedula)
            
            # Excluir ID específico (para actualizaciones)
            if exclude_id:
                query = query.where(self.model.id != exclude_id)
            
            result = await db.execute(query)
            return result.scalar_one_or_none() is None
        except Exception as e:
            logger.error(f"Error validando unicidad de cédula: {e}")
            return False

# Instancia global del repositorio
empleado_repository = EmpleadoRepository()