from typing import Any, Dict, Generic, List, Optional, TypeVar
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
import logging

from app.infrastructure.database.repositories.base import BaseRepository

ModelType = TypeVar("ModelType")
RepositoryType = TypeVar("RepositoryType", bound=BaseRepository)

logger = logging.getLogger(__name__)

class BaseService(Generic[ModelType, RepositoryType]):
    """Servicio base con lógica de negocio común"""
    
    def __init__(self, repository: RepositoryType):
        self.repository = repository
    
    async def get_by_id(self, db: AsyncSession, id: UUID) -> Optional[ModelType]:
        """Obtener por ID con validaciones de negocio"""
        return await self.repository.get_by_id(db, id)
    
    async def get_paginated(
        self, 
        db: AsyncSession, 
        page: int = 1, 
        size: int = 20,
        filters: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Obtener resultados paginados"""
        # Validar parámetros de paginación
        if page < 1:
            page = 1
        if size < 1 or size > 100:
            size = 20
        
        skip = (page - 1) * size
        
        # Obtener datos y total
        items = await self.repository.get_multi(db, skip=skip, limit=size, filters=filters)
        total = await self.repository.count(db, filters=filters)
        
        # Calcular metadatos de paginación
        pages = (total + size - 1) // size  # Redondear hacia arriba
        
        return {
            "items": items,
            "total": total,
            "page": page,
            "size": size,
            "pages": pages,
            "has_next": page < pages,
            "has_prev": page > 1
        }
    
    async def create_with_validation(
        self, 
        db: AsyncSession, 
        obj_in: Any,
        created_by: Optional[UUID] = None
    ) -> ModelType:
        """Crear con validaciones de negocio"""
        # Validaciones específicas del dominio se implementan en servicios hijos
        return await self.repository.create(db, obj_in, created_by)
    
    async def update_with_validation(
        self, 
        db: AsyncSession, 
        id: UUID, 
        obj_in: Any,
        updated_by: Optional[UUID] = None
    ) -> Optional[ModelType]:
        """Actualizar con validaciones de negocio"""
        # Verificar que existe
        db_obj = await self.repository.get_by_id(db, id)
        if not db_obj:
            return None
        
        # Validaciones específicas del dominio se implementan en servicios hijos
        return await self.repository.update(db, db_obj, obj_in, updated_by)
    
    async def delete_with_validation(
        self, 
        db: AsyncSession, 
        id: UUID
    ) -> bool:
        """Eliminar con validaciones de negocio"""
        # Verificar que existe
        exists = await self.repository.exists(db, id)
        if not exists:
            return False
        
        # Validaciones específicas del dominio se implementan en servicios hijos
        return await self.repository.delete(db, id)