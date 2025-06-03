from typing import Any, Dict, Generic, List, Optional, Type, TypeVar, Union
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy import func, and_, or_
from sqlalchemy.exc import NoResultFound
import logging

from app.core.database import Base

ModelType = TypeVar("ModelType", bound=Base)
CreateSchemaType = TypeVar("CreateSchemaType")
UpdateSchemaType = TypeVar("UpdateSchemaType")

logger = logging.getLogger(__name__)

class BaseRepository(Generic[ModelType, CreateSchemaType, UpdateSchemaType]):
    """Repositorio base con operaciones CRUD comunes"""
    
    def __init__(self, model: Type[ModelType]):
        self.model = model
    
    async def get_by_id(
        self, 
        db: AsyncSession, 
        id: UUID,
        load_relationships: List[str] = None
    ) -> Optional[ModelType]:
        """Obtener registro por ID"""
        try:
            query = select(self.model).where(self.model.id == id)
            
            # Cargar relaciones si se especifican
            if load_relationships:
                for relationship in load_relationships:
                    query = query.options(selectinload(getattr(self.model, relationship)))
            
            result = await db.execute(query)
            return result.scalar_one_or_none()
        except Exception as e:
            logger.error(f"Error obteniendo {self.model.__name__} por ID {id}: {e}")
            return None
    
    async def get_multi(
        self, 
        db: AsyncSession, 
        skip: int = 0, 
        limit: int = 100,
        filters: Dict[str, Any] = None,
        order_by: str = "created_at"
    ) -> List[ModelType]:
        """Obtener múltiples registros con paginación y filtros"""
        try:
            query = select(self.model)
            
            # Aplicar filtros
            if filters:
                for field, value in filters.items():
                    if hasattr(self.model, field) and value is not None:
                        query = query.where(getattr(self.model, field) == value)
            
            # Aplicar ordenamiento
            if hasattr(self.model, order_by):
                query = query.order_by(getattr(self.model, order_by))
            
            # Aplicar paginación
            query = query.offset(skip).limit(limit)
            
            result = await db.execute(query)
            return result.scalars().all()
        except Exception as e:
            logger.error(f"Error obteniendo múltiples {self.model.__name__}: {e}")
            return []
    
    async def create(
        self, 
        db: AsyncSession, 
        obj_in: CreateSchemaType,
        created_by: Optional[UUID] = None
    ) -> ModelType:
        """Crear nuevo registro"""
        try:
            # Convertir Pydantic model a dict
            if hasattr(obj_in, 'model_dump'):
                obj_data = obj_in.model_dump()
            else:
                obj_data = obj_in.dict()
            
            # Agregar usuario que crea
            if created_by and hasattr(self.model, 'created_by'):
                obj_data['created_by'] = created_by
            
            db_obj = self.model(**obj_data)
            db.add(db_obj)
            await db.commit()
            await db.refresh(db_obj)
            
            logger.info(f"Creado {self.model.__name__} con ID: {db_obj.id}")
            return db_obj
        except Exception as e:
            await db.rollback()
            logger.error(f"Error creando {self.model.__name__}: {e}")
            raise
    
    async def update(
        self, 
        db: AsyncSession, 
        db_obj: ModelType, 
        obj_in: Union[UpdateSchemaType, Dict[str, Any]],
        updated_by: Optional[UUID] = None
    ) -> ModelType:
        """Actualizar registro existente"""
        try:
            # Convertir a dict si es Pydantic model
            if hasattr(obj_in, 'model_dump'):
                update_data = obj_in.model_dump(exclude_unset=True)
            elif hasattr(obj_in, 'dict'):
                update_data = obj_in.dict(exclude_unset=True)
            else:
                update_data = obj_in
            
            # Agregar usuario que actualiza
            if updated_by and hasattr(self.model, 'updated_by'):
                update_data['updated_by'] = updated_by
            
            # Actualizar campos
            for field, value in update_data.items():
                if hasattr(db_obj, field):
                    setattr(db_obj, field, value)
            
            await db.commit()
            await db.refresh(db_obj)
            
            logger.info(f"Actualizado {self.model.__name__} con ID: {db_obj.id}")
            return db_obj
        except Exception as e:
            await db.rollback()
            logger.error(f"Error actualizando {self.model.__name__}: {e}")
            raise
    
    async def delete(self, db: AsyncSession, id: UUID) -> bool:
        """Eliminar registro (soft delete si existe campo 'estado')"""
        try:
            db_obj = await self.get_by_id(db, id)
            if not db_obj:
                return False
            
            # Soft delete si existe campo estado
            if hasattr(db_obj, 'estado'):
                db_obj.estado = 'inactivo'
                await db.commit()
                logger.info(f"Soft delete {self.model.__name__} con ID: {id}")
            else:
                # Hard delete
                await db.delete(db_obj)
                await db.commit()
                logger.info(f"Hard delete {self.model.__name__} con ID: {id}")
            
            return True
        except Exception as e:
            await db.rollback()
            logger.error(f"Error eliminando {self.model.__name__} con ID {id}: {e}")
            return False
    
    async def count(self, db: AsyncSession, filters: Dict[str, Any] = None) -> int:
        """Contar registros con filtros opcionales"""
        try:
            query = select(func.count(self.model.id))
            
            # Aplicar filtros
            if filters:
                for field, value in filters.items():
                    if hasattr(self.model, field) and value is not None:
                        query = query.where(getattr(self.model, field) == value)
            
            result = await db.execute(query)
            return result.scalar()
        except Exception as e:
            logger.error(f"Error contando {self.model.__name__}: {e}")
            return 0
    
    async def exists(self, db: AsyncSession, id: UUID) -> bool:
        """Verificar si existe un registro por ID"""
        try:
            query = select(self.model.id).where(self.model.id == id)
            result = await db.execute(query)
            return result.scalar_one_or_none() is not None
        except Exception as e:
            logger.error(f"Error verificando existencia de {self.model.__name__}: {e}")
            return False