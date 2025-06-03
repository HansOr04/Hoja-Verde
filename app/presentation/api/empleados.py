from fastapi import APIRouter, Depends, Query, Path
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from uuid import UUID
import logging

from app.core.database import get_db
from app.domain.services.empleado import empleado_service
from app.presentation.schemas.empleado import (
    EmpleadoCreate, EmpleadoUpdate, EmpleadoResponse
)
from app.presentation.schemas.base import PaginatedResponse, PaginationParams
from app.core.exceptions import NotFoundError

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/", response_model=EmpleadoResponse, status_code=201)
async def crear_empleado(
    empleado_data: EmpleadoCreate,
    db: AsyncSession = Depends(get_db)
):
    """Crear un nuevo empleado"""
    logger.info(f"Creando empleado: {empleado_data.nombres} {empleado_data.apellidos}")
    
    empleado = await empleado_service.create_empleado(db, empleado_data)
    return EmpleadoResponse.model_validate(empleado)

@router.get("/", response_model=PaginatedResponse)
async def listar_empleados(
    pagination: PaginationParams = Depends(),
    area: Optional[str] = Query(None, description="Filtrar por área"),
    cargo: Optional[str] = Query(None, description="Filtrar por cargo"),
    estado: str = Query("activo", description="Estado del empleado"),
    db: AsyncSession = Depends(get_db)
):
    """Listar empleados con paginación y filtros"""
    logger.info(f"Listando empleados - Página: {pagination.page}, Tamaño: {pagination.size}")
    
    filters = {"estado": estado}
    if area:
        filters["area"] = area
    if cargo:
        filters["cargo"] = cargo
    
    result = await empleado_service.get_paginated(
        db, 
        page=pagination.page, 
        size=pagination.size,
        filters=filters
    )
    
    # Convertir empleados a schemas de respuesta
    empleados_response = [
        EmpleadoResponse.model_validate(emp) for emp in result["items"]
    ]
    
    return PaginatedResponse(
        items=empleados_response,
        total=result["total"],
        page=result["page"],
        size=result["size"],
        pages=result["pages"],
        has_next=result["has_next"],
        has_prev=result["has_prev"]
    )

@router.get("/search", response_model=PaginatedResponse)
async def buscar_empleados(
    q: str = Query("", description="Término de búsqueda"),
    area: Optional[str] = Query(None, description="Filtrar por área"),
    cargo: Optional[str] = Query(None, description="Filtrar por cargo"),
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db)
):
    """Búsqueda avanzada de empleados"""
    logger.info(f"Buscando empleados: '{q}'")
    
    result = await empleado_service.search_empleados(
        db,
        search_term=q,
        area=area,
        cargo=cargo,
        page=pagination.page,
        size=pagination.size
    )
    
    empleados_response = [
        EmpleadoResponse.model_validate(emp) for emp in result["items"]
    ]
    
    return PaginatedResponse(
        items=empleados_response,
        total=result["total"],
        page=result["page"],
        size=result["size"],
        pages=result["pages"],
        has_next=result["has_next"],
        has_prev=result["has_prev"]
    )

@router.get("/{empleado_id}", response_model=EmpleadoResponse)
async def obtener_empleado(
    empleado_id: UUID = Path(..., description="ID del empleado"),
    db: AsyncSession = Depends(get_db)
):
    """Obtener empleado por ID"""
    logger.info(f"Obteniendo empleado: {empleado_id}")
    
    empleado = await empleado_service.get_by_id(db, empleado_id)
    if not empleado:
        raise NotFoundError("Empleado", str(empleado_id))
    
    return EmpleadoResponse.model_validate(empleado)

@router.put("/{empleado_id}", response_model=EmpleadoResponse)
async def actualizar_empleado(
    empleado_id: UUID = Path(..., description="ID del empleado"),
    empleado_data: EmpleadoUpdate = ...,
    db: AsyncSession = Depends(get_db)
):
    """Actualizar empleado"""
    logger.info(f"Actualizando empleado: {empleado_id}")
    
    empleado = await empleado_service.update_empleado(db, empleado_id, empleado_data)
    if not empleado:
        raise NotFoundError("Empleado", str(empleado_id))
    
    return EmpleadoResponse.model_validate(empleado)

@router.delete("/{empleado_id}", status_code=204)
async def eliminar_empleado(
    empleado_id: UUID = Path(..., description="ID del empleado"),
    db: AsyncSession = Depends(get_db)
):
    """Eliminar (desactivar) empleado"""
    logger.info(f"Eliminando empleado: {empleado_id}")
    
    success = await empleado_service.deactivate_empleado(db, empleado_id)
    if not success:
        raise NotFoundError("Empleado", str(empleado_id))

@router.get("/area/{area}", response_model=List[EmpleadoResponse])
async def obtener_empleados_por_area(
    area: str = Path(..., description="Área de trabajo"),
    db: AsyncSession = Depends(get_db)
):
    """Obtener empleados por área"""
    logger.info(f"Obteniendo empleados del área: {area}")
    
    empleados = await empleado_service.get_empleados_by_area(db, area)
    return [EmpleadoResponse.model_validate(emp) for emp in empleados]

@router.get("/stats/general")
async def obtener_estadisticas(db: AsyncSession = Depends(get_db)):
    """Obtener estadísticas generales de empleados"""
    logger.info("Obteniendo estadísticas de empleados")
    
    estadisticas = await empleado_service.get_estadisticas(db)
    return estadisticas