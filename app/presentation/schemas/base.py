from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime
from uuid import UUID

class BaseSchema(BaseModel):
    """Schema base con configuración común"""
    model_config = ConfigDict(
        from_attributes=True,
        validate_assignment=True,
        arbitrary_types_allowed=True,
        str_strip_whitespace=True,
    )

class TimestampMixin(BaseModel):
    """Mixin para campos de auditoría"""
    created_at: datetime
    updated_at: datetime
    created_by: Optional[UUID] = None
    updated_by: Optional[UUID] = None

class PaginationParams(BaseModel):
    """Parámetros de paginación"""
    page: int = 1
    size: int = 20
    
    model_config = ConfigDict(
        validate_assignment=True,
        extra="forbid"
    )

class PaginatedResponse(BaseModel):
    """Respuesta paginada genérica"""
    items: list
    total: int
    page: int
    size: int
    pages: int
    has_next: bool
    has_prev: bool