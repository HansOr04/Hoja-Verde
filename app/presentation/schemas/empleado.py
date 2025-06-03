from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
from datetime import date
from decimal import Decimal
from uuid import UUID

from .base import BaseSchema, TimestampMixin

class EmpleadoBase(BaseModel):
    """Campos base de empleado"""
    cedula: str = Field(..., min_length=10, max_length=10, description="Cédula de identidad")
    nombres: str = Field(..., min_length=2, max_length=100, description="Nombres del empleado")
    apellidos: str = Field(..., min_length=2, max_length=100, description="Apellidos del empleado")
    area: str = Field(..., description="Área de trabajo")
    cargo: str = Field(..., description="Cargo del empleado")
    jornada_horas: Decimal = Field(default=Decimal("8.00"), ge=4, le=12, description="Horas de jornada")
    unidad_productiva: Optional[str] = Field(None, max_length=50, description="Unidad productiva")
    
    @field_validator('cedula')
    @classmethod
    def validate_cedula(cls, v):
        """Validar formato de cédula ecuatoriana"""
        if not v.isdigit():
            raise ValueError('La cédula debe contener solo números')
        if len(v) != 10:
            raise ValueError('La cédula debe tener exactamente 10 dígitos')
        
        # Validación del algoritmo de cédula ecuatoriana
        digits = [int(d) for d in v]
        province = int(v[:2])
        if province < 1 or province > 24:
            raise ValueError('Código de provincia inválido')
        
        # Algoritmo de verificación
        coefficients = [2, 1, 2, 1, 2, 1, 2, 1, 2]
        total = 0
        for i in range(9):
            result = digits[i] * coefficients[i]
            if result >= 10:
                result = result - 9
            total += result
        
        verifier = total % 10
        if verifier != 0:
            verifier = 10 - verifier
        
        if verifier != digits[9]:
            raise ValueError('Número de cédula inválido')
        
        return v
    
    @field_validator('area')
    @classmethod
    def validate_area(cls, v):
        areas_validas = ['Producción', 'Calidad', 'Mantenimiento', 'Administración']
        if v not in areas_validas:
            raise ValueError(f'Área debe ser una de: {", ".join(areas_validas)}')
        return v
    
    @field_validator('cargo')
    @classmethod
    def validate_cargo(cls, v):
        cargos_validos = ['Trabajador Agrícola', 'Talento Humano', 'Supervisor', 'Administrador']
        if v not in cargos_validos:
            raise ValueError(f'Cargo debe ser uno de: {", ".join(cargos_validos)}')
        return v

class EmpleadoCreate(EmpleadoBase):
    """Schema para crear empleado"""
    fecha_ingreso: Optional[date] = None

class EmpleadoUpdate(BaseModel):
    """Schema para actualizar empleado"""
    nombres: Optional[str] = Field(None, min_length=2, max_length=100)
    apellidos: Optional[str] = Field(None, min_length=2, max_length=100)
    area: Optional[str] = None
    cargo: Optional[str] = None
    jornada_horas: Optional[Decimal] = Field(None, ge=4, le=12)
    unidad_productiva: Optional[str] = Field(None, max_length=50)
    estado: Optional[str] = Field(None, pattern="^(activo|inactivo|suspendido)$")
    
    @field_validator('area')
    @classmethod
    def validate_area(cls, v):
        if v is not None:
            areas_validas = ['Producción', 'Calidad', 'Mantenimiento', 'Administración']
            if v not in areas_validas:
                raise ValueError(f'Área debe ser una de: {", ".join(areas_validas)}')
        return v
    
    @field_validator('cargo')
    @classmethod
    def validate_cargo(cls, v):
        if v is not None:
            cargos_validos = ['Trabajador Agrícola', 'Talento Humano', 'Supervisor', 'Administrador']
            if v not in cargos_validos:
                raise ValueError(f'Cargo debe ser uno de: {", ".join(cargos_validos)}')
        return v

class EmpleadoInDB(EmpleadoBase, TimestampMixin):
    """Schema de empleado en base de datos"""
    id: UUID
    codigo_qr: Optional[str] = None
    fecha_ingreso: date
    estado: str

class EmpleadoResponse(BaseSchema):
    """Schema de respuesta de empleado"""
    id: UUID
    cedula: str
    nombres: str
    apellidos: str
    area: str
    cargo: str
    jornada_horas: Decimal
    estado: str
    fecha_ingreso: date
    unidad_productiva: Optional[str] = None
    codigo_qr: Optional[str] = None
    
    @property
    def nombre_completo(self) -> str:
        return f"{self.nombres} {self.apellidos}"

class EmpleadoList(BaseModel):
    """Schema para lista de empleados"""
    empleados: List[EmpleadoResponse]
    total: int