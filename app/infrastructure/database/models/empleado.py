from sqlalchemy import Column, String, Date, Boolean, CheckConstraint
from sqlalchemy.types import DECIMAL
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from .base import BaseModel

class Empleado(BaseModel):
    """Modelo de empleado con validaciones"""
    __tablename__ = "empleados"
    
    # Información personal
    cedula = Column(
        String(10), 
        unique=True, 
        nullable=False,
        index=True
    )
    nombres = Column(String(100), nullable=False)
    apellidos = Column(String(100), nullable=False)
    
    # Información laboral
    area = Column(String(50), nullable=False)
    cargo = Column(String(50), nullable=False)
    jornada_horas = Column(DECIMAL(4, 2), default=8.00)
    estado = Column(String(10), default='activo')
    
    # Información adicional
    codigo_qr = Column(String(100), unique=True)
    fecha_ingreso = Column(Date, default=func.current_date())
    unidad_productiva = Column(String(50))
    
    # Relaciones
    registros = relationship("RegistroDiario", back_populates="empleado")
    
    # Constraints de validación
    __table_args__ = (
        CheckConstraint(
            "cedula ~ '^[0-9]{10}$'", 
            name='check_cedula_format'
        ),
        CheckConstraint(
            "area IN ('Producción', 'Calidad', 'Mantenimiento', 'Administración')",
            name='check_area_values'
        ),
        CheckConstraint(
            "cargo IN ('Trabajador Agrícola', 'Talento Humano', 'Supervisor', 'Administrador')",
            name='check_cargo_values'
        ),
        CheckConstraint(
            "estado IN ('activo', 'inactivo', 'suspendido')",
            name='check_estado_values'
        ),
        CheckConstraint(
            "jornada_horas >= 4.00 AND jornada_horas <= 12.00",
            name='check_jornada_horas'
        ),
    )
    
    def __str__(self):
        return f"{self.nombres} {self.apellidos}"