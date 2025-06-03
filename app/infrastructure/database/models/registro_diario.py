from sqlalchemy import Column, String, Date, Time, Boolean, Text, ForeignKey, CheckConstraint, UniqueConstraint, DateTime
from sqlalchemy.dialects.postgresql import UUID, INTERVAL
from sqlalchemy.types import DECIMAL
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from ..base import BaseModel

class RegistroDiario(BaseModel):
    """Modelo de registro diario de asistencia"""
    __tablename__ = "registros_diarios"
    
    # Relaciones
    empleado_id = Column(
        UUID(as_uuid=True), 
        ForeignKey("empleados.id", ondelete="CASCADE"),
        nullable=False
    )
    
    # Información temporal
    fecha = Column(Date, nullable=False)
    dia_semana = Column(String(10))
    
    # Horarios
    hora_entrada = Column(Time)
    hora_salida = Column(Time)
    tiempo_lunch = Column(INTERVAL, default='01:00:00')
    
    # Horas extras
    hr_25 = Column(DECIMAL(4, 2), default=0.00)  # Horas al 25%
    hs_50 = Column(DECIMAL(4, 2), default=0.00)  # Horas al 50%
    he_100 = Column(DECIMAL(4, 2), default=0.00) # Horas al 100%
    
    # Permisos y observaciones
    horas_permiso = Column(DECIMAL(4, 2), default=0.00)
    transporte = Column(Boolean, default=False)
    observaciones = Column(Text)
    
    # Aprobación
    estado = Column(String(15), default='pendiente')
    aprobado_por = Column(UUID(as_uuid=True), ForeignKey("empleados.id"))
    fecha_aprobacion = Column(DateTime(timezone=True))
    
    # Relaciones
    empleado = relationship("Empleado", back_populates="registros", foreign_keys=[empleado_id])
    aprobador = relationship("Empleado", foreign_keys=[aprobado_por])
    alimentacion = relationship("Alimentacion", back_populates="registro", uselist=False)
    
    # Constraints
    __table_args__ = (
        UniqueConstraint('empleado_id', 'fecha', name='unique_empleado_fecha'),
        CheckConstraint(
            "fecha >= '2024-01-01' AND fecha <= CURRENT_DATE + INTERVAL '1 day'",
            name='check_fecha_range'
        ),
        CheckConstraint(
            "dia_semana IN ('L', 'M', 'MI', 'J', 'V', 'S', 'D')",
            name='check_dia_semana'
        ),
        CheckConstraint(
            "hora_salida IS NULL OR hora_entrada IS NULL OR hora_salida > hora_entrada",
            name='check_horas_logicas'
        ),
        CheckConstraint(
            "hr_25 >= 0.00 AND hr_25 <= 4.00",
            name='check_hr_25_range'
        ),
        CheckConstraint(
            "hs_50 >= 0.00 AND hs_50 <= 4.00",
            name='check_hs_50_range'
        ),
        CheckConstraint(
            "he_100 >= 0.00 AND he_100 <= 8.00",
            name='check_he_100_range'
        ),
        CheckConstraint(
            "horas_permiso >= 0.00 AND horas_permiso <= 8.00",
            name='check_horas_permiso'
        ),
        CheckConstraint(
            "estado IN ('pendiente', 'aprobado', 'rechazado')",
            name='check_estado_values'
        ),
        CheckConstraint(
            "tiempo_lunch >= '00:30:00' AND tiempo_lunch <= '02:00:00'",
            name='check_tiempo_lunch'
        ),
    )