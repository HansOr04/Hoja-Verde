from sqlalchemy import Column, Integer, ForeignKey, CheckConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import BaseModel

class Alimentacion(BaseModel):
    """Modelo de registro de alimentación"""
    __tablename__ = "alimentacion"
    
    # Relación con registro diario
    registro_id = Column(
        UUID(as_uuid=True),
        ForeignKey("registros_diarios.id", ondelete="CASCADE"),
        nullable=False
    )
    
    # Tipos de alimentación
    desayuno = Column(Integer, default=0)
    desayuno_reforzado = Column(Integer, default=0)
    refrigerio = Column(Integer, default=0)
    merienda = Column(Integer, default=0)
    seco = Column(Integer, default=0)
    almuerzo = Column(Integer, default=0)
    
    # Relación
    registro = relationship("RegistroDiario", back_populates="alimentacion")
    
    # Constraints de validación
    __table_args__ = (
        CheckConstraint(
            "desayuno >= 0 AND desayuno <= 5",
            name='check_desayuno_range'
        ),
        CheckConstraint(
            "desayuno_reforzado >= 0 AND desayuno_reforzado <= 3",
            name='check_desayuno_reforzado_range'
        ),
        CheckConstraint(
            "refrigerio >= 0 AND refrigerio <= 5",
            name='check_refrigerio_range'
        ),
        CheckConstraint(
            "merienda >= 0 AND merienda <= 3",
            name='check_merienda_range'
        ),
        CheckConstraint(
            "seco >= 0 AND seco <= 3",
            name='check_seco_range'
        ),
        CheckConstraint(
            "almuerzo >= 0 AND almuerzo <= 3",
            name='check_almuerzo_range'
        ),
    )