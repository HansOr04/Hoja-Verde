from app.infrastructure.database.models.empleado import Empleado
from app.infrastructure.database.models.registro_diario import RegistroDiario
from app.infrastructure.database.models.alimentacion import Alimentacion
from app.core.config import settings
from app.core.database import Base
# Importar todos los modelos para que Alembic los detecte
from app.infrastructure.database.models.empleado import Empleado
from app.infrastructure.database.models.usuario import Usuario, HistorialPassword  # NUEVO
from app.infrastructure.database.base import Base
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context
import os
import sys

# Agregar el directorio padre al path para importar la app
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
# Importar todos los modelos aquí para que Alembic los detecte
# from app.infrastructure.database.models import empleado, registro_diario, alimentacion, usuario
# this is the Alembic Config object
config = context.config
# Configurar la URL de la base de datos desde nuestras settings
config.set_main_option("sqlalchemy.url", settings.database_url)
# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)
# add your model's MetaData object here for 'autogenerate' support
target_metadata = Base.metadata

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, 
            target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()