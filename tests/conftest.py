import pytest
import asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.core.database import get_db, Base
from app.core.config import settings

# Base de datos de prueba en memoria
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

@pytest.fixture(scope="session")
def event_loop():
   """Crear event loop para toda la sesión de pruebas"""
   loop = asyncio.get_event_loop_policy().new_event_loop()
   yield loop
   loop.close()

@pytest.fixture(scope="session")
async def test_engine():
   """Motor de base de datos para pruebas"""
   engine = create_async_engine(
       TEST_DATABASE_URL,
       poolclass=StaticPool,
       connect_args={"check_same_thread": False},
       echo=False,
   )
   
   # Crear todas las tablas
   async with engine.begin() as conn:
       await conn.run_sync(Base.metadata.create_all)
   
   yield engine
   
   # Limpiar
   await engine.dispose()

@pytest.fixture
async def test_db(test_engine):
   """Sesión de base de datos para cada prueba"""
   TestSessionLocal = async_sessionmaker(
       test_engine, class_=AsyncSession, expire_on_commit=False
   )
   
   async with TestSessionLocal() as session:
       yield session

@pytest.fixture
async def client(test_db):
   """Cliente de pruebas con base de datos mock"""
   async def override_get_db():
       yield test_db
   
   app.dependency_overrides[get_db] = override_get_db
   
   async with AsyncClient(app=app, base_url="http://test") as ac:
       yield ac
   
   app.dependency_overrides.clear()
   import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from typing import AsyncGenerator, Dict

from app.main import app
from app.core.database import get_db
from app.infrastructure.database.base import Base
from app.infrastructure.database.models.usuario import Usuario, RolEnum  # NUEVO
from app.core.security import security_manager  # NUEVO

# URL de base de datos de test
TEST_DATABASE_URL = "postgresql+asyncpg://test:test@localhost/hojaverde_test"

# Engine de test
test_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
    future=True
)

# Session factory de test
TestSessionLocal = sessionmaker(
    test_engine,
    class_=AsyncSession,
    expire_on_commit=False
)

@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Fixture de sesión de base de datos para tests"""
    # Crear tablas
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Crear sesión
    async with TestSessionLocal() as session:
        yield session
    
    # Limpiar tablas después del test
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Fixture de cliente HTTP para tests"""
    def override_get_db():
        return db_session
    
    app.dependency_overrides[get_db] = override_get_db
    
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client
    
    app.dependency_overrides.clear()

# === NUEVAS FIXTURES DE AUTENTICACIÓN ===

@pytest_asyncio.fixture
async def admin_user(db_session: AsyncSession) -> Usuario:
    """Fixture para crear usuario administrador de test"""
    password = "Admin123!"
    hashed_password = security_manager.hash_password(password)
    
    admin = Usuario(
        email="admin@hojaverde.com",
        nombres="Admin",
        apellidos="Test",
        hashed_password=hashed_password,
        rol=RolEnum.SUPER_ADMIN
    )
    
    db_session.add(admin)
    await db_session.commit()
    await db_session.refresh(admin)
    
    return admin

@pytest_asyncio.fixture
async def auth_headers(client: AsyncClient, admin_user: Usuario) -> Dict[str, str]:
    """Fixture para obtener headers de autenticación"""
    login_data = {
        "email": "admin@hojaverde.com",
        "password": "Admin123!",
        "remember_me": False
    }
    
    response = await client.post("/api/v1/auth/login", json=login_data)
    assert response.status_code == 200
    
    tokens = response.json()["tokens"]
    access_token = tokens["access_token"]
    
    return {"Authorization": f"Bearer {access_token}"}

@pytest_asyncio.fixture
async def rrhh_user(db_session: AsyncSession) -> Usuario:
    """Fixture para crear usuario de RRHH"""
    password = "Rrhh123!"
    hashed_password = security_manager.hash_password(password)
    
    rrhh = Usuario(
        email="rrhh@hojaverde.com",
        nombres="RRHH",
        apellidos="Test",
        hashed_password=hashed_password,
        rol=RolEnum.RECURSOS_HUMANOS
    )
    
    db_session.add(rrhh)
    await db_session.commit()
    await db_session.refresh(rrhh)
    
    return rrhh

@pytest_asyncio.fixture
async def rrhh_headers(client: AsyncClient, rrhh_user: Usuario) -> Dict[str, str]:
    """Fixture para headers de autenticación de RRHH"""
    login_data = {
        "email": "rrhh@hojaverde.com",
        "password": "Rrhh123!",
        "remember_me": False
    }
    
    response = await client.post("/api/v1/auth/login", json=login_data)
    assert response.status_code == 200
    
    tokens = response.json()["tokens"]
    access_token = tokens["access_token"]
    
    return {"Authorization": f"Bearer {access_token}"}