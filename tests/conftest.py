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