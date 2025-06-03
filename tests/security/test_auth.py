import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import uuid4

from app.infrastructure.database.models.usuario import Usuario, RolEnum
from app.core.security import security_manager

@pytest.mark.asyncio
async def test_login_exitoso(client: AsyncClient, db_session: AsyncSession):
    """Test login con credenciales válidas"""
    # Crear usuario de prueba
    password = "TestPassword123!"
    hashed_password = security_manager.hash_password(password)
    
    usuario = Usuario(
        email="test@hojaverde.com",
        nombres="Test",
        apellidos="User",
        hashed_password=hashed_password,
        rol=RolEnum.USUARIO
    )
    
    db_session.add(usuario)
    await db_session.commit()
    
    # Intentar login
    login_data = {
        "email": "test@hojaverde.com",
        "password": password,
        "remember_me": False
    }
    
    response = await client.post("/api/v1/auth/login", json=login_data)
    assert response.status_code == 200
    
    data = response.json()
    assert "tokens" in data
    assert "user" in data
    assert data["tokens"]["token_type"] == "bearer"
    assert "access_token" in data["tokens"]
    assert "refresh_token" in data["tokens"]
    assert data["user"]["email"] == "test@hojaverde.com"

@pytest.mark.asyncio
async def test_login_credenciales_invalidas(client: AsyncClient):
    """Test login con credenciales incorrectas"""
    login_data = {
        "email": "noexiste@hojaverde.com",
        "password": "WrongPassword123!",
        "remember_me": False
    }
    
    response = await client.post("/api/v1/auth/login", json=login_data)
    assert response.status_code == 401
    
    data = response.json()
    assert "detail" in data

@pytest.mark.asyncio
async def test_login_usuario_bloqueado(client: AsyncClient, db_session: AsyncSession):
    """Test login con usuario bloqueado"""
    password = "TestPassword123!"
    hashed_password = security_manager.hash_password(password)
    
    usuario = Usuario(
        email="blocked@hojaverde.com",
        nombres="Blocked",
        apellidos="User",
        hashed_password=hashed_password,
        rol=RolEnum.USUARIO,
        intentos_fallidos=5,  # Usuario bloqueado
        is_active=False
    )
    
    db_session.add(usuario)
    await db_session.commit()
    
    login_data = {
        "email": "blocked@hojaverde.com",
        "password": password,
        "remember_me": False
    }
    
    response = await client.post("/api/v1/auth/login", json=login_data)
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_refresh_token_valido(client: AsyncClient, auth_headers: dict):
    """Test renovación de token con refresh token válido"""
    # Primero hacer login para obtener tokens
    login_data = {
        "email": "admin@hojaverde.com",
        "password": "admin123",
        "remember_me": False
    }
    
    login_response = await client.post("/api/v1/auth/login", json=login_data)
    assert login_response.status_code == 200
    
    tokens = login_response.json()["tokens"]
    refresh_token = tokens["refresh_token"]
    
    # Usar refresh token
    refresh_data = {"refresh_token": refresh_token}
    response = await client.post("/api/v1/auth/refresh", json=refresh_data)
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

@pytest.mark.asyncio
async def test_refresh_token_invalido(client: AsyncClient):
    """Test renovación con refresh token inválido"""
    refresh_data = {"refresh_token": "token_invalido"}
    response = await client.post("/api/v1/auth/refresh", json=refresh_data)
    
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_logout_exitoso(client: AsyncClient, auth_headers: dict):
    """Test logout exitoso"""
    response = await client.post("/api/v1/auth/logout", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert "message" in data
    assert "logged_out_at" in data

@pytest.mark.asyncio
async def test_logout_sin_autenticacion(client: AsyncClient):
    """Test logout sin estar autenticado"""
    response = await client.post("/api/v1/auth/logout")
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_obtener_usuario_actual(client: AsyncClient, auth_headers: dict):
    """Test obtener información del usuario actual"""
    response = await client.get("/api/v1/auth/me", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert "user" in data
    assert "context" in data
    assert data["user"]["email"] == "admin@hojaverde.com"

@pytest.mark.asyncio
async def test_validar_sesion(client: AsyncClient, auth_headers: dict):
    """Test validación de sesión activa"""
    response = await client.get("/api/v1/auth/validate", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["is_valid"] == True
    assert "user_id" in data

@pytest.mark.asyncio
async def test_obtener_permisos(client: AsyncClient, auth_headers: dict):
    """Test obtener permisos del usuario actual"""
    response = await client.get("/api/v1/auth/permissions", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert "rol" in data
    assert "permisos_adicionales" in data
    assert "capabilities" in data

@pytest.mark.asyncio
async def test_verificar_permiso_especifico(client: AsyncClient, auth_headers: dict):
    """Test verificar permiso específico"""
    permission = "empleados.leer"
    response = await client.get(f"/api/v1/auth/check-permission/{permission}", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert "permission" in data
    assert "granted" in data
    assert data["permission"] == permission

@pytest.mark.asyncio
async def test_solicitar_reset_password(client: AsyncClient):
    """Test solicitar reset de contraseña"""
    reset_data = {"email": "admin@hojaverde.com"}
    response = await client.post("/api/v1/auth/reset-password", json=reset_data)
    
    assert response.status_code == 200
    data = response.json()
    assert "message" in data

@pytest.mark.asyncio
async def test_obtener_sesiones_activas(client: AsyncClient, auth_headers: dict):
    """Test obtener sesiones activas"""
    response = await client.get("/api/v1/auth/sessions", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert "sessions" in data
    assert "total" in data

@pytest.mark.asyncio
async def test_health_check_auth(client: AsyncClient):
    """Test health check del servicio de autenticación"""
    response = await client.get("/api/v1/auth/health")
    assert response.status_code == 200
    
    data = response.json()
    assert data["service"] == "authentication"
    assert data["status"] == "healthy"

# === TESTS DE SEGURIDAD ===

@pytest.mark.asyncio
async def test_acceso_sin_token(client: AsyncClient):
    """Test acceso a endpoint protegido sin token"""
    response = await client.get("/api/v1/empleados/")
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_acceso_con_token_invalido(client: AsyncClient):
    """Test acceso con token inválido"""
    headers = {"Authorization": "Bearer token_invalido"}
    response = await client.get("/api/v1/empleados/", headers=headers)
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_acceso_con_token_expirado(client: AsyncClient):
    """Test acceso con token expirado"""
    # Crear token expirado
    from datetime import timedelta
    import jwt
    from app.core.config import settings
    
    expired_payload = {
        "sub": str(uuid4()),
        "exp": 1000000000,  # Timestamp muy antiguo
        "type": "access"
    }
    
    expired_token = jwt.encode(expired_payload, settings.secret_key, algorithm=settings.algorithm)
    headers = {"Authorization": f"Bearer {expired_token}"}
    
    response = await client.get("/api/v1/empleados/", headers=headers)
    assert response.status_code == 401

# === TESTS DE AUTORIZACIÓN ===

@pytest.mark.asyncio
async def test_usuario_normal_no_puede_crear_empleado(client: AsyncClient, db_session: AsyncSession):
    """Test que usuario normal no puede crear empleados"""
    # Crear usuario normal
    password = "TestPassword123!"
    hashed_password = security_manager.hash_password(password)
    
    usuario = Usuario(
        email="normal@hojaverde.com",
        nombres="Normal",
        apellidos="User",
        hashed_password=hashed_password,
        rol=RolEnum.USUARIO
    )
    
    db_session.add(usuario)
    await db_session.commit()
    
    # Login
    login_data = {
        "email": "normal@hojaverde.com",
        "password": password,
        "remember_me": False
    }
    
    login_response = await client.post("/api/v1/auth/login", json=login_data)
    tokens = login_response.json()["tokens"]
    
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    
    # Intentar crear empleado
    empleado_data = {
        "cedula": "9876543210",
        "nombres": "Test",
        "apellidos": "Empleado",
        "area": "Producción",
        "cargo": "Trabajador Agrícola"
    }
    
    response = await client.post("/api/v1/empleados/", json=empleado_data, headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_admin_puede_acceder_usuarios(client: AsyncClient, auth_headers: dict):
    """Test que admin puede acceder a endpoints de usuarios"""
    response = await client.get("/api/v1/usuarios/", headers=auth_headers)
    assert response.status_code == 200

# === FIXTURES ADICIONALES ===

@pytest.fixture
async def usuario_normal(db_session: AsyncSession) -> Usuario:
    """Fixture para crear usuario normal"""
    password = "TestPassword123!"
    hashed_password = security_manager.hash_password(password)
    
    usuario = Usuario(
        email="normal@hojaverde.com",
        nombres="Normal",
        apellidos="User",
        hashed_password=hashed_password,
        rol=RolEnum.USUARIO
    )
    
    db_session.add(usuario)
    await db_session.commit()
    await db_session.refresh(usuario)
    
    return usuario

@pytest.fixture
async def usuario_supervisor(db_session: AsyncSession) -> Usuario:
    """Fixture para crear usuario supervisor"""
    password = "SuperPassword123!"
    hashed_password = security_manager.hash_password(password)
    
    usuario = Usuario(
        email="supervisor@hojaverde.com",
        nombres="Super",
        apellidos="Visor",
        hashed_password=hashed_password,
        rol=RolEnum.SUPERVISOR
    )
    
    db_session.add(usuario)
    await db_session.commit()
    await db_session.refresh(usuario)
    
    return usuario