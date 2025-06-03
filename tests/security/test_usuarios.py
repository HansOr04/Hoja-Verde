import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import uuid4

from app.infrastructure.database.models.usuario import RolEnum

@pytest.mark.asyncio
async def test_crear_usuario_como_admin(client: AsyncClient, auth_headers: dict):
    """Test crear usuario siendo administrador"""
    usuario_data = {
        "email": "nuevo@hojaverde.com",
        "password": "NuevoUser123!",
        "nombres": "Nuevo",
        "apellidos": "Usuario",
        "rol": "usuario"
    }
    
    response = await client.post("/api/v1/usuarios/", json=usuario_data, headers=auth_headers)
    assert response.status_code == 201
    
    data = response.json()
    assert data["email"] == usuario_data["email"]
    assert data["nombres"] == usuario_data["nombres"]
    assert data["apellidos"] == usuario_data["apellidos"]
    assert data["rol"] == usuario_data["rol"]
    assert "id" in data
    assert "hashed_password" not in data  # No debe devolver la contraseña

@pytest.mark.asyncio
async def test_crear_usuario_sin_permisos(client: AsyncClient, rrhh_headers: dict):
    """Test crear usuario sin permisos de administrador"""
    usuario_data = {
        "email": "nuevo@hojaverde.com",
        "password": "NuevoUser123!",
        "nombres": "Nuevo",
        "apellidos": "Usuario",
        "rol": "usuario"
    }
    
    response = await client.post("/api/v1/usuarios/", json=usuario_data, headers=rrhh_headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_crear_usuario_email_duplicado(client: AsyncClient, auth_headers: dict):
    """Test crear usuario con email duplicado"""
    usuario_data = {
        "email": "admin@hojaverde.com",  # Email que ya existe
        "password": "NuevoUser123!",
        "nombres": "Otro",
        "apellidos": "Admin",
        "rol": "usuario"
    }
    
    response = await client.post("/api/v1/usuarios/", json=usuario_data, headers=auth_headers)
    assert response.status_code == 409  # Conflict

@pytest.mark.asyncio
async def test_crear_usuario_password_debil(client: AsyncClient, auth_headers: dict):
    """Test crear usuario con contraseña débil"""
    usuario_data = {
        "email": "nuevo@hojaverde.com",
        "password": "123",  # Contraseña muy débil
        "nombres": "Nuevo",
        "apellidos": "Usuario",
        "rol": "usuario"
    }
    
    response = await client.post("/api/v1/usuarios/", json=usuario_data, headers=auth_headers)
    assert response.status_code == 422  # Validation error

@pytest.mark.asyncio
async def test_listar_usuarios(client: AsyncClient, auth_headers: dict):
    """Test listar usuarios"""
    response = await client.get("/api/v1/usuarios/", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert len(data["items"]) >= 1  # Al menos el admin

@pytest.mark.asyncio
async def test_listar_usuarios_con_filtros(client: AsyncClient, auth_headers: dict):
    """Test listar usuarios con filtros"""
    params = {
        "rol": "super_admin",
        "search": "admin"
    }
    
    response = await client.get("/api/v1/usuarios/", params=params, headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert "items" in data

@pytest.mark.asyncio
async def test_obtener_usuario_por_id(client: AsyncClient, auth_headers: dict, admin_user):
    """Test obtener usuario por ID"""
    user_id = str(admin_user.id)
    
    response = await client.get(f"/api/v1/usuarios/{user_id}", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["id"] == user_id
    assert data["email"] == admin_user.email

@pytest.mark.asyncio
async def test_obtener_usuario_inexistente(client: AsyncClient, auth_headers: dict):
    """Test obtener usuario que no existe"""
    user_id = str(uuid4())
    
    response = await client.get(f"/api/v1/usuarios/{user_id}", headers=auth_headers)
    assert response.status_code == 404

@pytest.mark.asyncio
async def test_actualizar_usuario_propio(client: AsyncClient, auth_headers: dict, admin_user):
    """Test actualizar información propia"""
    user_id = str(admin_user.id)
    
    update_data = {
        "nombres": "Administrador Actualizado",
        "apellidos": "Sistema Nuevo"
    }
    
    response = await client.put(f"/api/v1/usuarios/{user_id}", json=update_data, headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["nombres"] == update_data["nombres"]
    assert data["apellidos"] == update_data["apellidos"]

@pytest.mark.asyncio
async def test_cambiar_password_propia(client: AsyncClient, auth_headers: dict, admin_user):
    """Test cambiar contraseña propia"""
    user_id = str(admin_user.id)
    
    password_data = {
        "password_actual": "Admin123!",
        "password_nuevo": "NewAdmin123!",
        "confirmar_password": "NewAdmin123!"
    }
    
    response = await client.put(f"/api/v1/usuarios/{user_id}/password", json=password_data, headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert "message" in data

@pytest.mark.asyncio
async def test_cambiar_password_incorrecta(client: AsyncClient, auth_headers: dict, admin_user):
    """Test cambiar contraseña con contraseña actual incorrecta"""
    user_id = str(admin_user.id)
    
    password_data = {
        "password_actual": "PasswordIncorrecta!",
        "password_nuevo": "NewAdmin123!",
        "confirmar_password": "NewAdmin123!"
    }
    
    response = await client.put(f"/api/v1/usuarios/{user_id}/password", json=password_data, headers=auth_headers)
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_desactivar_usuario(client: AsyncClient, auth_headers: dict):
    """Test desactivar usuario"""
    # Primero crear un usuario para desactivar
    usuario_data = {
        "email": "para_desactivar@hojaverde.com",
        "password": "Test123!",
        "nombres": "Para",
        "apellidos": "Desactivar",
        "rol": "usuario"
    }
    
    create_response = await client.post("/api/v1/usuarios/", json=usuario_data, headers=auth_headers)
    assert create_response.status_code == 201
    
    user_id = create_response.json()["id"]
    
    # Desactivar usuario
    response = await client.delete(f"/api/v1/usuarios/{user_id}", headers=auth_headers)
    assert response.status_code == 204

@pytest.mark.asyncio
async def test_obtener_permisos_usuario(client: AsyncClient, auth_headers: dict, admin_user):
    """Test obtener permisos de usuario"""
    user_id = str(admin_user.id)
    
    response = await client.get(f"/api/v1/usuarios/{user_id}/permissions", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert "rol" in data
    assert "permisos_adicionales" in data
    assert "permisos_efectivos" in data

@pytest.mark.asyncio
async def test_agregar_permisos_usuario(client: AsyncClient, auth_headers: dict):
    """Test agregar permisos a usuario"""
    # Crear usuario de prueba
    usuario_data = {
        "email": "test_permisos@hojaverde.com",
        "password": "Test123!",
        "nombres": "Test",
        "apellidos": "Permisos",
        "rol": "usuario"
    }
    
    create_response = await client.post("/api/v1/usuarios/", json=usuario_data, headers=auth_headers)
    user_id = create_response.json()["id"]
    
    # Agregar permisos
    permisos_data = {
        "permisos": ["reportes.leer"],
        "accion": "agregar"
    }
    
    response = await client.post(f"/api/v1/usuarios/{user_id}/permissions", json=permisos_data, headers=auth_headers)
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_obtener_usuarios_por_rol(client: AsyncClient, auth_headers: dict):
    """Test obtener usuarios por rol específico"""
    rol = "super_admin"
    
    response = await client.get(f"/api/v1/usuarios/roles/{rol}", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert isinstance(data, list)
    
    # Verificar que todos tienen el rol correcto
    for user in data:
        assert user["rol"] == rol

@pytest.mark.asyncio
async def test_estadisticas_usuarios(client: AsyncClient, auth_headers: dict):
    """Test obtener estadísticas de usuarios"""
    response = await client.get("/api/v1/usuarios/stats/general", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert "total" in data
    assert "activos" in data
    assert "por_rol" in data

@pytest.mark.asyncio
async def test_activar_usuario(client: AsyncClient, auth_headers: dict):
    """Test activar usuario desactivado"""
    # Crear y desactivar usuario
    usuario_data = {
        "email": "para_activar@hojaverde.com",
        "password": "Test123!",
        "nombres": "Para",
        "apellidos": "Activar",
        "rol": "usuario"
    }
    
    create_response = await client.post("/api/v1/usuarios/", json=usuario_data, headers=auth_headers)
    user_id = create_response.json()["id"]
    
    # Desactivar
    await client.delete(f"/api/v1/usuarios/{user_id}", headers=auth_headers)
    
    # Activar
    response = await client.post(f"/api/v1/usuarios/{user_id}/activate", headers=auth_headers)
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_reset_password_admin(client: AsyncClient, auth_headers: dict):
    """Test reset de contraseña por administrador"""
    # Crear usuario
    usuario_data = {
        "email": "para_reset@hojaverde.com",
        "password": "Test123!",
        "nombres": "Para",
        "apellidos": "Reset",
        "rol": "usuario"
    }
    
    create_response = await client.post("/api/v1/usuarios/", json=usuario_data, headers=auth_headers)
    user_id = create_response.json()["id"]
    
    # Reset contraseña
    response = await client.post(f"/api/v1/usuarios/{user_id}/reset-password", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert "temp_password" in data
    assert data["must_change"] == True

# === TESTS DE AUTORIZACIÓN ===

@pytest.mark.asyncio
async def test_usuario_normal_no_puede_ver_otros_usuarios(client: AsyncClient, db_session: AsyncSession):
    """Test que usuario normal no puede ver lista de usuarios"""
    # Crear usuario normal
    from app.infrastructure.database.models.usuario import Usuario
    from app.core.security import security_manager
    
    password = "Normal123!"
    hashed_password = security_manager.hash_password(password)
    
    normal_user = Usuario(
        email="normal@hojaverde.com",
        nombres="Normal",
        apellidos="User",
        hashed_password=hashed_password,
        rol=RolEnum.USUARIO
    )
    
    db_session.add(normal_user)
    await db_session.commit()
    
    # Login como usuario normal
    login_data = {
        "email": "normal@hojaverde.com",
        "password": password,
        "remember_me": False
    }
    
    login_response = await client.post("/api/v1/auth/login", json=login_data)
    tokens = login_response.json()["tokens"]
    normal_headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    
    # Intentar acceder a lista de usuarios
    response = await client.get("/api/v1/usuarios/", headers=normal_headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_usuario_puede_ver_su_propio_perfil(client: AsyncClient, db_session: AsyncSession):
    """Test que usuario puede ver su propio perfil"""
    # Crear usuario normal
    from app.infrastructure.database.models.usuario import Usuario
    from app.core.security import security_manager
    
    password = "Normal123!"
    hashed_password = security_manager.hash_password(password)
    
    normal_user = Usuario(
        email="normal2@hojaverde.com",
        nombres="Normal2",
        apellidos="User",
        hashed_password=hashed_password,
        rol=RolEnum.USUARIO
    )
    
    db_session.add(normal_user)
    await db_session.commit()
    await db_session.refresh(normal_user)
    
    # Login
    login_data = {
        "email": "normal2@hojaverde.com",
        "password": password,
        "remember_me": False
    }
    
    login_response = await client.post("/api/v1/auth/login", json=login_data)
    tokens = login_response.json()["tokens"]
    normal_headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    
    # Ver su propio perfil
    response = await client.get(f"/api/v1/usuarios/{normal_user.id}", headers=normal_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["email"] == "normal2@hojaverde.com"