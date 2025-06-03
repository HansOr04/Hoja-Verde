import pytest
from httpx import AsyncClient
from uuid import uuid4

@pytest.mark.asyncio
async def test_crear_empleado_exitoso(client: AsyncClient):
    """Test crear empleado con datos válidos"""
    empleado_data = {
        "cedula": "1234567890",
        "nombres": "Juan Carlos",
        "apellidos": "Pérez González",
        "area": "Producción",
        "cargo": "Trabajador Agrícola",
        "jornada_horas": 8.0,
        "unidad_productiva": "Cultivo de Rosas"
    }
    
    response = await client.post("/api/v1/empleados/", json=empleado_data)
    assert response.status_code == 201
    
    data = response.json()
    assert data["cedula"] == empleado_data["cedula"]
    assert data["nombres"] == empleado_data["nombres"]
    assert data["apellidos"] == empleado_data["apellidos"]
    assert data["estado"] == "activo"
    assert "id" in data
    assert "codigo_qr" in data

@pytest.mark.asyncio
async def test_crear_empleado_cedula_invalida(client: AsyncClient):
    """Test crear empleado con cédula inválida"""
    empleado_data = {
        "cedula": "123456789",  # Solo 9 dígitos
        "nombres": "Juan",
        "apellidos": "Pérez",
        "area": "Producción",
        "cargo": "Trabajador Agrícola"
    }
    
    response = await client.post("/api/v1/empleados/", json=empleado_data)
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_crear_empleado_area_invalida(client: AsyncClient):
    """Test crear empleado con área inválida"""
    empleado_data = {
        "cedula": "1234567890",
        "nombres": "Juan",
        "apellidos": "Pérez",
        "area": "Área Inexistente",
        "cargo": "Trabajador Agrícola"
    }
    
    response = await client.post("/api/v1/empleados/", json=empleado_data)
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_listar_empleados(client: AsyncClient):
    """Test listar empleados con paginación"""
    response = await client.get("/api/v1/empleados/")
    assert response.status_code == 200
    
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert "size" in data
    assert "pages" in data
    assert "has_next" in data
    assert "has_prev" in data

@pytest.mark.asyncio
async def test_buscar_empleados(client: AsyncClient):
    """Test búsqueda de empleados"""
    response = await client.get("/api/v1/empleados/search?q=Juan")
    assert response.status_code == 200
    
    data = response.json()
    assert "items" in data

@pytest.mark.asyncio
async def test_obtener_empleado_inexistente(client: AsyncClient):
    """Test obtener empleado que no existe"""
    empleado_id = str(uuid4())
    response = await client.get(f"/api/v1/empleados/{empleado_id}")
    assert response.status_code == 404

@pytest.mark.asyncio
async def test_obtener_estadisticas(client: AsyncClient):
    """Test obtener estadísticas de empleados"""
    response = await client.get("/api/v1/empleados/stats/general")
    assert response.status_code == 200
    
    data = response.json()
    assert "total_activos" in data
    assert "total_general" in data
    assert "por_area" in data