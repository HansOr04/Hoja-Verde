import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_root_endpoint(client: AsyncClient):
    """Test del endpoint raíz"""
    response = await client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "version" in data
    assert data["status"] == "running"

@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient):
    """Test del health check"""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "timestamp" in data
    assert "version" in data

@pytest.mark.asyncio 
async def test_rate_limiting(client: AsyncClient):
    """Test básico de rate limiting"""
    # Hacer varias requests rápidamente
    responses = []
    for _ in range(5):
        response = await client.get("/")
        responses.append(response.status_code)
    
    # Todas deberían ser exitosas con pocos requests
    assert all(status == 200 for status in responses)