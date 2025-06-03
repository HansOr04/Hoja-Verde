#!/bin/bash

# Script de despliegue seguro para Render
set -e

echo "🚀 Iniciando despliegue..."

# Verificar variables de entorno críticas
if [[ -z "$DATABASE_URL" ]]; then
    echo "❌ ERROR: DATABASE_URL no está configurada"
    exit 1
fi

if [[ -z "$SECRET_KEY" ]]; then
    echo "❌ ERROR: SECRET_KEY no está configurada"
    exit 1
fi

# Instalar dependencias
echo "📦 Instalando dependencias..."
pip install --no-cache-dir -r requirements.txt

# Ejecutar migraciones
echo "🗄️ Ejecutando migraciones..."
alembic upgrade head

# Verificar salud de la base de datos
echo "🏥 Verificando conexión a la base de datos..."
python -c "
import asyncio
from app.core.database import engine
from sqlalchemy import text

async def test_connection():
    async with engine.begin() as conn:
        result = await conn.execute(text('SELECT 1'))
        print('✅ Conexión a BD exitosa')

asyncio.run(test_connection())
"

# Crear directorios necesarios
echo "📁 Creando directorios..."
mkdir -p logs reports temp

# Configurar permisos
chmod 755 logs reports temp

echo "✅ Despliegue completado exitosamente!"