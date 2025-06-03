import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# URL corregida
database_url = "postgresql://postgres.yrfzdutcetlquobnynvp:hojaverdeadmin@aws-0-us-east-2.pooler.supabase.com:6543/postgres"

print(f"Probando conexión con: {database_url}")

try:
    # Crear engine
    engine = create_engine(database_url)
    
    # Probar conexión
    with engine.connect() as conn:
        result = conn.execute(text("SELECT version()"))
        version = result.fetchone()[0]
        print("✅ Conexión exitosa a Supabase!")
        print(f"PostgreSQL version: {version}")
        
        # Probar permisos
        result = conn.execute(text("SELECT current_user, current_database()"))
        user_info = result.fetchone()
        print(f"Usuario conectado: {user_info[0]}")
        print(f"Base de datos: {user_info[1]}")
        
        # Verificar que podemos crear tablas
        result = conn.execute(text("SELECT has_database_privilege(current_user, current_database(), 'CREATE')"))
        can_create = result.fetchone()[0]
        print(f"Permisos para crear tablas: {'✅ Sí' if can_create else '❌ No'}")
        
except Exception as e:
    print(f"❌ Error de conexión: {e}")
    print(f"Tipo de error: {type(e).__name__}")