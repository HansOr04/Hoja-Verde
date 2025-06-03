import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# URL corregida
database_url = "postgresql://postgres.yrfzdutcetlquobnynvp:hojaverdeadmin@aws-0-us-east-2.pooler.supabase.com:6543/postgres"

try:
    engine = create_engine(database_url)
    
    with engine.connect() as conn:
        print("🔍 Verificando tablas creadas en Supabase...\n")
        
        # Obtener lista de tablas
        result = conn.execute(text("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            ORDER BY table_name
        """))
        
        tables = result.fetchall()
        
        if tables:
            print("✅ Tablas encontradas:")
            for table in tables:
                print(f"  📋 {table[0]}")
                
            print(f"\n📊 Total de tablas: {len(tables)}")
            
            # Verificar las tablas específicas de nuestro modelo
            expected_tables = ['empleados', 'registros_diarios', 'alimentacion', 'alembic_version']
            found_tables = [table[0] for table in tables]
            
            print(f"\n🎯 Verificando tablas del modelo:")
            for expected in expected_tables:
                if expected in found_tables:
                    print(f"  ✅ {expected}")
                else:
                    print(f"  ❌ {expected} (faltante)")
        else:
            print("❌ No se encontraron tablas en la base de datos")
            
except Exception as e:
    print(f"❌ Error: {e}")