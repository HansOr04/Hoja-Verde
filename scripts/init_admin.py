"""
Script para inicializar el sistema con un usuario administrador

Uso:
    python scripts/init_admin.py
    python scripts/init_admin.py --email admin@custom.com --password mypassword
"""

import asyncio
import argparse
import getpass
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_async_session_factory
from app.domain.services.usuario import usuario_service
from app.infrastructure.database.models.usuario import RolEnum
from app.presentation.schemas.usuario import UsuarioCreate
from app.core.exceptions import ConflictError

async def create_admin_user(
    email: str = "admin@hojaverde.com",
    password: str = None,
    nombres: str = "Administrador",
    apellidos: str = "Sistema"
):
    """
    Crear usuario administrador inicial
    
    Args:
        email: Email del administrador
        password: Contraseña (se solicitará si no se proporciona)
        nombres: Nombres del administrador
        apellidos: Apellidos del administrador
    """
    if not password:
        password = getpass.getpass("Ingrese la contraseña para el administrador: ")
        confirm_password = getpass.getpass("Confirme la contraseña: ")
        
        if password != confirm_password:
            print("❌ Las contraseñas no coinciden")
            return False
    
    # Validar contraseña
    from app.core.security import security_manager
    is_strong, errors = security_manager.is_password_strong(password)
    if not is_strong:
        print(f"❌ Contraseña débil:")
        for error in errors:
            print(f"   - {error}")
        return False
    
    # Crear sesión de base de datos
    session_factory = get_async_session_factory()
    async with session_factory() as session:
        try:
            # Verificar si ya existe un administrador
            existing_admin = await usuario_service.get_by_email(session, email)
            if existing_admin:
                print(f"⚠️  Ya existe un usuario con el email: {email}")
                
                overwrite = input("¿Desea actualizar la contraseña? (y/N): ")
                if overwrite.lower() not in ['y', 'yes', 'sí', 's']:
                    print("🚫 Operación cancelada")
                    return False
                
                # Actualizar contraseña
                success = await usuario_service.repository.update_password(
                    session, existing_admin.id, password
                )
                
                if success:
                    print(f"✅ Contraseña actualizada para: {email}")
                    return True
                else:
                    print("❌ Error actualizando contraseña")
                    return False
            
            # Crear nuevo usuario administrador
            admin_data = UsuarioCreate(
                email=email,
                password=password,
                nombres=nombres,
                apellidos=apellidos,
                rol=RolEnum.SUPER_ADMIN
            )
            
            admin_user = await usuario_service.create_usuario(session, admin_data)
            
            print(f"✅ Usuario administrador creado exitosamente:")
            print(f"   📧 Email: {admin_user.email}")
            print(f"   👤 Nombre: {admin_user.nombre_completo}")
            print(f"   🔑 Rol: {admin_user.rol.value}")
            print(f"   🆔 ID: {admin_user.id}")
            
            return True
            
        except ConflictError as e:
            print(f"❌ Error: {e.message}")
            return False
        except Exception as e:
            print(f"❌ Error inesperado: {e}")
            return False

async def create_sample_users():
    """Crear usuarios de ejemplo para desarrollo"""
    print("\n🔧 Creando usuarios de ejemplo...")
    
    session_factory = get_async_session_factory()
    async with session_factory() as session:
        sample_users = [
            {
                "email": "rrhh@hojaverde.com",
                "password": "Rrhh123!",
                "nombres": "María",
                "apellidos": "Recursos",
                "rol": RolEnum.RECURSOS_HUMANOS
            },
            {
                "email": "empleado@hojaverde.com",
                "password": "Empleado123!",
                "nombres": "Juan",
                "apellidos": "Pérez",
                "rol": RolEnum.EMPLEADO
            },
            {
                "email": "supervisor@hojaverde.com",
                "password": "Supervisor123!",
                "nombres": "Ana",
                "apellidos": "García",
                "rol": RolEnum.SUPERVISOR
            },
            {
                "email": "gerente@hojaverde.com",
                "password": "Gerente123!",
                "nombres": "Carlos",
                "apellidos": "López",
                "rol": RolEnum.GERENTE
            }
        ]
        
        created_count = 0
        for user_data in sample_users:
            try:
                # Verificar si el usuario ya existe
                existing_user = await usuario_service.get_by_email(session, user_data["email"])
                if existing_user:
                    print(f"⚠️  Usuario ya existe: {user_data['email']}")
                    continue
                
                # Crear usuario de ejemplo
                user_create = UsuarioCreate(
                    email=user_data["email"],
                    password=user_data["password"],
                    nombres=user_data["nombres"],
                    apellidos=user_data["apellidos"],
                    rol=user_data["rol"]
                )
                
                user = await usuario_service.create_usuario(session, user_create)
                print(f"✅ Usuario creado: {user.email} ({user.rol.value})")
                created_count += 1
                
            except ConflictError as e:
                print(f"❌ Error creando {user_data['email']}: {e.message}")
            except Exception as e:
                print(f"❌ Error inesperado creando {user_data['email']}: {e}")
        
        print(f"\n📊 Resumen: {created_count} usuarios de ejemplo creados")
        return created_count > 0

def setup_argument_parser():
    """Configurar argumentos de línea de comandos"""
    parser = argparse.ArgumentParser(
        description="Inicializar sistema con usuario administrador",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
    python scripts/init_admin.py
    python scripts/init_admin.py --email admin@custom.com --password mypassword
    python scripts/init_admin.py --samples
    python scripts/init_admin.py --email admin@test.com --samples --force
        """
    )
    
    parser.add_argument(
        "--email",
        default="admin@hojaverde.com",
        help="Email del usuario administrador (default: admin@hojaverde.com)"
    )
    
    parser.add_argument(
        "--password",
        help="Contraseña del administrador (se solicitará si no se proporciona)"
    )
    
    parser.add_argument(
        "--nombres",
        default="Administrador",
        help="Nombres del administrador (default: Administrador)"
    )
    
    parser.add_argument(
        "--apellidos",
        default="Sistema",
        help="Apellidos del administrador (default: Sistema)"
    )
    
    parser.add_argument(
        "--samples",
        action="store_true",
        help="Crear usuarios de ejemplo para desarrollo"
    )
    
    parser.add_argument(
        "--force",
        action="store_true",
        help="No solicitar confirmación para operaciones"
    )
    
    parser.add_argument(
        "--only-samples",
        action="store_true",
        help="Solo crear usuarios de ejemplo (no crear administrador)"
    )
    
    return parser

async def main():
    """Función principal"""
    parser = setup_argument_parser()
    args = parser.parse_args()
    
    print("🚀 Inicializando sistema HojaVerde...")
    print("=" * 50)
    
    success = True
    
    # Crear usuario administrador (a menos que se especifique --only-samples)
    if not args.only_samples:
        print("\n👑 Creando usuario administrador...")
        
        admin_success = await create_admin_user(
            email=args.email,
            password=args.password,
            nombres=args.nombres,
            apellidos=args.apellidos
        )
        
        if not admin_success:
            success = False
            print("❌ Error creando usuario administrador")
    
    # Crear usuarios de ejemplo si se solicita
    if args.samples or args.only_samples:
        if not args.force and not args.only_samples:
            confirm = input("\n¿Desea crear usuarios de ejemplo? (y/N): ")
            if confirm.lower() not in ['y', 'yes', 'sí', 's']:
                print("🚫 Creación de usuarios de ejemplo cancelada")
            else:
                samples_success = await create_sample_users()
                if not samples_success:
                    success = False
        else:
            samples_success = await create_sample_users()
            if not samples_success:
                success = False
    
    # Resultado final
    print("\n" + "=" * 50)
    if success:
        print("🎉 Inicialización completada exitosamente!")
        
        if not args.only_samples:
            print(f"\n🔐 Credenciales de administrador:")
            print(f"   📧 Email: {args.email}")
            print(f"   🔑 Contraseña: {'[proporcionada]' if args.password else '[ingresada interactivamente]'}")
        
        print("\n📋 Próximos pasos:")
        print("   1. Verificar que la aplicación esté funcionando")
        print("   2. Iniciar sesión con las credenciales de administrador")
        print("   3. Configurar otros aspectos del sistema según sea necesario")
        
    else:
        print("❌ Inicialización completada con errores")
        print("\n🔍 Revise los mensajes de error anteriores")
        exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n🚫 Operación cancelada por el usuario")
        exit(1)
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        exit(1)