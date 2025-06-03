from pydantic_settings import BaseSettings
from pydantic import ConfigDict, field_validator, AnyHttpUrl
from typing import List, Optional, Union
from datetime import timedelta
import os
import secrets

class Settings(BaseSettings):
    # Configuración del modelo (Pydantic v2)
    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"  # Ignora campos extra del .env
    )
    
    # Información de la aplicación
    app_name: str = "Sistema Control Asistencia Hojaverde"
    app_version: str = "1.0.0"
    debug: bool = False
    environment: str = "production"
    port: int = 8000
    
    # Base de datos
    database_url: str
    async_database_url: Optional[str] = None
    database_test_url: Optional[str] = None
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_pool_timeout: int = 30
    db_pool_recycle: int = 3600
    
    # Supabase
    supabase_url: Optional[str] = None
    supabase_key: Optional[str] = None
    supabase_service_role_key: Optional[str] = None
    
    # Seguridad
    secret_key: str = secrets.token_urlsafe(32)
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    jwt_issuer: str = "Sistema-Asistencia-Hojaverde"
    jwt_audience: str = "hojaverde-system"
    
    # Password hashing
    bcrypt_rounds: int = 12
    
    # CORS (como strings para evitar problemas de parsing)
    cors_origins: str = '["http://localhost:3000"]'
    allowed_hosts: str = '["localhost", "127.0.0.1"]'
    
    # Rate limiting
    rate_limit_per_minute: int = 60
    rate_limit_per_hour: int = 1000
    rate_limit_per_day: int = 10000
    requests_per_minute: int = 60
    
    # Security headers
    security_headers_enabled: bool = True
    
    # Session configuration
    session_cookie_name: str = "session"
    session_max_age: int = 1800  # 30 minutos
    
    # Redis
    redis_url: str = "redis://localhost:6379"
    
    # Seguridad de contraseñas
    min_password_length: int = 8
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_numbers: bool = True
    password_require_symbols: bool = True
    
    # Sesiones
    session_timeout_minutes: int = 60
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 15
    
    # Archivos
    reports_directory: str = "./reports"
    temp_directory: str = "./temp"
    max_report_size_mb: int = 50
    max_file_size_mb: int = 10
    allowed_file_types: str = '["image/jpeg", "image/png", "application/pdf", "text/csv"]'
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "json"
    log_file: str = "./logs/app.log"
    log_max_size_mb: int = 100
    log_backup_count: int = 5
    
    # Email
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_tls: bool = True
    smtp_user: str = ""
    smtp_password: str = ""
    email_from: str = "noreply@hojaverde.com"
    
    # API Keys para servicios externos
    email_api_key: Optional[str] = None
    sms_api_key: Optional[str] = None
    
    # Deployment
    render_external_url: Optional[str] = None
    health_check_interval: int = 30
    health_check_timeout: int = 10
    
    # Monitoreo
    sentry_dsn: Optional[str] = None
    enable_metrics: bool = True
    metrics_port: int = 8001

    # Validadores para convertir strings a booleanos correctamente
    @field_validator('debug', 'password_require_uppercase', 'password_require_lowercase', 
                     'password_require_numbers', 'password_require_symbols', 'smtp_tls', 
                     'enable_metrics', 'security_headers_enabled', mode='before')
    def validate_boolean(cls, v):
        if isinstance(v, str):
            if v.lower() in ('true', '1', 'yes', 'on'):
                return True
            elif v.lower() in ('false', '0', 'no', 'off'):
                return False
        return v

    @field_validator("cors_origins", mode='before')
    def assemble_cors_origins(cls, v):
        if isinstance(v, str) and not v.startswith("["):
            return '["' + '", "'.join([i.strip() for i in v.split(",")]) + '"]'
        return v
    
    @field_validator("database_url", mode='before')
    def validate_database_url(cls, v):
        if not v:
            raise ValueError("DATABASE_URL es requerida")
        return v
    
    @field_validator("secret_key", mode='before')
    def validate_secret_key(cls, v):
        if not v or len(v) < 32:
            # Generar una clave segura si no existe
            return secrets.token_urlsafe(32)
        return v

    @property
    def cors_origins_list(self) -> List[str]:
        """Convierte la string de CORS origins a lista"""
        import json
        try:
            return json.loads(self.cors_origins)
        except:
            return ["http://localhost:3000"]
    
    @property
    def allowed_hosts_list(self) -> List[str]:
        """Convierte la string de allowed hosts a lista"""
        import json
        try:
            return json.loads(self.allowed_hosts)
        except:
            return ["localhost", "127.0.0.1"]
    
    @property
    def allowed_file_types_list(self) -> List[str]:
        """Convierte la string de file types a lista"""
        import json
        try:
            return json.loads(self.allowed_file_types)
        except:
            return ["image/jpeg", "image/png", "application/pdf", "text/csv"]

    # Propiedades calculadas para JWT
    @property
    def access_token_expire_timedelta(self) -> timedelta:
        return timedelta(minutes=self.access_token_expire_minutes)
    
    @property
    def refresh_token_expire_timedelta(self) -> timedelta:
        return timedelta(days=self.refresh_token_expire_days)

# Crear instancia global de configuración
settings = Settings()

# Configuraciones específicas por ambiente
def get_database_url() -> str:
    """Obtener URL de base de datos según el ambiente"""
    if settings.environment == "test":
        return settings.database_test_url or settings.database_url.replace("/hojaverde", "/hojaverde_test")
    return settings.database_url

def get_cors_origins() -> List[str]:
    """Obtener orígenes CORS según el ambiente"""
    if settings.debug:
        return ["http://localhost:3000", "http://localhost:8000", "http://127.0.0.1:3000"]
    return settings.cors_origins_list