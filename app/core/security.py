from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Union
from uuid import UUID
import secrets
import logging

from jose import JWTError, jwt
from passlib.context import CryptContext
from passlib.hash import bcrypt

from app.core.config import settings

logger = logging.getLogger(__name__)

# Configuración del contexto de hash de contraseñas
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=settings.bcrypt_rounds
)

class SecurityManager:
    """Manejador centralizado de operaciones de seguridad"""
    
    def __init__(self):
        self.secret_key = settings.secret_key
        self.algorithm = settings.algorithm
        self.pwd_context = pwd_context
    
    # === MANEJO DE CONTRASEÑAS ===
    
    def hash_password(self, password: str) -> str:
        """
        Crear hash seguro de una contraseña
        
        Args:
            password: Contraseña en texto plano
            
        Returns:
            Hash de la contraseña
        """
        try:
            hashed = self.pwd_context.hash(password)
            logger.debug("Contraseña hasheada exitosamente")
            return hashed
        except Exception as e:
            logger.error(f"Error hasheando contraseña: {e}")
            raise
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verificar si una contraseña coincide con su hash
        
        Args:
            plain_password: Contraseña en texto plano
            hashed_password: Hash almacenado
            
        Returns:
            True si la contraseña es correcta
        """
        try:
            is_valid = self.pwd_context.verify(plain_password, hashed_password)
            logger.debug(f"Verificación de contraseña: {'exitosa' if is_valid else 'fallida'}")
            return is_valid
        except Exception as e:
            logger.error(f"Error verificando contraseña: {e}")
            return False
    
    def needs_rehash(self, hashed_password: str) -> bool:
        """
        Verificar si un hash necesita ser regenerado (por cambios en configuración)
        
        Args:
            hashed_password: Hash existente
            
        Returns:
            True si necesita rehash
        """
        return self.pwd_context.needs_update(hashed_password)
    
    # === MANEJO DE JWT TOKENS ===
    
    def create_access_token(
        self, 
        subject: Union[str, UUID], 
        expires_delta: Optional[timedelta] = None,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Crear token de acceso JWT
        
        Args:
            subject: Identificador del usuario (UUID o email)
            expires_delta: Tiempo de expiración personalizado
            additional_claims: Claims adicionales para el token
            
        Returns:
            Token JWT codificado
        """
        try:
            if expires_delta:
                expire = datetime.utcnow() + expires_delta
            else:
                expire = datetime.utcnow() + settings.access_token_expire_timedelta
            
            # Claims básicos
            to_encode = {
                "sub": str(subject),
                "exp": expire,
                "iat": datetime.utcnow(),
                "type": "access"
            }
            
            # Agregar claims adicionales si se proporcionan
            if additional_claims:
                to_encode.update(additional_claims)
            
            encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
            logger.debug(f"Token de acceso creado para sujeto: {subject}")
            return encoded_jwt
            
        except Exception as e:
            logger.error(f"Error creando token de acceso: {e}")
            raise
    
    def create_refresh_token(
        self, 
        subject: Union[str, UUID],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Crear token de refresh JWT
        
        Args:
            subject: Identificador del usuario
            expires_delta: Tiempo de expiración personalizado
            
        Returns:
            Token JWT de refresh
        """
        try:
            if expires_delta:
                expire = datetime.utcnow() + expires_delta
            else:
                expire = datetime.utcnow() + settings.refresh_token_expire_timedelta
            
            to_encode = {
                "sub": str(subject),
                "exp": expire,
                "iat": datetime.utcnow(),
                "type": "refresh",
                "jti": secrets.token_urlsafe(16)  # JWT ID único
            }
            
            encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
            logger.debug(f"Token de refresh creado para sujeto: {subject}")
            return encoded_jwt
            
        except Exception as e:
            logger.error(f"Error creando token de refresh: {e}")
            raise
    
    def verify_token(self, token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
        """
        Verificar y decodificar un token JWT
        
        Args:
            token: Token JWT a verificar
            token_type: Tipo de token esperado ("access" o "refresh")
            
        Returns:
            Payload del token si es válido, None si no
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Verificar que sea el tipo de token correcto
            if payload.get("type") != token_type:
                logger.warning(f"Tipo de token incorrecto. Esperado: {token_type}, Recibido: {payload.get('type')}")
                return None
            
            # Verificar que el token no haya expirado
            if datetime.utcnow() > datetime.fromtimestamp(payload.get("exp", 0)):
                logger.debug("Token expirado")
                return None
            
            logger.debug(f"Token {token_type} verificado exitosamente")
            return payload
            
        except JWTError as e:
            logger.warning(f"Error verificando token JWT: {e}")
            return None
        except Exception as e:
            logger.error(f"Error inesperado verificando token: {e}")
            return None
    
    def extract_subject_from_token(self, token: str) -> Optional[str]:
        """
        Extraer el subject (usuario) de un token sin verificar completamente
        
        Args:
            token: Token JWT
            
        Returns:
            Subject del token o None
        """
        try:
            # Decodificar sin verificar (solo para obtener el subject)
            unverified_payload = jwt.get_unverified_claims(token)
            return unverified_payload.get("sub")
        except Exception as e:
            logger.warning(f"No se pudo extraer subject del token: {e}")
            return None
    
    # === GENERADORES DE TOKENS SEGUROS ===
    
    def generate_password_reset_token(self, email: str) -> str:
        """
        Generar token para reset de contraseña
        
        Args:
            email: Email del usuario
            
        Returns:
            Token de reset
        """
        expire = datetime.utcnow() + timedelta(hours=1)  # 1 hora para reset
        to_encode = {
            "sub": email,
            "exp": expire,
            "type": "password_reset",
            "iat": datetime.utcnow()
        }
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    def verify_password_reset_token(self, token: str) -> Optional[str]:
        """
        Verificar token de reset de contraseña
        
        Args:
            token: Token de reset
            
        Returns:
            Email del usuario si el token es válido
        """
        payload = self.verify_token(token, "password_reset")
        if payload:
            return payload.get("sub")
        return None
    
    def generate_api_key(self, length: int = 32) -> str:
        """
        Generar API key segura
        
        Args:
            length: Longitud de la clave
            
        Returns:
            API key generada
        """
        return secrets.token_urlsafe(length)
    
    # === VALIDACIONES DE SEGURIDAD ===
    
    def is_password_strong(self, password: str) -> tuple[bool, list[str]]:
        """
        Validar la fortaleza de una contraseña
        
        Args:
            password: Contraseña a validar
            
        Returns:
            Tupla (es_fuerte, lista_de_errores)
        """
        errors = []
        
        if len(password) < 8:
            errors.append("La contraseña debe tener al menos 8 caracteres")
        
        if not any(c.isupper() for c in password):
            errors.append("La contraseña debe contener al menos una mayúscula")
        
        if not any(c.islower() for c in password):
            errors.append("La contraseña debe contener al menos una minúscula")
        
        if not any(c.isdigit() for c in password):
            errors.append("La contraseña debe contener al menos un número")
        
        if not any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password):
            errors.append("La contraseña debe contener al menos un carácter especial")
        
        # Verificar patrones comunes débiles
        weak_patterns = ["123456", "password", "qwerty", "abc123", "admin"]
        if any(pattern in password.lower() for pattern in weak_patterns):
            errors.append("La contraseña contiene patrones comunes inseguros")
        
        return len(errors) == 0, errors

# Instancia global del manejador de seguridad
security_manager = SecurityManager()

# Funciones de conveniencia para mantener compatibilidad
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verificar contraseña (función de conveniencia)"""
    return security_manager.verify_password(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hashear contraseña (función de conveniencia)"""
    return security_manager.hash_password(password)

def create_access_token(subject: Union[str, UUID], expires_delta: Optional[timedelta] = None) -> str:
    """Crear token de acceso (función de conveniencia)"""
    return security_manager.create_access_token(subject, expires_delta)

def verify_token(token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
    """Verificar token (función de conveniencia)"""
    return security_manager.verify_token(token, token_type)