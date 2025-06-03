from typing import Optional, Dict, Any, Tuple, List
from datetime import datetime, timedelta
from uuid import UUID
import secrets
import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.services.usuario import usuario_service
from app.infrastructure.database.models.usuario import Usuario
from app.presentation.schemas.usuario import LoginRequest
from app.presentation.schemas.auth import TokenResponse, AuthResponse
from app.core.security import security_manager
from app.core.config import settings
from app.core.exceptions import AuthenticationError, ValidationError, BusinessError

logger = logging.getLogger(__name__)

class AuthService:
    """Servicio de dominio para operaciones de autenticación"""
    
    def __init__(self):
        self.usuario_service = usuario_service
        self.security_manager = security_manager
    
    # === AUTENTICACIÓN ===
    
    async def login(
        self, 
        db: AsyncSession, 
        login_data: LoginRequest,
        request_info: Optional[Dict[str, Any]] = None
    ) -> AuthResponse:
        """
        Realizar login de usuario
        
        Args:
            db: Sesión de base de datos
            login_data: Datos de login
            request_info: Información de la request (IP, user agent, etc.)
            
        Returns:
            Respuesta de autenticación con tokens
            
        Raises:
            AuthenticationError: Si las credenciales son inválidas
        """
        try:
            # Autenticar usuario
            usuario, mensaje = await self.usuario_service.authenticate_user(
                db, login_data.email, login_data.password
            )
            
            if not usuario:
                # Log intento de login fallido
                self._log_authentication_attempt(
                    login_data.email, False, mensaje, request_info
                )
                raise AuthenticationError(mensaje)
            
            # Generar tokens
            tokens = await self._generate_tokens(db, usuario, login_data.remember_me)
            
            # Log login exitoso
            self._log_authentication_attempt(
                login_data.email, True, "Login exitoso", request_info
            )
            
            # Preparar respuesta de usuario (sin datos sensibles)
            from app.presentation.schemas.usuario import UsuarioResponse
            usuario_response = UsuarioResponse.model_validate(usuario)
            
            # Información de sesión
            session_info = {
                "login_time": datetime.utcnow().isoformat(),
                "ip_address": request_info.get("ip_address") if request_info else None,
                "user_agent": request_info.get("user_agent") if request_info else None,
                "remember_me": login_data.remember_me
            }
            
            return AuthResponse(
                message="Autenticación exitosa",
                user=usuario_response,
                tokens=tokens,
                session_info=session_info
            )
            
        except AuthenticationError:
            raise
        except Exception as e:
            logger.error(f"Error en login: {e}")
            raise BusinessError("Error interno en autenticación")
    
    async def refresh_token(
        self, 
        db: AsyncSession, 
        refresh_token: str
    ) -> TokenResponse:
        """
        Renovar token de acceso usando refresh token
        
        Args:
            db: Sesión de base de datos
            refresh_token: Token de refresh
            
        Returns:
            Nuevos tokens
            
        Raises:
            AuthenticationError: Si el refresh token es inválido
        """
        try:
            # Verificar refresh token
            payload = self.security_manager.verify_token(refresh_token, "refresh")
            if not payload:
                raise AuthenticationError("Refresh token inválido o expirado")
            
            user_id = payload.get("sub")
            if not user_id:
                raise AuthenticationError("Refresh token malformado")
            
            # Obtener usuario
            usuario = await self.usuario_service.get_by_id(db, UUID(user_id))
            if not usuario:
                raise AuthenticationError("Usuario no encontrado")
            
            # Verificar que el usuario esté activo
            if not usuario.is_active or usuario.is_blocked:
                raise AuthenticationError("Usuario inactivo o bloqueado")
            
            # Verificar que el refresh token esté en la lista de tokens activos
            token_jti = payload.get("jti")
            if token_jti and hasattr(usuario, 'tokens_activos'):
                if token_jti not in (usuario.tokens_activos or []):
                    raise AuthenticationError("Sesión invalidada")
            
            # Generar nuevo access token
            additional_claims = {
                "rol": usuario.rol.value,
                "empleado_id": str(usuario.empleado_id) if usuario.empleado_id else None
            }
            
            access_token = self.security_manager.create_access_token(
                subject=usuario.id,
                additional_claims=additional_claims
            )
            
            logger.info(f"Token renovado para usuario: {usuario.email}")
            
            return TokenResponse(
                access_token=access_token,
                refresh_token=refresh_token,  # Mantener el mismo refresh token
                token_type="bearer",
                expires_in=int(settings.access_token_expire_timedelta.total_seconds()),
                refresh_expires_in=int(settings.refresh_token_expire_timedelta.total_seconds())
            )
            
        except AuthenticationError:
            raise
        except Exception as e:
            logger.error(f"Error renovando token: {e}")
            raise BusinessError("Error interno renovando token")
    
    async def logout(
        self, 
        db: AsyncSession, 
        usuario: Usuario,
        token_jti: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Realizar logout de usuario
        
        Args:
            db: Sesión de base de datos
            usuario: Usuario que hace logout
            token_jti: JTI del token a invalidar (opcional)
            
        Returns:
            Resultado del logout
        """
        try:
            if token_jti:
                # Invalidar solo el token específico
                await usuario_service.repository.remove_active_token(
                    db, usuario.id, token_jti
                )
                logger.info(f"Logout de sesión específica para usuario: {usuario.email}")
            else:
                # Invalidar todas las sesiones
                await usuario_service.repository.invalidate_all_tokens(db, usuario.id)
                logger.info(f"Logout de todas las sesiones para usuario: {usuario.email}")
            
            return {
                "message": "Sesión cerrada exitosamente",
                "logged_out_at": datetime.utcnow().isoformat(),
                "user_id": str(usuario.id)
            }
            
        except Exception as e:
            logger.error(f"Error en logout: {e}")
            raise BusinessError("Error interno en logout")
    
    async def logout_all_sessions(
        self, 
        db: AsyncSession, 
        usuario: Usuario
    ) -> Dict[str, Any]:
        """
        Cerrar todas las sesiones de un usuario
        
        Args:
            db: Sesión de base de datos
            usuario: Usuario
            
        Returns:
            Resultado del logout
        """
        try:
            # Contar sesiones activas antes de cerrarlas
            sessions_count = len(usuario.tokens_activos or [])
            
            # Invalidar todas las sesiones
            await usuario_service.repository.invalidate_all_tokens(db, usuario.id)
            
            logger.info(f"Todas las sesiones cerradas para usuario: {usuario.email}")
            
            return {
                "message": "Todas las sesiones han sido cerradas",
                "sessions_closed": sessions_count,
                "logged_out_at": datetime.utcnow().isoformat(),
                "user_id": str(usuario.id)
            }
            
        except Exception as e:
            logger.error(f"Error cerrando todas las sesiones: {e}")
            raise BusinessError("Error interno cerrando sesiones")
    
    # === RESET DE CONTRASEÑA ===
    
    async def request_password_reset(
        self, 
        db: AsyncSession, 
        email: str
    ) -> Dict[str, Any]:
        """
        Solicitar reset de contraseña
        
        Args:
            db: Sesión de base de datos
            email: Email del usuario
            
        Returns:
            Resultado de la solicitud
        """
        try:
            # Generar token (el servicio de usuario maneja la validación)
            reset_token = await self.usuario_service.reset_password(db, email)
            
            # En producción, aquí se enviaría el email
            # Por ahora solo loggeamos (NO EN PRODUCCIÓN)
            if settings.debug:
                logger.info(f"Token de reset generado: {reset_token}")
            
            return {
                "message": "Si el email existe, se enviarán instrucciones de reset",
                "reset_token": reset_token if settings.debug else None  # Solo en desarrollo
            }
            
        except Exception as e:
            logger.error(f"Error solicitando reset de contraseña: {e}")
            # Por seguridad, siempre devolver el mismo mensaje
            return {
                "message": "Si el email existe, se enviarán instrucciones de reset"
            }
    
    async def confirm_password_reset(
        self, 
        db: AsyncSession, 
        token: str, 
        new_password: str
    ) -> Dict[str, Any]:
        """
        Confirmar reset de contraseña
        
        Args:
            db: Sesión de base de datos
            token: Token de reset
            new_password: Nueva contraseña
            
        Returns:
            Resultado de la confirmación
        """
        try:
            success = await self.usuario_service.confirm_password_reset(
                db, token, new_password
            )
            
            if success:
                logger.info("Contraseña reseteada exitosamente")
                return {
                    "message": "Contraseña cambiada exitosamente",
                    "reset_at": datetime.utcnow().isoformat()
                }
            else:
                raise BusinessError("Error reseteando contraseña")
                
        except (ValidationError, BusinessError) as e:
            raise e
        except Exception as e:
            logger.error(f"Error confirmando reset de contraseña: {e}")
            raise BusinessError("Error interno confirmando reset")
    
    # === VALIDACIÓN DE SESIÓN ===
    
    async def validate_session(
        self, 
        db: AsyncSession, 
        token: str
    ) -> Dict[str, Any]:
        """
        Validar sesión activa
        
        Args:
            db: Sesión de base de datos
            token: Token a validar
            
        Returns:
            Información de la sesión
        """
        try:
            payload = self.security_manager.verify_token(token, "access")
            if not payload:
                return {
                    "is_valid": False,
                    "reason": "Token inválido o expirado"
                }
            
            user_id = payload.get("sub")
            if not user_id:
                return {
                    "is_valid": False,
                    "reason": "Token malformado"
                }
            
            usuario = await self.usuario_service.get_by_id(db, UUID(user_id))
            if not usuario or not usuario.is_active or usuario.is_blocked:
                return {
                    "is_valid": False,
                    "reason": "Usuario inactivo o bloqueado"
                }
            
            return {
                "is_valid": True,
                "user_id": str(usuario.id),
                "email": usuario.email,
                "rol": usuario.rol.value,
                "expires_at": datetime.fromtimestamp(payload.get("exp")).isoformat(),
                "permissions": usuario.permisos_adicionales or []
            }
            
        except Exception as e:
            logger.error(f"Error validando sesión: {e}")
            return {
                "is_valid": False,
                "reason": "Error interno validando sesión"
            }
    
    # === GESTIÓN DE SESIONES ===
    
    async def get_active_sessions(
        self, 
        db: AsyncSession, 
        usuario: Usuario
    ) -> List[Dict[str, Any]]:
        """
        Obtener sesiones activas del usuario
        
        Args:
            db: Sesión de base de datos
            usuario: Usuario
            
        Returns:
            Lista de sesiones activas
        """
        try:
            sessions = []
            
            for token_jti in (usuario.tokens_activos or []):
                # En una implementación completa, aquí buscaríamos
                # información adicional de la sesión en una tabla de sesiones
                session_info = {
                    "token_id": token_jti,
                    "created_at": datetime.utcnow().isoformat(),  # Placeholder
                    "last_activity": datetime.utcnow().isoformat(),  # Placeholder
                    "is_current": False  # Se marcaría el token actual
                }
                sessions.append(session_info)
            
            return sessions
            
        except Exception as e:
            logger.error(f"Error obteniendo sesiones activas: {e}")
            return []
    
    async def revoke_session(
        self, 
        db: AsyncSession, 
        usuario: Usuario,
        token_jti: str
    ) -> bool:
        """
        Revocar una sesión específica
        
        Args:
            db: Sesión de base de datos
            usuario: Usuario
            token_jti: JTI del token a revocar
            
        Returns:
            True si se revocó exitosamente
        """
        try:
            success = await usuario_service.repository.remove_active_token(
                db, usuario.id, token_jti
            )
            
            if success:
                logger.info(f"Sesión revocada: {token_jti} para usuario: {usuario.email}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error revocando sesión: {e}")
            return False
    
    # === MÉTODOS AUXILIARES ===
    
    async def _generate_tokens(
        self, 
        db: AsyncSession, 
        usuario: Usuario,
        remember_me: bool = False
    ) -> TokenResponse:
        """
        Generar tokens de acceso y refresh
        
        Args:
            db: Sesión de base de datos
            usuario: Usuario
            remember_me: Si debe recordar la sesión
            
        Returns:
            Tokens generados
        """
        try:
            # Claims adicionales para el access token
            additional_claims = {
                "rol": usuario.rol.value,
                "empleado_id": str(usuario.empleado_id) if usuario.empleado_id else None
            }
            
            # Duración del refresh token según remember_me
            refresh_expires_delta = None
            if remember_me:
                refresh_expires_delta = timedelta(days=30)  # 30 días si recuerda
            
            # Generar tokens
            access_token = self.security_manager.create_access_token(
                subject=usuario.id,
                additional_claims=additional_claims
            )
            
            refresh_token = self.security_manager.create_refresh_token(
                subject=usuario.id,
                expires_delta=refresh_expires_delta
            )
            
            # Extraer JTI del refresh token para gestión de sesiones
            refresh_payload = self.security_manager.verify_token(refresh_token, "refresh")
            if refresh_payload and refresh_payload.get("jti"):
                await usuario_service.repository.add_active_token(
                    db, usuario.id, refresh_payload["jti"]
                )
            
            expires_in = int(settings.access_token_expire_timedelta.total_seconds())
            refresh_expires_in = int(
                refresh_expires_delta.total_seconds() if refresh_expires_delta 
                else settings.refresh_token_expire_timedelta.total_seconds()
            )
            
            return TokenResponse(
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="bearer",
                expires_in=expires_in,
                refresh_expires_in=refresh_expires_in
            )
            
        except Exception as e:
            logger.error(f"Error generando tokens: {e}")
            raise BusinessError("Error interno generando tokens")
    
    def _log_authentication_attempt(
        self, 
        email: str, 
        success: bool, 
        reason: str,
        request_info: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log intento de autenticación"""
        status = "SUCCESS" if success else "FAILED"
        log_data = {
            "event": "authentication_attempt",
            "email": email,
            "status": status,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if request_info:
            log_data.update(request_info)
        
        if success:
            logger.info(f"AUTH {status}: {email} - {reason}")
        else:
            logger.warning(f"AUTH {status}: {email} - {reason}")
        
        # En producción, esto se enviaría a un sistema de auditoría
        logger.info(f"AUDIT: {log_data}")

# Instancia global del servicio
auth_service = AuthService()