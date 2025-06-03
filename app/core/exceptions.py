"""Excepciones personalizadas para el dominio de negocio"""

class BaseAppException(Exception):
    """Excepción base de la aplicación"""
    def __init__(self, message: str, code: str = None):
        self.message = message
        self.code = code
        super().__init__(self.message)

class ValidationError(BaseAppException):
    """Error de validación de datos"""
    def __init__(self, message: str):
        super().__init__(message, "VALIDATION_ERROR")

class BusinessError(BaseAppException):
    """Error de lógica de negocio"""
    def __init__(self, message: str):
        super().__init__(message, "BUSINESS_ERROR")

class NotFoundError(BaseAppException):
    """Recurso no encontrado"""
    def __init__(self, resource: str, identifier: str = None):
        message = f"{resource} no encontrado"
        if identifier:
            message += f": {identifier}"
        super().__init__(message, "NOT_FOUND")

class AuthenticationError(BaseAppException):
    """Error de autenticación"""
    def __init__(self, message: str = "Credenciales inválidas"):
        super().__init__(message, "AUTH_ERROR")

class AuthorizationError(BaseAppException):
    """Error de autorización"""
    def __init__(self, message: str = "No tiene permisos para esta acción"):
        super().__init__(message, "AUTHORIZATION_ERROR")

class ConflictError(BaseAppException):
    """Error de conflicto (recurso ya existe)"""
    def __init__(self, message: str):
        super().__init__(message, "CONFLICT_ERROR")