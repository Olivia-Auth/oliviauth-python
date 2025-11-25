"""
OliviaAuth Custom Exceptions

Provides clear, specific exceptions for different error scenarios.
"""


class OliviaAuthError(Exception):
    """Base exception for all OliviaAuth errors."""

    def __init__(self, message: str = "An error occurred"):
        self.message = message
        super().__init__(self.message)


class NotInitializedError(OliviaAuthError):
    """Raised when trying to use API before initialization."""

    def __init__(self, message: str = "App not initialized. Call init() first."):
        super().__init__(message)


class SessionExpiredError(OliviaAuthError):
    """Raised when the session has expired."""

    def __init__(self, message: str = "Session has expired. Please reinitialize."):
        super().__init__(message)


class AuthenticationError(OliviaAuthError):
    """Raised when authentication fails."""

    def __init__(self, message: str = "Authentication failed."):
        super().__init__(message)


class NotAuthenticatedError(OliviaAuthError):
    """Raised when trying to access authenticated features without auth."""

    def __init__(self, message: str = "Not authenticated. Use license() or login() first."):
        super().__init__(message)


class EncryptionError(OliviaAuthError):
    """Raised when encryption/decryption fails."""

    def __init__(self, message: str = "Encryption error occurred."):
        super().__init__(message)


class ConnectionError(OliviaAuthError):
    """Raised when connection to server fails."""

    def __init__(self, message: str = "Failed to connect to server."):
        super().__init__(message)


class HWIDMismatchError(OliviaAuthError):
    """Raised when HWID doesn't match the registered one."""

    def __init__(self, message: str = "HWID mismatch. Ask for a reset."):
        super().__init__(message)


class SubscriptionExpiredError(OliviaAuthError):
    """Raised when user's subscription has expired."""

    def __init__(self, message: str = "Your subscription has expired."):
        super().__init__(message)


class TwoFactorRequiredError(OliviaAuthError):
    """Raised when 2FA code is required but not provided."""

    def __init__(self, message: str = "Two-factor authentication code required."):
        super().__init__(message)


class UserBannedError(OliviaAuthError):
    """Raised when user is banned."""

    def __init__(self, message: str = "User is banned."):
        super().__init__(message)


class AppDisabledError(OliviaAuthError):
    """Raised when the app is disabled."""

    def __init__(self, message: str = "App is currently disabled."):
        super().__init__(message)


class VersionMismatchError(OliviaAuthError):
    """Raised when app version doesn't match server version."""

    def __init__(self, message: str = "Version mismatch. Update required."):
        super().__init__(message)


class VPNBlockedError(OliviaAuthError):
    """Raised when VPN/Proxy is detected and blocked."""

    def __init__(self, message: str = "VPN/Proxy detected. Please disable."):
        super().__init__(message)


class SSLVerificationError(OliviaAuthError):
    """Raised when SSL certificate verification fails (possible pirated server)."""

    def __init__(self, message: str = "SSL certificate verification failed. Server may be compromised."):
        super().__init__(message)
