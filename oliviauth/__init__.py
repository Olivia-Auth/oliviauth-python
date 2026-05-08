"""
Olivia Auth Python SDK

A simple, secure authentication SDK for Olivia Auth - Software Licensing Platform.
The dashboard wheel contains an app-specific OliviaAuth.dll. The DLL owns
transport configuration internally; the mode parameter is accepted for API
compatibility.

Quick Start:
    >>> from oliviauth import OliviaAuth
    >>>
    >>> api = OliviaAuth(version="1.0.0", mode="socket")
    >>> session = api.license("XXXX-XXXX-XXXX-XXXX")
    >>> print(session.username)
"""

__version__ = "1.0.3"
__author__ = "Olivia Auth"

from .exceptions import (
    AppDisabledError,
    AuthenticationError,
    ConnectionError,
    EncryptionError,
    HWIDMismatchError,
    NotAuthenticatedError,
    NotInitializedError,
    OliviaAuthError,
    SessionExpiredError,
    SSLVerificationError,
    SubscriptionExpiredError,
    TwoFactorRequiredError,
    UserBannedError,
    VersionMismatchError,
    VPNBlockedError,
)
try:
    from ._dll_client import OliviaAuth, OliviaSession
    _has_dll = True
    _dll_import_error = None
except Exception as exc:
    _dll_import_error = exc
    _has_dll = False

    class OliviaSession:
        """Placeholder used when the protected DLL client cannot be loaded."""

    class OliviaAuth:
        def __init__(self, *_, **__):
            raise RuntimeError(f"OliviaAuth DLL mode unavailable: {_dll_import_error}")

__all__ = [
    "OliviaAuthError",
    "NotInitializedError",
    "SessionExpiredError",
    "AuthenticationError",
    "NotAuthenticatedError",
    "EncryptionError",
    "ConnectionError",
    "HWIDMismatchError",
    "SSLVerificationError",
    "SubscriptionExpiredError",
    "TwoFactorRequiredError",
    "UserBannedError",
    "AppDisabledError",
    "VersionMismatchError",
    "VPNBlockedError",
]

__all__ = ["OliviaAuth", "OliviaSession"] + __all__
