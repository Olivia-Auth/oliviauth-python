"""
Olivia Auth Python SDK

A simple, secure authentication SDK for Olivia Auth - Software Licensing Platform.
Supports both HTTP and WebSocket modes with identical API.

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
except Exception:
    _has_dll = False

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

if _has_dll:
    __all__ = ["OliviaAuth", "OliviaSession"] + __all__
