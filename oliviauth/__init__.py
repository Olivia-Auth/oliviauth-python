"""
Olivia Auth Python SDK

A simple, secure authentication SDK for Olivia Auth - Software Licensing Platform.
Supports both HTTP and WebSocket modes with identical API.

Quick Start (WebSocket - default, with remote commands):
    >>> from oliviauth import Olivia
    >>>
    >>> api = Olivia(
    ...     owner_id="your_owner_id",
    ...     app_name="YourApp",
    ...     version="1.0.0",
    ...     server_url="https://your-server.com",
    ...     client_key="your_client_key",
    ...     server_key="your_server_key"
    ... )
    >>>
    >>> # Register command handler (server can call this remotely)
    >>> @api.on_command("show_message")
    >>> def handle_message(params):
    ...     print(f"Server says: {params['text']}")
    ...     return {"displayed": True}
    >>>
    >>> if api.license("XXXX-XXXX-XXXX-XXXX"):
    ...     print(f"Welcome {api.user.username}!")
    ...     api.wait()  # Keep listening for commands

HTTP Mode (simpler, no remote commands):
    >>> api = Olivia(..., mode="http")
"""

__version__ = "1.0.0"
__author__ = "Olivia Auth"

from .client import Olivia
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
from .hwid import generate_hwid
from .user import UserData

__all__ = [
    # Main class
    "Olivia",
    "UserData",
    # Utilities
    "generate_hwid",
    # Exceptions
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
