"""
OliviaAuth DLL Client

Wraps OliviaAuth.dll via the public olivia_* C ABI (oliviauth_c.h).
Uses a context-based API that returns opaque session handles.
"""

import json
import sys
from ctypes import create_string_buffer, CFUNCTYPE
from typing import Callable, Optional

from ._ffi import _lib, dll_generate_hwid

_SessionExpiredCb = CFUNCTYPE(None)


_BUF = 4096
_BUF_LARGE = 65536


def _require_dll():
    if _lib is None:
        raise RuntimeError(
            "OliviaAuth.dll could not be loaded. "
            "Place OliviaAuth.dll (and vxlib64.dll) in oliviauth/bin/ "
            "or ensure they are on PATH."
        )


class OliviaSession:
    """
    Opaque authenticated session returned by :meth:`OliviaAuth.license` /
    :meth:`OliviaAuth.login`.

    All operations that require an authenticated user go through this object.
    The session is owned by the parent :class:`OliviaAuth` context; do not
    use it after calling :meth:`OliviaAuth.close`.

    Example::

        api = OliviaAuth(version="1.0.0", mode="socket")

        session = api.license("XXXX-XXXX-XXXX-XXXX")
        if session:
            print(session.username)
            print(session.get_app_var("api_endpoint"))
    """

    def __init__(self, handle: int, ctx: int):
        self._handle = handle  # void* olivia_session_t
        self._ctx = ctx        # void* olivia_ctx_t (for last_error)

    def __bool__(self) -> bool:
        return bool(self._handle)

    # ------------------------------------------------------------------
    # User info
    # ------------------------------------------------------------------

    @property
    def username(self) -> str:
        buf = create_string_buffer(_BUF)
        n = _lib.olivia_get_username(self._handle, buf, _BUF)
        return buf.value.decode("utf-8", errors="replace") if n > 0 else ""

    def has_subscription(self, level: str = "") -> bool:
        return bool(_lib.olivia_has_subscription(self._handle, level.encode()))

    # ------------------------------------------------------------------
    # App variables
    # ------------------------------------------------------------------

    def get_app_var(self, name: str):
        buf = create_string_buffer(_BUF)
        n = _lib.olivia_get_app_var(self._handle, name.encode(), buf, _BUF)
        if n < 0:
            return ""
        raw = buf.value.decode("utf-8", errors="replace")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw

    # ------------------------------------------------------------------
    # Webhooks
    # ------------------------------------------------------------------

    def webhook(self, webhook_id: str, payload: str = "{}") -> str:
        buf = create_string_buffer(_BUF_LARGE)
        n = _lib.olivia_webhook(
            self._handle,
            webhook_id.encode(),
            payload.encode(),
            buf,
            _BUF_LARGE,
        )
        return buf.value.decode("utf-8", errors="replace") if n >= 0 else ""

    # ------------------------------------------------------------------
    # Error info
    # ------------------------------------------------------------------

    @property
    def last_error(self) -> str:
        err = _lib.olivia_last_error(self._ctx)
        return err.decode("utf-8", errors="replace") if err else ""

    def __repr__(self) -> str:
        return f"OliviaSession(username={self.username!r})"


class OliviaAuth:
    """
    Public protected-DLL API.

    Requires an app-specific OliviaAuth.dll beside the Python app. That DLL is
    downloaded from the OliviaAuth dashboard and contains the app configuration.
    """

    def __init__(
        self,
        version: str,
        mode: str = "socket",
        on_session_expired: Optional[Callable[[], None]] = None,
    ):
        if sys.platform != "win32":
            raise RuntimeError("OliviaAuth protected DLL mode is only supported on Windows.")
        _require_dll()

        self._app_name = "OliviaAuth"
        self._session: OliviaSession | None = None
        self._expired_cb_ref = None

        cb = _SessionExpiredCb(on_session_expired) if on_session_expired else _SessionExpiredCb(lambda: None)
        self._expired_cb_ref = cb
        ctx = _lib.olivia_init_ex(
            b"", b"", version.encode(),
            b"", b"", b"",
            mode.encode(), cb,
        )

        if not ctx:
            err = _lib.olivia_last_error(None)
            msg = err.decode("utf-8", errors="replace") if err else "unknown"
            raise RuntimeError(f"OliviaAuth init failed: {msg}")
        self._ctx = ctx

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def license(self, key: str, hwid: str = "") -> OliviaSession | None:
        """
        Authenticate with a license key.

        Returns an :class:`OliviaSession` on success, ``None`` on failure.
        The returned session is truthy; ``if session:`` works as expected.
        """
        handle = _lib.olivia_license(self._ctx, key.encode(), hwid.encode())
        if not handle:
            return None
        self._session = OliviaSession(handle, self._ctx)
        return self._session

    def login(
        self,
        username: str,
        password: str,
        hwid: str = "",
        twofa: str = "",
    ) -> OliviaSession | None:
        """
        Authenticate with username + password.

        Returns an :class:`OliviaSession` on success, ``None`` on failure.
        """
        handle = _lib.olivia_login(
            self._ctx,
            username.encode(),
            password.encode(),
            hwid.encode(),
            twofa.encode(),
        )
        if not handle:
            return None
        self._session = OliviaSession(handle, self._ctx)
        return self._session

    # ------------------------------------------------------------------
    # Convenience: delegate to current session
    # ------------------------------------------------------------------

    def get_app_var(self, name: str):
        if not self._session:
            raise RuntimeError("Not authenticated; call license() or login() first.")
        return self._session.get_app_var(name)

    def has_subscription(self, level: str = "") -> bool:
        if not self._session:
            return False
        return self._session.has_subscription(level)

    def webhook(self, webhook_id: str, payload: str = "{}") -> str:
        if not self._session:
            raise RuntimeError("Not authenticated; call license() or login() first.")
        return self._session.webhook(webhook_id, payload)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def authenticated(self) -> bool:
        return self._session is not None

    @property
    def last_error(self) -> str:
        err = _lib.olivia_last_error(self._ctx)
        return err.decode("utf-8", errors="replace") if err else ""

    @property
    def hwid(self) -> str:
        return dll_generate_hwid()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Release DLL resources (call on application exit)."""
        if self._ctx:
            _lib.olivia_free(self._ctx)
            self._ctx = None
            self._session = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __repr__(self) -> str:
        return (
            f"OliviaAuth(app={self._app_name!r}, "
            f"authenticated={self.authenticated})"
        )
