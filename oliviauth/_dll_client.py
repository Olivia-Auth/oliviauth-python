"""
OliviaAuth DLL Client

Wraps OliviaAuth.dll via the public olivia_* C ABI (oliviauth_c.h).
Uses a context-based API that returns opaque session handles.
"""

from __future__ import annotations

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
            "Install the app-specific OliviaAuth wheel from the dashboard."
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

    def get_all_app_vars(self) -> dict:
        if not hasattr(_lib, "olivia_get_all_app_vars"):
            return {}
        buf = create_string_buffer(_BUF_LARGE)
        n = _lib.olivia_get_all_app_vars(self._handle, buf, _BUF_LARGE)
        if n < 0:
            return {}
        raw = buf.value.decode("utf-8", errors="replace")
        try:
            value = json.loads(raw)
            return value if isinstance(value, dict) else {}
        except json.JSONDecodeError:
            return {}

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

    def webmenu_push_state(self, values: dict) -> bool:
        if not hasattr(_lib, "olivia_webmenu_push_state"):
            return False
        return bool(_lib.olivia_webmenu_push_state(self._handle, json.dumps(values).encode()))

    def heartbeat(self) -> bool:
        if not hasattr(_lib, "olivia_heartbeat"):
            return False
        return bool(_lib.olivia_heartbeat(self._handle))

    def subscription_time_left(self, level: str = "") -> str:
        if not hasattr(_lib, "olivia_subscription_time_left"):
            return ""
        buf = create_string_buffer(_BUF)
        n = _lib.olivia_subscription_time_left(self._handle, level.encode(), buf, _BUF)
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

    Requires the app-specific OliviaAuth wheel from the dashboard. The packaged
    DLL contains the app configuration.
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

    def license(self, key: str, hwid: str | None = None) -> OliviaSession | None:
        """
        Authenticate with a license key.

        Leave ``hwid`` as ``None`` to let OliviaAuth.dll generate it. Pass
        ``hwid=""`` only when the app intentionally authenticates without HWID.

        Returns an :class:`OliviaSession` on success, ``None`` on failure.
        The returned session is truthy; ``if session:`` works as expected.
        """
        encoded_hwid = None if hwid is None else hwid.encode()
        handle = _lib.olivia_license(self._ctx, key.encode(), encoded_hwid)
        if not handle:
            return None
        self._session = OliviaSession(handle, self._ctx)
        return self._session

    def login(
        self,
        username: str,
        password: str,
        hwid: str | None = None,
        twofa: str = "",
    ) -> OliviaSession | None:
        """
        Authenticate with username + password.

        Leave ``hwid`` as ``None`` to let OliviaAuth.dll generate it. Pass
        ``hwid=""`` only when the app intentionally authenticates without HWID.

        Returns an :class:`OliviaSession` on success, ``None`` on failure.
        """
        encoded_hwid = None if hwid is None else hwid.encode()
        handle = _lib.olivia_login(
            self._ctx,
            username.encode(),
            password.encode(),
            encoded_hwid,
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

    def get_all_app_vars(self) -> dict:
        if not self._session:
            raise RuntimeError("Not authenticated; call license() or login() first.")
        return self._session.get_all_app_vars()

    def has_subscription(self, level: str = "") -> bool:
        if not self._session:
            return False
        return self._session.has_subscription(level)

    def webhook(self, webhook_id: str, payload: str = "{}") -> str:
        if not self._session:
            raise RuntimeError("Not authenticated; call license() or login() first.")
        return self._session.webhook(webhook_id, payload)

    def webmenu_push_state(self, values: dict) -> bool:
        if not self._session:
            return False
        return self._session.webmenu_push_state(values)

    def heartbeat(self) -> bool:
        if not self._session:
            return False
        return self._session.heartbeat()

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
