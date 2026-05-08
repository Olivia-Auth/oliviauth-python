"""
ctypes bindings for OliviaAuth.dll.
"""

import ctypes
import os
import sys
from ctypes import c_char_p, c_int

try:
    from . import _olivia_binding
except Exception:
    _olivia_binding = None


if sys.platform != "win32":
    _lib = None
    _native = None
    _loaded_path = ""
    _load_error = "OliviaAuth protected DLL mode is only supported on Windows."
else:
    _lib = None
    _native = None
    _loaded_path = ""
    _load_errors = []
    _load_error = ""

    _here = os.path.dirname(os.path.abspath(__file__))
    _bin_dir = os.path.join(_here, "bin")
    _packaged_dll = os.path.join(_bin_dir, "OliviaAuth.dll")

    if os.path.isdir(_bin_dir) and hasattr(os, "add_dll_directory"):
        os.add_dll_directory(_bin_dir)

    if _olivia_binding is not None and hasattr(_olivia_binding, "init"):
        try:
            _olivia_binding.load(_packaged_dll)
            _native = _olivia_binding
            _loaded_path = _packaged_dll
        except Exception as exc:
            _load_error = f"{_packaged_dll}: {exc}"

    if _olivia_binding is not None and hasattr(_olivia_binding, "init"):
        _candidates = []
    elif _olivia_binding is not None:
        _candidates = [_packaged_dll]
    else:
        _candidates = [
            os.path.join(os.getcwd(), "OliviaAuth.dll"),
            os.path.join(os.path.dirname(sys.executable), "OliviaAuth.dll"),
            _packaged_dll,
            "OliviaAuth.dll",
        ]
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            _candidates.insert(0, os.path.join(sys._MEIPASS, "OliviaAuth.dll"))

    for _path in _candidates:
        try:
            if _olivia_binding is not None:
                _olivia_binding.verify(_path)
            _lib = ctypes.CDLL(_path)
            _loaded_path = _path
            break
        except OSError as exc:
            _load_errors.append(f"{_path}: {exc}")
            continue
        except Exception:
            raise
    if _native is None and _lib is None and not _load_error:
        _load_error = "\n".join(_load_errors)

    if _lib is not None:
        _SessionExpiredCb = ctypes.CFUNCTYPE(None)

        _lib.olivia_init_ex.restype = ctypes.c_void_p
        _lib.olivia_init_ex.argtypes = [
            c_char_p,
            c_char_p,
            c_char_p,
            c_char_p,
            c_char_p,
            c_char_p,
            c_char_p,
            _SessionExpiredCb,
        ]

        _lib.olivia_free.restype = None
        _lib.olivia_free.argtypes = [ctypes.c_void_p]

        _lib.olivia_license.restype = ctypes.c_void_p
        _lib.olivia_license.argtypes = [ctypes.c_void_p, c_char_p, c_char_p]

        _lib.olivia_login.restype = ctypes.c_void_p
        _lib.olivia_login.argtypes = [
            ctypes.c_void_p,
            c_char_p,
            c_char_p,
            c_char_p,
            c_char_p,
        ]

        _lib.olivia_get_app_var.restype = c_int
        _lib.olivia_get_app_var.argtypes = [ctypes.c_void_p, c_char_p, c_char_p, c_int]

        if hasattr(_lib, "olivia_get_all_app_vars"):
            _lib.olivia_get_all_app_vars.restype = c_int
            _lib.olivia_get_all_app_vars.argtypes = [ctypes.c_void_p, c_char_p, c_int]

        _lib.olivia_has_subscription.restype = c_int
        _lib.olivia_has_subscription.argtypes = [ctypes.c_void_p, c_char_p]

        _lib.olivia_webhook.restype = c_int
        _lib.olivia_webhook.argtypes = [
            ctypes.c_void_p,
            c_char_p,
            c_char_p,
            c_char_p,
            c_int,
        ]

        if hasattr(_lib, "olivia_webmenu_push_state"):
            _lib.olivia_webmenu_push_state.restype = c_int
            _lib.olivia_webmenu_push_state.argtypes = [ctypes.c_void_p, c_char_p]

        if hasattr(_lib, "olivia_heartbeat"):
            _lib.olivia_heartbeat.restype = c_int
            _lib.olivia_heartbeat.argtypes = [ctypes.c_void_p]

        if hasattr(_lib, "olivia_subscription_time_left"):
            _lib.olivia_subscription_time_left.restype = c_int
            _lib.olivia_subscription_time_left.argtypes = [ctypes.c_void_p, c_char_p, c_char_p, c_int]

        _lib.olivia_get_username.restype = c_int
        _lib.olivia_get_username.argtypes = [ctypes.c_void_p, c_char_p, c_int]

        _lib.olivia_last_error.restype = c_char_p
        _lib.olivia_last_error.argtypes = [ctypes.c_void_p]

        _lib.olivia_core_generate_hwid.restype = c_char_p
        _lib.olivia_core_generate_hwid.argtypes = []


def dll_generate_hwid() -> str:
    """Generate the hardware ID via OliviaAuth.dll."""
    if _native is not None:
        return _native.generate_hwid()
    if _lib is None:
        return ""
    value = _lib.olivia_core_generate_hwid()
    return value.decode("utf-8", errors="replace") if value else ""
