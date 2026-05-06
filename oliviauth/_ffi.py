"""
ctypes bindings for OliviaAuth.dll.
"""

import ctypes
import os
import sys
from ctypes import c_char_p, c_int, c_size_t


if sys.platform != "win32":
    _lib = None
else:
    _lib = None

    _here = os.path.dirname(os.path.abspath(__file__))
    _bin_dir = os.path.join(_here, "bin")

    if os.path.isdir(_bin_dir) and hasattr(os, "add_dll_directory"):
        os.add_dll_directory(_bin_dir)

    _candidates = [
        os.path.join(os.getcwd(), "OliviaAuth.dll"),
        os.path.join(os.path.dirname(sys.executable), "OliviaAuth.dll"),
        os.path.join(_bin_dir, "OliviaAuth.dll"),
        "OliviaAuth.dll",
    ]
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        _candidates.insert(0, os.path.join(sys._MEIPASS, "OliviaAuth.dll"))

    for _path in _candidates:
        try:
            _lib = ctypes.CDLL(_path)
            break
        except OSError:
            continue

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

        _lib.olivia_get_username.restype = c_int
        _lib.olivia_get_username.argtypes = [ctypes.c_void_p, c_char_p, c_int]

        _lib.olivia_last_error.restype = c_char_p
        _lib.olivia_last_error.argtypes = [ctypes.c_void_p]

        _lib.olivia_core_generate_hwid.restype = None
        _lib.olivia_core_generate_hwid.argtypes = [ctypes.c_char_p, c_size_t]


def dll_generate_hwid() -> str:
    """Generate the hardware ID via OliviaAuth.dll."""
    if _lib is None:
        return ""
    buf = ctypes.create_string_buffer(256)
    _lib.olivia_core_generate_hwid(buf, c_size_t(256))
    return buf.value.decode("utf-8", errors="replace")
