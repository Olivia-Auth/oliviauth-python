"""Live smoke test for get_app_var using the protected OliviaAuth DLL."""

import os
import sys

from oliviauth import OliviaAuth


def short(value: object, limit: int = 120) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[:limit] + "..."


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"Missing required env var: {name}", file=sys.stderr)
        raise SystemExit(1)
    return value


def main() -> int:
    version = os.environ.get("OLIVIA_VERSION", "1.0.0")
    mode = os.environ.get("OLIVIA_MODE", "http")
    license_key = require_env("OLIVIA_LICENSE_KEY")
    names = [
        name.strip()
        for name in os.environ.get("OLIVIA_APP_VAR_NAMES", "colors,config").split(",")
        if name.strip()
    ]

    api = OliviaAuth(version=version, mode=mode)
    try:
        session = api.license(license_key)
        if not session:
            print(f"license failed: {api.last_error}", file=sys.stderr)
            return 1

        print(f"authenticated as {session.username!r}")
        for name in names:
            value = session.get_app_var(name)
            print(f"get_app_var({name!r}) = {short(value)} ({type(value).__name__})")
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())
