"""Live audit for the public protected-DLL Python API."""

import os
import sys

import oliviauth
from oliviauth import OliviaAuth


def check(condition: bool, label: str) -> bool:
    print(f"  [{'PASS' if condition else 'FAIL'}] {label}")
    return condition


def short(value: object, limit: int = 120) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[:limit] + "..."


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"Missing required env var: {name}", file=sys.stderr)
        raise SystemExit(1)
    return value


def auth_round(mode: str, license_key: str, version: str) -> bool:
    api = OliviaAuth(version=version, mode=mode)
    try:
        ok = check(bool(api.hwid), f"{mode} DLL-generated HWID is available")
        session = api.license(license_key)
        ok &= check(session is not None, f"{mode} license() returned a session")
        if not session:
            print(f"    last_error: {api.last_error}")
            return False

        ok &= check(bool(session.username), f"{mode} username = {session.username!r}")
        ok &= check(session.has_subscription(), f"{mode} has active subscription")

        for name in os.environ.get("OLIVIA_APP_VAR_NAMES", "colors,config").split(","):
            name = name.strip()
            if not name:
                continue
            value = session.get_app_var(name)
            ok &= check(value != "", f"{mode} get_app_var({name!r}) = {short(value)}")
        return ok
    finally:
        api.close()


def main() -> int:
    license_key = require_env("OLIVIA_LICENSE_KEY")
    version = os.environ.get("OLIVIA_VERSION", "1.0.0")

    ok = True
    print("\n[1] Public package surface")
    ok &= check(hasattr(oliviauth, "OliviaAuth"), "OliviaAuth is exported")
    ok &= check(not hasattr(oliviauth, "Olivia"), "legacy Olivia client is not exported")

    print("\n[2] HTTP mode")
    ok &= auth_round("http", license_key, version)

    print("\n[3] Socket mode")
    ok &= auth_round("socket", license_key, version)

    print("\n=== Audit complete ===")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
