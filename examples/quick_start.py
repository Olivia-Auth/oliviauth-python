"""
OliviaAuth Python quick start.

Install the app-specific OliviaAuth wheel downloaded from the dashboard before
running or packaging the app.
"""

import os
import sys

from oliviauth import OliviaAuth


def main() -> int:
    version = os.environ.get("OLIVIA_VERSION", "1.0.0")
    mode = os.environ.get("OLIVIA_MODE", "socket")
    key = os.environ.get("OLIVIA_LICENSE_KEY") or input("License key: ").strip()

    api = None
    try:
        api = OliviaAuth(version=version, mode=mode)
        session = api.license(key)
        if not session:
            print(f"Authentication failed: {api.last_error}", file=sys.stderr)
            return 1
        if not session.has_subscription():
            print("No active subscription.", file=sys.stderr)
            return 1
        print(f"Welcome {session.username}")
        return 0
    except Exception as exc:
        print(f"OliviaAuth failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if api:
            api.close()


if __name__ == "__main__":
    raise SystemExit(main())
