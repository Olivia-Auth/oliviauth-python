"""OliviaAuth username/password login example."""

import os
import sys

from oliviauth import OliviaAuth


def main() -> int:
    api = None
    try:
        api = OliviaAuth(
            version=os.environ.get("OLIVIA_VERSION", "1.0.0"),
            mode=os.environ.get("OLIVIA_MODE", "socket"),
        )

        username = os.environ.get("OLIVIA_USERNAME") or input("Username: ").strip()
        password = os.environ.get("OLIVIA_PASSWORD") or input("Password: ").strip()
        session = api.login(username, password)
        if not session:
            print(api.last_error, file=sys.stderr)
            return 1

        print(f"Welcome {session.username}")
        return 0
    finally:
        if api:
            api.close()


if __name__ == "__main__":
    raise SystemExit(main())
