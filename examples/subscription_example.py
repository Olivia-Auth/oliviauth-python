"""OliviaAuth subscription check example."""

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

        license_key = os.environ.get("OLIVIA_LICENSE_KEY") or input("License key: ").strip()
        session = api.license(license_key)
        if not session:
            print(api.last_error, file=sys.stderr)
            return 1

        if not session.has_subscription():
            print("No active subscription.", file=sys.stderr)
            return 1

        print(f"{session.username} has an active subscription")
        return 0
    finally:
        if api:
            api.close()


if __name__ == "__main__":
    raise SystemExit(main())
