"""Small OliviaAuth example covering the common flow."""

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

        print(f"Welcome {session.username}")
        print(f"Subscription active: {session.has_subscription()}")

        var_name = os.environ.get("OLIVIA_VAR")
        if var_name:
            print(f"{var_name}: {session.get_app_var(var_name)}")

        return 0
    finally:
        if api:
            api.close()


if __name__ == "__main__":
    raise SystemExit(main())
