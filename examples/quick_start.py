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
        app_vars = session.get_all_app_vars()
        welcome = session.get_app_var("welcome_message")

        print("\nAuthentication OK")
        print(f"User: {session.username}")
        print(f"Subscription active: {'yes' if session.has_subscription() else 'no'}")
        print(f"Time left: {session.subscription_time_left()}")
        print(f"App vars loaded: {len(app_vars)}")
        if welcome is not None:
            print(f"Message: {welcome}")
        return 0
    except Exception as exc:
        print(f"OliviaAuth failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if api:
            api.close()


if __name__ == "__main__":
    raise SystemExit(main())
