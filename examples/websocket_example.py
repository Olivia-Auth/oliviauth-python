"""OliviaAuth socket mode example."""

import os
import sys
import time

from oliviauth import OliviaAuth


def main() -> int:
    api = None
    try:
        api = OliviaAuth(version=os.environ.get("OLIVIA_VERSION", "1.0.0"), mode="socket")

        license_key = os.environ.get("OLIVIA_LICENSE_KEY") or input("License key: ").strip()
        session = api.license(license_key)
        if not session:
            print(api.last_error, file=sys.stderr)
            return 1

        print(f"Welcome {session.username}")
        print("Socket session is active. Press Ctrl+C to exit.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        return 0
    finally:
        if api:
            api.close()


if __name__ == "__main__":
    raise SystemExit(main())
