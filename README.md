# Olivia Auth Python SDK

Python SDK for Olivia Auth protected apps.

## Requirements

- Windows x64
- Python 3.8+
- The app-specific `OliviaAuth.dll` downloaded from the dashboard

## Install

```bash
pip install oliviauth
```

Put `OliviaAuth.dll` beside your Python entrypoint. The DLL already contains
the app owner, app name, server URL, encryption keys, and SSL pin. Your code
only passes `version` and `mode`.

## Quick Start

```python
from oliviauth import OliviaAuth

api = OliviaAuth(version="1.0.0", mode="socket")

session = api.license(input("License key: ").strip())
if not session:
    print(api.last_error)
    raise SystemExit(1)

print(f"Welcome {session.username}")

api.close()
```

`mode` can be `"socket"` or `"http"`. Socket mode is recommended for desktop
apps.

## What The Customer Ships

```text
your_app.exe or your_app.py
OliviaAuth.dll
```

Do not put `owner_id`, `client_key`, `server_key`, server URL, SSL pin, or HWID
code in the customer app. The DLL handles that internally.

## License Auth

```python
from oliviauth import OliviaAuth

api = OliviaAuth(version="1.0.0", mode="socket")

session = api.license("XXXX-XXXX-XXXX-XXXX")
if not session:
    print(api.last_error)
    raise SystemExit(1)

if not session.has_subscription():
    print("No active subscription")
    raise SystemExit(1)

print(session.username)
api.close()
```

## Login

```python
from oliviauth import OliviaAuth

api = OliviaAuth(version="1.0.0", mode="http")

session = api.login("username", "password")
if not session:
    print(api.last_error)
    raise SystemExit(1)

print(session.username)
api.close()
```

HWID is generated inside `OliviaAuth.dll` when you do not pass one.

## App Variables

```python
api = OliviaAuth(version="1.0.0")
session = api.license("XXXX-XXXX-XXXX-XXXX")

download_url = session.get_app_var("download_url")

api.close()
```

## Errors

Use `api.last_error` after a failed authentication. DLL load/configuration
errors raise `RuntimeError` with the underlying OliviaAuth message.

| Error | Fix |
|-------|-----|
| `OliviaAuth.dll could not be loaded` | Put the app-specific DLL beside the app or on PATH |
| `OliviaAuth.dll is not configured for this app` | Download the DLL from the dashboard for this app |
| SSL pin / certificate error | Download a fresh DLL after the dashboard updates the pin |
| `HWID mismatch` | Reset the user's HWID in the dashboard |
| `Version mismatch` | Update the app version in code or dashboard |

## Examples

The `examples/` folder uses the protected DLL flow:

| File | Purpose |
|------|---------|
| `quick_start.py` | Minimal license auth |
| `license_example.py` | License auth with subscription check |
| `login_example.py` | Username/password auth |
| `subscription_example.py` | Subscription check |
| `download_example.py` | Private download after auth |
| `websocket_example.py` | Socket mode app |
| `complete_example.py` | Common calls in one file |

## OliviaShield

OliviaShield protects your compiled app and returns a bundle containing the
protected executable plus `OliviaAuth.dll`.

For local testing, download `OliviaAuth.dll` from the app settings page and run
your app beside that DLL before sending the executable through Shield.
