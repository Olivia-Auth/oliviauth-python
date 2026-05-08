# Olivia Auth Python SDK

Python SDK for Olivia Auth protected apps.

## Requirements

- Windows x64
- Python 3.8+
- The app-specific `OliviaAuth.dll` downloaded from the dashboard

## Install

```bash
pip install .\oliviauth-1.0.3+yourapp-cp38-abi3-win_amd64.whl
```

Download this wheel from the OliviaAuth dashboard for the selected app. It
already contains the matching `OliviaAuth.dll` and native binding, so your code
only passes `version` and credentials. Dashboard wheels include an app-specific
OliviaAuth.dll generated and bound by OliviaShield.

The PyPI package is useful for development/reference installs. Customer builds
should use the dashboard wheel because it binds the Python package to that
app's DLL.

This public repository does not ship a production `OliviaAuth.dll`; the
dashboard wheel is generated per app.

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

`mode` is accepted for API compatibility. App-specific dashboard DLLs currently
own the runtime transport configuration internally.

## What The Customer Ships

```text
your_app.exe or your_app.py
oliviauth package installed from the dashboard wheel
```

Do not put `owner_id`, `client_key`, `server_key`, server URL, SSL pin, or HWID
code in the customer app. The wheel/DLL handles that internally and rejects a
DLL generated for another app.

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

api = OliviaAuth(version="1.0.0", mode="socket")

session = api.login("username", "password")
if not session:
    print(api.last_error)
    raise SystemExit(1)

print(session.username)
api.close()
```

HWID is generated inside `OliviaAuth.dll` when you do not pass one. Passing
`hwid=""` intentionally authenticates without HWID.

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
| `OliviaAuth.dll could not be loaded` | Install the app-specific dashboard wheel |
| `OliviaAuth.dll is not configured for this app` | Download the wheel from the dashboard for this app |
| SSL pin / certificate error | Download a fresh wheel after the dashboard updates the pin |
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

For local testing, install the dashboard wheel and run your app before sending
the executable through Shield.
