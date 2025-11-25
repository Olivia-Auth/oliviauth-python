# Olivia Auth Python SDK

Simple and secure Python SDK for Olivia Auth - Software Licensing Platform.

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Or install as package
pip install .

# With WebSocket support (recommended)
pip install .[websocket]
```

## Quick Start

```python
from oliviauth import Olivia

# Create client (WebSocket mode by default)
api = Olivia(
    owner_id="your_owner_id",
    app_name="YourApp",
    version="1.0.0",
    server_url="https://your-server.com",
    client_key="your_client_key",
    server_key="your_server_key"
)

# Authenticate with license
if api.license("XXXX-XXXX-XXXX-XXXX"):
    print(f"Welcome {api.user.username}!")

    # Check subscription
    if api.user.has_subscription("1"):
        print("Premium features unlocked!")
else:
    print(f"Failed: {api.last_error}")

# Close when done
api.close()
```

## Features

- **Dual Mode**: WebSocket (default) or HTTP - same API for both
- **Automatic Encryption**: RSA-2048 + AES-256-GCM
- **Auto HWID**: Hardware ID generated automatically
- **Auto Heartbeat**: Keeps session alive in background
- **Auto Watchdog**: Kills app if authentication is lost (security)
- **Remote Commands**: Server can send commands to clients (WebSocket mode)
- **Subscription Management**: Easy subscription verification
- **2FA Support**: Two-factor authentication
- **Context Manager**: Works with `with` statement

## Modes

### WebSocket Mode (Default)
```python
api = Olivia(..., mode="socket")  # or just Olivia(...)
```
- Real-time connection
- Server can push commands to client
- More efficient heartbeat
- Recommended for desktop apps

### HTTP Mode
```python
api = Olivia(..., mode="http")
```
- Traditional REST requests
- Simpler, no persistent connection
- Good for scripts and simple tools

Both modes have **identical API** - all functions work the same way!

## Authentication

### With License Key

```python
if api.license("XXXX-XXXX-XXXX-XXXX"):
    print(f"Authenticated as: {api.user.username}")
```

### With Username/Password

```python
if api.login("username", "password"):
    print("Login successful!")

# With 2FA
if api.login("username", "password", two_factor_code="123456"):
    print("Login with 2FA successful!")
```

### Register New User

```python
if api.register("LICENSE_KEY", "new_username", "password"):
    print("Account created!")
```

## Subscriptions

```python
# Has any active subscription?
if api.user.has_subscription():
    print("User is active")

# Has specific subscription level?
if api.user.has_subscription("1"):
    print("Basic plan active")

# Get plan name
name = api.user.get_subscription_name("1")  # "Basic"

# Time remaining (seconds)
seconds = api.user.get_subscription_time_left("1")

# Time remaining (formatted)
time_left = api.user.format_time_left("1")  # "30 days"

# List active levels
levels = api.user.get_active_subscription_levels()  # ["1", "2"]

# Is lifetime?
if api.user.is_lifetime("1"):
    print("Lifetime subscription!")
```

## Remote Commands (WebSocket Only)

```python
api = Olivia(...)

# Register command handler
@api.on_command("show_message")
def handle_message(params):
    print(f"Server says: {params['text']}")
    return {"displayed": True}

# Authenticate
api.license("XXXX-XXXX-XXXX-XXXX")

# Keep connection alive to receive commands
api.wait()
```

## App Variables

```python
# Get single variable
download_url = api.get_app_var("download_link")

# Get all variables
all_vars = api.get_all_app_vars()
```

## Webhooks

```python
result = api.call_webhook(
    webhook_id="your_webhook_id",
    payload={"action": "login", "user": api.user.username},
    method="POST"
)
```

## File Downloads

Download files from your server - supports both PUBLIC and PRIVATE downloads.

### Private Downloads (requires authentication + subscription)

```python
# Authenticate first
api = Olivia(...)
api.license("XXXX-XXXX")

# Download file (automatically uses your session)
api.download_file("download_id", "update.zip")
```

### Public Downloads (no authentication needed)

```python
# Download without authentication
Olivia.quick_download(
    server_url="https://api.oliviauth.xyz",
    download_id="download_id",
    save_path="installer.zip"
)
```

### Check Download Info

```python
info = api.get_download_info("download_id")
print(f"File: {info['name']} ({info['fileSize']} bytes)")
print(f"Requires auth: {info['authenticated']}")
```

## Error Handling

```python
from oliviauth import (
    Olivia,
    NotInitializedError,
    AuthenticationError,
    HWIDMismatchError,
    SubscriptionExpiredError,
    TwoFactorRequiredError,
    UserBannedError
)

try:
    api = Olivia(...)
    api.license("XXX")
except NotInitializedError:
    print("App not initialized")
except HWIDMismatchError:
    print("HWID mismatch - request reset")
except SubscriptionExpiredError:
    print("Subscription expired")
except TwoFactorRequiredError:
    print("2FA code required")
except UserBannedError:
    print("User is banned")
except AuthenticationError as e:
    print(f"Error: {e}")

# Or use last_error for simple error handling
if not api.license("XXX"):
    print(f"Failed: {api.last_error}")
```

## Context Manager

```python
with Olivia(
    owner_id="...",
    app_name="...",
    version="...",
    server_url="...",
    client_key="...",
    server_key="..."
) as api:
    if api.license("XXX"):
        # Your code here
        pass
# api.close() called automatically
```

## User Data

After authentication, `api.user` contains:

```python
api.user.username          # Username
api.user.subscriptions     # Dict of subscriptions
api.user.ip                # User IP address
api.user.hwid              # Hardware ID
api.user.variables         # User variables
api.user.create_date       # Creation date (timestamp)
api.user.last_login        # Last login (timestamp)
```

## Configuration

```python
api = Olivia(
    owner_id="...",           # Required: your owner ID
    app_name="...",           # Required: app name
    version="...",            # Required: app version
    server_url="...",         # Required: server URL
    client_key="...",         # Required: client encryption key
    server_key="...",         # Required: server encryption key
    mode="socket",            # Optional: "socket" (default) or "http"
    auto_init=True,           # Optional: auto-initialize (default: True)
    auto_exit=True,           # Optional: exit app if auth lost (default: True)
    heartbeat_interval=30,    # Optional: heartbeat interval in seconds
)
```

## Examples

See the `examples/` folder for complete examples:

- `quick_start.py` - Minimal example to get started
- `license_example.py` - License authentication
- `login_example.py` - Username/password login
- `register_example.py` - Register new user
- `subscription_example.py` - Subscription management
- `websocket_example.py` - WebSocket with remote commands
- `complete_example.py` - All features demonstrated

## Available Methods

### Olivia

| Method | Description |
|--------|-------------|
| `init()` | Initialize connection (automatic by default) |
| `license(key, hwid=None)` | Authenticate with license |
| `login(user, pass, hwid=None, 2fa=None)` | Login with credentials |
| `register(license, user, pass, hwid=None)` | Register new user |
| `heartbeat()` | Send heartbeat (automatic) |
| `get_app_var(name)` | Get app variable |
| `get_all_app_vars()` | Get all app variables |
| `call_webhook(id, payload, ...)` | Call webhook |
| `on_command(name)` | Decorator for remote commands |
| `wait()` | Keep connection alive for commands |
| `close()` | Close connection |

### UserData

| Method | Description |
|--------|-------------|
| `has_subscription(level=None)` | Check active subscription |
| `get_subscription_name(level)` | Get subscription name |
| `get_subscription_expiry(level)` | Get expiry timestamp |
| `get_subscription_time_left(level)` | Get seconds remaining |
| `get_active_subscription_levels()` | List active levels |
| `format_time_left(level)` | Get formatted time remaining |
| `is_lifetime(level)` | Check if lifetime |
| `get_variable(name, default=None)` | Get user variable |

## Common Errors

| Error | Solution |
|-------|----------|
| "App not initialized" | Check owner_id, app_name and server_url |
| "Session expired" | Re-initialize the client |
| "HWID mismatch" | Request HWID reset from admin |
| "Subscription expired" | Renew subscription |
| "User is banned" | Contact support |
| "VPN/Proxy detected" | Disable VPN/Proxy |
| "Version mismatch" | Update your application |

## Support

- Issues: [GitHub Issues](https://github.com/Olivia-Auth/oliviauth-python/issues)
- Documentation: [GitHub README](https://github.com/Olivia-Auth/oliviauth-python#readme)

## License

MIT License - see LICENSE file for details.
