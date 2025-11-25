"""
Olivia Auth - Complete Example

Demonstrates all features of the Olivia Auth Python SDK.

This example works with both modes - just change the 'mode' parameter:
  - mode="socket" (default) - WebSocket with remote commands support
  - mode="http" - Traditional HTTP requests

Both modes have the SAME API - all functions work identically!
"""

import time
from oliviauth import Olivia, OliviaAuthError

# =============================================================================
# Copy from Dashboard at https://oliviauth.xyz/dashboard
# =============================================================================
api = Olivia(
    owner_id="your_owner_id",
    app_name="YourApp",
    version="1.0.0",
    hash_check="",
    server_url="https://api.oliviauth.xyz/",
    ssl_sha256="",
    client_key="your_client_key",
    server_key="your_server_key",
    mode="socket"  # Default is "socket", change to "http" if needed
)


def print_header(title):
    print("\n" + "=" * 50)
    print(f" {title}")
    print("=" * 50)


def main():
    print_header("OliviaAuth Complete Example")

    # =========================================
    # 1. INITIALIZATION
    # =========================================
    print_header("1. Initialization")

    # Using context manager for automatic cleanup
    with api:

        if not api.initialized:
            print(f"Failed to initialize: {api.last_error}")
            return

        print("App initialized successfully!")
        print(f"Mode: {api.mode}")  # Shows "socket" or "http"
        print(f"Session ID: {api.session_id[:20]}...")

        # =========================================
        # REMOTE COMMANDS (Socket mode only)
        # =========================================
        # Register handlers for commands the server can send
        # These only work in socket mode!

        @api.on_command("show_message")
        def handle_message(params):
            print(f"\n[SERVER]: {params.get('text', '')}")
            return {"displayed": True}

        @api.on_command("reload_config")
        def handle_reload(params):
            print("\n[SERVER]: Requested reload")
            return {"status": "reloaded"}

        # =========================================
        # 2. AUTHENTICATION
        # =========================================
        print_header("2. Authentication")

        print("Choose authentication method:")
        print("1. License key")
        print("2. Username/password")
        choice = input("Enter choice (1 or 2): ").strip()

        try:
            if choice == "1":
                license_key = input("License key: ").strip()
                success = api.license(license_key)
            else:
                username = input("Username: ").strip()
                password = input("Password: ").strip()
                success = api.login(username, password)

            if not success:
                print(f"Authentication failed: {api.last_error}")
                return

        except OliviaAuthError as e:
            print(f"Error: {e}")
            return

        print(f"\nAuthenticated as: {api.user.username}")
        print(f"IP Address: {api.user.ip}")
        print(f"HWID: {api.user.hwid}")
        print(f"Account created: {time.ctime(api.user.create_date)}")
        print(f"Last login: {time.ctime(api.user.last_login)}")

        # =========================================
        # 3. SUBSCRIPTIONS
        # =========================================
        print_header("3. Subscriptions")

        # Check if user has ANY active subscription
        if not api.user.has_subscription():
            print("No active subscriptions")
            print("\nYour subscription has expired!")
            return

        active = api.user.get_active_subscription_levels()
        print(f"Active subscription levels: {', '.join(active)}")

        for level in active:
            name = api.user.get_subscription_name(level)
            time_left = api.user.format_time_left(level)
            print(f"  - Level {level} ({name}): {time_left}")

        # Check specific subscription levels
        print("\nFeature access:")
        print(f"  Basic (level 1): {'Yes' if api.user.has_subscription('1') else 'No'}")
        print(f"  Premium (level 2): {'Yes' if api.user.has_subscription('2') else 'No'}")
        print(f"  VIP (level 3): {'Yes' if api.user.has_subscription('3') else 'No'}")

        # =========================================
        # 4. USER VARIABLES
        # =========================================
        print_header("4. User Variables")

        if api.user.variables:
            print("Your variables:")
            for key, value in api.user.variables.items():
                print(f"  {key}: {value}")
        else:
            print("No user variables set")

        # =========================================
        # 5. APP VARIABLES
        # =========================================
        print_header("5. App Variables")

        # Get all app variables
        app_vars = api.get_all_app_vars()
        if app_vars:
            print("Available app variables:")
            for var in app_vars if isinstance(app_vars, list) else [app_vars]:
                print(f"  {var}")
        else:
            print("No app variables or unable to retrieve")

        # Get a specific variable
        # download_url = api.get_app_var("download_link")
        # if download_url:
        #     print(f"Download URL: {download_url}")

        # =========================================
        # 6. WEBHOOKS
        # =========================================
        print_header("6. Webhooks (if configured)")

        # Example webhook call (commented out - configure your own)
        # result = api.call_webhook(
        #     webhook_id="your_webhook_id",
        #     payload={"action": "user_login", "username": api.user.username},
        #     method="POST"
        # )
        # if result:
        #     print(f"Webhook response: {result}")
        print("Webhook example (configure your own webhook ID)")

        # =========================================
        # 7. HEARTBEAT
        # =========================================
        print_header("7. Heartbeat")

        print("Heartbeat runs automatically (default: 60 seconds)")

        # Manual heartbeat (not needed, just for demonstration)
        if api.heartbeat():
            print("Manual heartbeat: Success")

        # =========================================
        # 8. SESSION INFO
        # =========================================
        print_header("8. Session Status")

        print(f"Initialized: {api.initialized}")
        print(f"Authenticated: {api.authenticated}")
        print(f"User: {api.user.username if api.user else 'None'}")

        # =========================================
        # CLEANUP
        # =========================================
        print_header("Cleanup")

        input("\nPress Enter to exit...")
        print("Closing connection and stopping heartbeat...")

    # Context manager automatically calls api.close()
    print("Done! Connection closed.")


if __name__ == "__main__":
    main()
