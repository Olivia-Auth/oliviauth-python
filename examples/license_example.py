"""
Olivia Auth - License Authentication Example

Shows how to authenticate users with a license key.
"""

from oliviauth import Olivia

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
    server_key="your_server_key"
)


def main():

    # Check if initialization was successful
    if not api.initialized:
        print(f"Failed to initialize: {api.last_error}")
        return

    print("App initialized successfully!")

    # Get license key from user
    license_key = input("Enter your license key: ").strip()

    # Authenticate with license
    # HWID is generated automatically if not provided
    if api.license(license_key):
        # Check subscription
        if not api.user.has_subscription():
            print("Your subscription has expired!")
            api.close()
            return

        print(f"\nWelcome, {api.user.username}!")
        print(f"IP: {api.user.ip}")
        print(f"HWID: {api.user.hwid}")
        print(f"Subscription: {api.user.format_time_left()} remaining")

        # Heartbeat runs automatically in the background
        # Your session will be kept alive

        # Your app logic here...
        input("\nPress Enter to exit...")

    else:
        print(f"\nAuthentication failed: {api.last_error}")

    # Clean up (stops heartbeat)
    api.close()


if __name__ == "__main__":
    main()
