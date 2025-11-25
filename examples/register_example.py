"""
Olivia Auth - User Registration Example

Shows how to register a new user with a license key.
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

    if not api.initialized:
        print(f"Failed to initialize: {api.last_error}")
        return

    print("App initialized!")
    print("\n=== User Registration ===")

    # Get registration info
    license_key = input("License key: ").strip()
    username = input("Choose username: ").strip()
    password = input("Choose password: ").strip()

    # Register the user
    if api.register(license_key, username, password):
        print("\nAccount created successfully!")
        print("You can now login with your username and password.")
    else:
        print(f"\nRegistration failed: {api.last_error}")

    api.close()


if __name__ == "__main__":
    main()
