"""
Olivia Auth - Login Example

Shows how to authenticate users with username/password.
"""

from oliviauth import Olivia, TwoFactorRequiredError

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

    # Get credentials
    username = input("Username: ").strip()
    password = input("Password: ").strip()

    try:
        if api.login(username, password):
            # Check subscription
            if not api.user.has_subscription():
                print("Your subscription has expired!")
                api.close()
                return

            print(f"\nWelcome back, {api.user.username}!")
            print(f"Subscription: {api.user.format_time_left()} remaining")

            # Your app logic here...
            input("\nPress Enter to exit...")
        else:
            print(f"\nLogin failed: {api.last_error}")

    except TwoFactorRequiredError:
        # Handle 2FA if enabled on account
        code = input("Enter 2FA code: ").strip()

        if api.login(username, password, two_factor_code=code):
            # Check subscription
            if not api.user.has_subscription():
                print("Your subscription has expired!")
                api.close()
                return

            print(f"\nWelcome back, {api.user.username}!")
            print(f"Subscription: {api.user.format_time_left()} remaining")
        else:
            print(f"\nLogin failed: {api.last_error}")

    api.close()


if __name__ == "__main__":
    main()
