"""
Olivia Auth - Subscription Management Example

Shows how to check and manage user subscriptions.
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

    license_key = input("Enter your license key: ").strip()

    if not api.license(license_key):
        print(f"Authentication failed: {api.last_error}")
        return

    print(f"\nWelcome, {api.user.username}!")
    print("\n" + "=" * 40)
    print("SUBSCRIPTION STATUS")
    print("=" * 40)

    # Check if user has ANY active subscription
    if api.user.has_subscription():
        print("Status: ACTIVE")

        # Get all active subscription levels
        active_levels = api.user.get_active_subscription_levels()
        print(f"Active plans: {', '.join(active_levels)}")

        # Show details for each subscription
        print("\nPlan Details:")
        for level in active_levels:
            name = api.user.get_subscription_name(level)
            time_left = api.user.format_time_left(level)
            is_lifetime = api.user.is_lifetime(level)

            print(f"  Level {level}: {name}")
            print(f"    Time remaining: {time_left}")
            if is_lifetime:
                print("    Type: Lifetime (never expires)")

    else:
        print("Status: NO ACTIVE SUBSCRIPTION")

    print("\n" + "=" * 40)
    print("FEATURE ACCESS")
    print("=" * 40)

    # Example: Control features based on subscription level
    if api.user.has_subscription("1"):
        print("Basic features: UNLOCKED")
    else:
        print("Basic features: LOCKED")

    if api.user.has_subscription("2"):
        print("Premium features: UNLOCKED")
    else:
        print("Premium features: LOCKED")

    if api.user.has_subscription("3"):
        print("VIP features: UNLOCKED")
    else:
        print("VIP features: LOCKED")

    # Example: Show different content based on subscription
    print("\n" + "=" * 40)
    print("CONTENT ACCESS")
    print("=" * 40)

    if api.user.has_subscription("3"):
        print("Welcome VIP member! You have access to everything.")
    elif api.user.has_subscription("2"):
        print("Welcome Premium member! Upgrade to VIP for more features.")
    elif api.user.has_subscription("1"):
        print("Welcome! Consider upgrading for more features.")
    else:
        print("Please purchase a subscription to access features.")

    api.close()


if __name__ == "__main__":
    main()
