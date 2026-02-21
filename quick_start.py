"""
Olivia Auth - Quick Start

Minimal example to integrate authentication into your app.
Everything runs automatically in the background:
  - Heartbeat (keeps session alive)
  - Watchdog (kills app if auth is lost - prevents unauthorized usage)
  - Encryption (all data is encrypted automatically)

Just copy this pattern into your project!
"""

from oliviauth import Olivia

# =============================================================================
# STEP 1: Copy from Dashboard at https://oliviauth.xyz/dashboard
# =============================================================================
api = Olivia(
    owner_id="owner1_id",
    app_name="Majesty",
    version="1.0.0",
    hash_check=False,
    server_url="https://api.oliviauth.xyz",
    ssl_sha256="cfe8c3d715275cdcefd10f8d36bd8d9d1c36001f4dd45e745bd4ca22953625332",
    client_key="jq2WAoojhT03WQOcYjpngZrEqR2wz",
    server_key="OK49pCzUPXxlb757Nf6jU43PkfXCx",
    mode="socket"
)

# Check if connected to server
if not api.initialized:
    print(f"Could not connect to server: {api.last_error}")
    exit(1)

# =============================================================================
# STEP 2: Authenticate
# =============================================================================
license_key = input("Enter license key: ")

if not api.license(license_key):
    print(f"Authentication failed: {api.last_error}")
    api.close()
    exit(1)

# =============================================================================
# STEP 3: Check subscription
# =============================================================================
if not api.user.has_subscription():
    print("Your subscription has expired!")
    api.close()
    exit(1)

# =============================================================================
# DONE! Your app is now protected.
# =============================================================================
# From this point on:
#   - Heartbeat runs automatically in background
#   - If session expires or is killed by admin, app exits automatically
#   - You don't need to do anything else!

print(f"Welcome {api.user.username}!")
print(f"Subscription: {api.user.format_time_left()} remaining")
print()


# =============================================================================
# YOUR APP CODE BELOW
# =============================================================================
# The app will automatically exit if:
#   - Session expires
#   - Admin kills the session from dashboard
#   - License is revoked
#
# You can set a callback to run before exit:
#   api.on_session_expired = lambda: print("Session expired! Closing...")

def main():
    """Your actual application logic goes here"""

    # Example: simple loop
    while True:
        command = input("Your app is running. Type 'quit' to exit: ")
        if command.lower() == "quit":
            break

        # Your app logic here...

    # Clean exit
    api.close()


if __name__ == "__main__":
    main()
