"""
Olivia Auth - WebSocket Example

Shows how to use WebSocket mode for real-time features including
remote commands from the server.

Note: WebSocket mode is the default in Olivia Auth SDK.
Just use mode="socket" (or omit it, since it's the default).
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
    server_key="your_server_key",
    mode="socket"  # This is the default, can be omitted
)


def main():

    if not api.initialized:
        print(f"Failed to initialize: {api.last_error}")
        return

    print("Connected to server!")

    # Register command handlers BEFORE authentication
    # These allow the server to call functions on your client remotely

    @api.on_command("show_message")
    def handle_message(params):
        """Server can send messages to display"""
        print(f"\n[SERVER MESSAGE]: {params.get('text', '')}")
        return {"displayed": True}

    @api.on_command("reload_config")
    def handle_reload(params):
        """Server can request the client to reload"""
        print("\n[SERVER]: Requested config reload")
        # Your reload logic here...
        return {"status": "reloaded"}

    @api.on_command("kick")
    def handle_kick(params):
        """Server can kick this client"""
        reason = params.get("reason", "No reason provided")
        print(f"\n[SERVER]: Kicked - {reason}")
        api.close()
        return {"acknowledged": True}

    # Now authenticate
    license_key = input("Enter your license key: ").strip()

    if api.license(license_key):
        print(f"\nWelcome, {api.user.username}!")
        print(f"Mode: {api.mode}")
        print("Real-time features active - server can send commands!")

        # Show registered commands
        commands = api.get_registered_commands()
        print(f"Registered commands: {', '.join(commands)}")

        # Keep connection alive to receive commands
        try:
            print("\nListening for server commands... Press Ctrl+C to exit")
            api.wait()
        except KeyboardInterrupt:
            print("\nDisconnecting...")

    else:
        print(f"\nAuthentication failed: {api.last_error}")

    api.close()


if __name__ == "__main__":
    main()
