"""
Download Example - Shows how to download files

TWO TYPES OF DOWNLOADS:
1. PUBLIC downloads - Anyone can download (no auth needed)
2. PRIVATE downloads - Requires login + active subscription
"""

from oliviauth import Olivia

# =============================================================================
# Example 1: PRIVATE DOWNLOAD (requires authentication)
# =============================================================================

print("=== PRIVATE DOWNLOAD EXAMPLE ===\n")

# Configure your app
api = Olivia(
    owner_id="your_owner_id",
    app_name="YourApp",
    version="1.0.0",
    server_url="https://api.oliviauth.xyz",
    client_key="your_client_key",
    server_key="your_server_key"
)

# Authenticate first
if api.license("XXXX-XXXX-XXXX-XXXX"):
    print(f"✓ Logged in as: {api.user.username}\n")

    # Check if download requires authentication (optional)
    download_id = "your_download_id"  # Get this from your dashboard

    info = api.get_download_info(download_id)
    if info:
        print(f"File: {info['name']}")
        print(f"Size: {info['fileSize']} bytes")
        print(f"Requires auth: {info['authenticated']}\n")

    # Download the file (uses your session automatically)
    if api.download_file(download_id, "downloaded_file.zip"):
        print("\n✓ Download successful!")
    else:
        print(f"\n✗ Download failed: {api.last_error}")
else:
    print(f"✗ Authentication failed: {api.last_error}")

api.close()

# =============================================================================
# Example 2: PUBLIC DOWNLOAD (no authentication needed)
# =============================================================================

print("\n\n=== PUBLIC DOWNLOAD EXAMPLE ===\n")

# For public files, you don't even need to authenticate!
# Just use the quick_download static method

if Olivia.quick_download(
    server_url="https://api.oliviauth.xyz",
    download_id="public_download_id",  # Get this from your dashboard
    save_path="public_file.zip"
):
    print("✓ Public download successful!")
else:
    print("✗ Public download failed")

# =============================================================================
# Example 3: COMPLETE WORKFLOW
# =============================================================================

print("\n\n=== COMPLETE WORKFLOW ===\n")

api = Olivia(
    owner_id="your_owner_id",
    app_name="YourApp",
    version="1.0.0",
    server_url="https://api.oliviauth.xyz",
    client_key="your_client_key",
    server_key="your_server_key"
)

# Login
if api.login("username", "password"):
    print(f"✓ Logged in as: {api.user.username}")

    # Check subscription
    if not api.user.has_subscription():
        print("✗ No active subscription - cannot download private files")
    else:
        print(f"✓ Subscription active: {api.user.format_time_left()}")

        # Download private file
        print("\nDownloading private file...")
        if api.download_file("private_download_id", "premium_content.zip"):
            print("✓ Download complete!")

api.close()

print("\n\n=== USAGE SUMMARY ===")
print("""
For PRIVATE downloads (requires auth + subscription):
    api = Olivia(...)
    api.license("XXXX")  # or api.login("user", "pass")
    api.download_file("download_id", "save_path.zip")

For PUBLIC downloads (no auth needed):
    Olivia.quick_download(
        server_url="https://...",
        download_id="download_id",
        save_path="file.zip"
    )
""")
