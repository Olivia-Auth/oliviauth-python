"""
OliviaAuth HWID Generation Module

Generates a unique hardware identifier based on system characteristics.
"""

import hashlib
import platform
import socket
import uuid


def get_mac_address() -> str:
    """
    Get the MAC address of the primary network interface.

    Returns:
        str: MAC address in hex format
    """
    try:
        mac = uuid.getnode()
        return hex(mac)[2:].upper()
    except Exception:
        return ""


def get_hostname() -> str:
    """
    Get the system hostname.

    Returns:
        str: Hostname
    """
    try:
        return socket.gethostname()
    except Exception:
        return ""


def get_system_info() -> str:
    """
    Get system information (OS, architecture).

    Returns:
        str: System info string
    """
    try:
        return f"{platform.system()}-{platform.machine()}-{platform.processor()}"
    except Exception:
        return ""


def generate_hwid() -> str:
    """
    Generate a unique hardware identifier.

    Combines MAC address, hostname, and system info into a SHA-256 hash.
    Falls back to a default value if generation fails.

    Returns:
        str: 64-character hexadecimal HWID
    """
    try:
        mac = get_mac_address()
        hostname = get_hostname()
        system = get_system_info()

        combined = f"{mac}:{hostname}:{system}"

        if not combined.strip(":"):
            return "default_hwid_" + hashlib.sha256(
                str(uuid.uuid4()).encode()
            ).hexdigest()[:32]

        hwid = hashlib.sha256(combined.encode()).hexdigest()
        return hwid.upper()
    except Exception:
        return "default_hwid_" + hashlib.sha256(
            str(uuid.uuid4()).encode()
        ).hexdigest()[:32]


def validate_hwid(hwid: str, min_length: int = 10) -> bool:
    """
    Validate HWID meets minimum length requirements.

    Args:
        hwid: Hardware ID to validate
        min_length: Minimum required length

    Returns:
        bool: True if valid
    """
    return hwid is not None and len(hwid) >= min_length
