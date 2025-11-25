"""
OliviaAuth User Data Module

Provides UserData class with easy access to user info and subscriptions.
"""

import time
from typing import Any, Dict, List, Optional


class UserData:
    """
    Represents authenticated user data with helper methods for subscriptions.

    Attributes:
        username: User's username or license key
        subscriptions: Dictionary of subscription levels
        ip: User's IP address
        hwid: User's hardware ID
        variables: User-specific variables
        create_date: Account creation timestamp
        last_login: Last login timestamp
    """

    def __init__(self, data: Dict[str, Any]):
        """
        Initialize UserData from server response.

        Args:
            data: User data dictionary from server response
        """
        self._raw = data
        self.username: str = data.get('username', '')
        self.subscriptions: Dict[str, Dict] = data.get('subscriptions', {})
        self.ip: str = data.get('ip', '')
        self.hwid: str = data.get('hwid', '')
        self.variables: Dict[str, Any] = data.get('userVars', {})
        self.create_date: float = data.get('createdate', 0)
        self.last_login: float = data.get('lastlogin', 0)

    def has_subscription(self, level: Optional[str] = None) -> bool:
        """
        Check if user has an active subscription.

        Args:
            level: Specific subscription level to check (e.g., "1", "2").
                   If None, checks if ANY subscription is active.

        Returns:
            bool: True if subscription exists and is not expired

        Example:
            >>> if user.has_subscription():
            ...     print("User has at least one active subscription")
            >>> if user.has_subscription("1"):
            ...     print("User has Basic subscription")
        """
        if not self.subscriptions:
            return False

        if level is None:
            return any(self._is_subscription_active(sub)
                      for sub in self.subscriptions.values())

        if level not in self.subscriptions:
            return False

        return self._is_subscription_active(self.subscriptions[level])

    def _is_subscription_active(self, sub: Dict) -> bool:
        """Check if a subscription dict represents an active subscription."""
        expiry = sub.get('expiry', 0)
        if expiry == -1:  # Lifetime subscription
            return True
        return expiry > time.time()

    def get_subscription_name(self, level: str) -> Optional[str]:
        """
        Get the name of a subscription level.

        Args:
            level: Subscription level (e.g., "1", "2")

        Returns:
            Subscription name or None if not found

        Example:
            >>> print(user.get_subscription_name("1"))
            'Basic'
        """
        if level not in self.subscriptions:
            return None
        return self.subscriptions[level].get('name')

    def get_subscription_expiry(self, level: str) -> Optional[float]:
        """
        Get the expiry timestamp of a subscription.

        Args:
            level: Subscription level

        Returns:
            Unix timestamp of expiry, -1 for lifetime, or None if not found
        """
        if level not in self.subscriptions:
            return None
        return self.subscriptions[level].get('expiry')

    def get_subscription_time_left(self, level: str) -> Optional[int]:
        """
        Get seconds remaining on a subscription.

        Args:
            level: Subscription level

        Returns:
            Seconds remaining, -1 for lifetime, 0 if expired, None if not found

        Example:
            >>> seconds = user.get_subscription_time_left("1")
            >>> if seconds > 0:
            ...     print(f"Expires in {seconds // 86400} days")
        """
        if level not in self.subscriptions:
            return None

        expiry = self.subscriptions[level].get('expiry', 0)
        if expiry == -1:  # Lifetime
            return -1

        time_left = max(0, int(expiry - time.time()))
        return time_left

    def get_active_subscription_levels(self) -> List[str]:
        """
        Get list of all active subscription levels.

        Returns:
            List of active subscription level strings

        Example:
            >>> levels = user.get_active_subscription_levels()
            >>> print(f"Active plans: {levels}")
            Active plans: ['1', '2']
        """
        active = []
        for level, sub in self.subscriptions.items():
            if self._is_subscription_active(sub):
                active.append(level)
        return active

    def get_all_subscription_names(self) -> Dict[str, str]:
        """
        Get all subscription names mapped by level.

        Returns:
            Dictionary mapping level to name

        Example:
            >>> names = user.get_all_subscription_names()
            >>> print(names)
            {'1': 'Basic', '2': 'Premium'}
        """
        return {
            level: sub.get('name', f'Plan {level}')
            for level, sub in self.subscriptions.items()
        }

    def get_variable(self, name: str, default: Any = None) -> Any:
        """
        Get a user-specific variable.

        Args:
            name: Variable name
            default: Default value if not found

        Returns:
            Variable value or default
        """
        return self.variables.get(name, default)

    def is_lifetime(self, level: str) -> bool:
        """
        Check if a subscription is lifetime (never expires).

        Args:
            level: Subscription level

        Returns:
            True if lifetime subscription
        """
        if level not in self.subscriptions:
            return False
        return self.subscriptions[level].get('expiry') == -1

    def format_time_left(self, level: Optional[str] = None) -> str:
        """
        Get human-readable time remaining on subscription.

        Args:
            level: Subscription level. If None, uses first active subscription.

        Returns:
            Formatted string like "30 days", "2 hours", "Expired", "Lifetime"

        Example:
            >>> print(user.format_time_left())      # Uses first active
            '30 days'
            >>> print(user.format_time_left("1"))   # Specific level
            '30 days'
        """
        # If no level specified, use first active subscription
        if level is None:
            active = self.get_active_subscription_levels()
            if not active:
                return "No active subscription"
            level = active[0]

        time_left = self.get_subscription_time_left(level)

        if time_left is None:
            return "Not found"
        if time_left == -1:
            return "Lifetime"
        if time_left == 0:
            return "Expired"

        if time_left >= 86400:
            days = time_left // 86400
            return f"{days} day{'s' if days > 1 else ''}"
        elif time_left >= 3600:
            hours = time_left // 3600
            return f"{hours} hour{'s' if hours > 1 else ''}"
        elif time_left >= 60:
            minutes = time_left // 60
            return f"{minutes} minute{'s' if minutes > 1 else ''}"
        else:
            return f"{time_left} second{'s' if time_left > 1 else ''}"

    def __repr__(self) -> str:
        return f"UserData(username='{self.username}', subscriptions={list(self.subscriptions.keys())})"
