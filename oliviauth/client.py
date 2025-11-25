"""
Olivia Auth Unified Client

Single client class that supports both HTTP and WebSocket modes.
WebSocket is the default mode (more features like remote commands).

Example:
    >>> # WebSocket mode (default) - supports remote commands
    >>> api = Olivia(
    ...     owner_id="your_owner_id",
    ...     app_name="YourApp",
    ...     version="1.0.0",
    ...     server_url="https://your-server.com",
    ...     client_key="your_client_key",
    ...     server_key="your_server_key"
    ... )
    >>>
    >>> # Register command handler (only works in socket mode)
    >>> @api.on_command("show_message")
    >>> def handle_message(params):
    ...     print(f"Server says: {params['text']}")
    ...     return {"displayed": True}
    >>>
    >>> if api.license("XXXX-XXXX-XXXX-XXXX"):
    ...     print(f"Welcome {api.user.username}!")
    ...     api.wait()  # Keep listening for commands
    >>>
    >>> # HTTP mode - simpler, no remote commands
    >>> api = Olivia(..., mode="http")
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import queue
import threading
import time
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional

import requests

from .crypto import (
    decrypt_aes_gcm,
    decrypt_with_rsa,
    encrypt_aes_gcm,
    encrypt_with_rsa,
    generate_aes_key,
    generate_rsa_keypair,
    load_public_key,
    serialize_public_key,
    verify_ssl_certificate,
    xor_deobfuscate,
    xor_obfuscate,
)
from .exceptions import (
    AppDisabledError,
    ConnectionError,
    EncryptionError,
    HWIDMismatchError,
    NotAuthenticatedError,
    NotInitializedError,
    SSLVerificationError,
    SubscriptionExpiredError,
    TwoFactorRequiredError,
    UserBannedError,
    VersionMismatchError,
    VPNBlockedError,
)
from .hwid import generate_hwid
from .user import UserData

# Check if socketio is available
try:
    import socketio
    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False

logger = logging.getLogger("oliviauth")


class ConnectionState(Enum):
    """WebSocket connection states for the state machine."""
    DISCONNECTED = auto()    # No socket connection
    CONNECTING = auto()      # Attempting to connect
    CONNECTED = auto()       # Socket connected, session not authenticated
    AUTHENTICATING = auto()  # Sending session_id to server
    AUTHENTICATED = auto()   # Fully operational


class Olivia:
    """
    Olivia Auth Unified Client - Simple, secure authentication for your apps.

    Supports two modes:
    - "socket" (default): WebSocket with real-time features and remote commands
    - "http": Traditional HTTP requests, simpler but no remote commands

    Both modes have identical API - just change the mode parameter.
    """

    def __init__(
        self,
        owner_id: str,
        app_name: str,
        version: str,
        server_url: str = "http://127.0.0.1:5000",
        client_key: str = "",
        server_key: str = "",
        hash_check: Optional[str] = None,
        ssl_sha256: Optional[str] = None,
        auto_init: bool = True,
        heartbeat_interval: int = 60,
        mode: str = "socket",
        auto_exit: bool = True,
    ):
        """
        Initialize Olivia Auth client.

        Args:
            owner_id: Your owner ID from the dashboard
            app_name: Name of your application
            version: Current version of your application
            server_url: Olivia Auth server URL
            client_key: Client obfuscation key (from dashboard)
            server_key: Server obfuscation key (from dashboard)
            hash_check: Optional hash for integrity verification
            ssl_sha256: Optional SSL certificate SHA256 for pinning (from dashboard)
            auto_init: Auto-initialize on creation (default: True)
            heartbeat_interval: Seconds between heartbeats (default: 60)
            mode: Connection mode - "socket" (default) or "http"
            auto_exit: Auto-exit app if authentication is lost (default: True)
        """
        self.owner_id = owner_id
        self.app_name = app_name
        self.version = version
        self.server_url = server_url.rstrip('/')
        self.hash_check = hash_check
        self.ssl_sha256 = ssl_sha256
        self.heartbeat_interval = heartbeat_interval

        # Validate and set mode
        mode = mode.lower()
        if mode == "socket" and not SOCKETIO_AVAILABLE:
            logger.warning(
                "WebSocket mode requested but python-socketio not installed. "
                "Falling back to HTTP mode."
            )
            mode = "http"

        if mode not in ("socket", "http"):
            raise ValueError(f"Invalid mode '{mode}'. Use 'socket' or 'http'.")

        self.mode = mode
        self.auto_exit = auto_exit

        # State machine (thread-safe)
        self._state = ConnectionState.DISCONNECTED
        self._state_lock = threading.Lock()
        self._state_condition = threading.Condition(self._state_lock)
        self.initialized = False
        self.last_error: Optional[str] = None
        self.user: Optional[UserData] = None

        # Session & Crypto
        self.session_id: Optional[str] = None
        self._private_key = None
        self._public_key = None
        self._server_public_key = None
        self._client_key: Optional[str] = client_key or None
        self._server_key: Optional[str] = server_key or None

        # Threading
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._heartbeat_stop = threading.Event()
        self._watchdog_thread: Optional[threading.Thread] = None
        self._watchdog_stop = threading.Event()
        self._response_queue: queue.Queue = queue.Queue()

        # Reconnection control (unified)
        self._reconnect_thread: Optional[threading.Thread] = None
        self._reconnect_stop = threading.Event()
        self._reconnect_attempt = 0
        self._max_reconnect_attempts = 50  # ~5 min with exponential backoff
        self._preventive_refresh = False  # Flag to prevent disconnect handler interference
        self._refresh_in_progress = False  # Guard against concurrent refreshes

        # WebSocket
        self._sio: Optional["socketio.Client"] = None
        self._last_connect_time: float = 0

        # Command system (socket mode only)
        self._command_handlers: Dict[str, Callable] = {}
        self._channel_id: Optional[str] = None
        self._processed_commands: Dict[str, float] = {}

        # Callbacks
        self.on_connect: Optional[Callable[[], None]] = None
        self.on_disconnect: Optional[Callable[[], None]] = None
        self.on_session_expired: Optional[Callable[[], None]] = None

        if self.mode == "socket":
            self._setup_socket()

        if auto_init:
            try:
                self.init()
            except SSLVerificationError as e:
                # Show clean error message instead of traceback
                self.last_error = str(e)
                print(f"\n[Olivia Auth] SSL Error: {e}")
                print("[Olivia Auth] Possible pirated server detected. Closing application...")
                import sys
                sys.exit(1)

    # =========================================================================
    # STATE MACHINE PROPERTIES & METHODS
    # =========================================================================

    @property
    def connected(self) -> bool:
        """Thread-safe connected status."""
        with self._state_lock:
            return self._state in (
                ConnectionState.CONNECTED,
                ConnectionState.AUTHENTICATING,
                ConnectionState.AUTHENTICATED
            )

    @property
    def authenticated(self) -> bool:
        """Thread-safe authenticated status."""
        with self._state_lock:
            return self._state == ConnectionState.AUTHENTICATED

    def _transition_state(self, new_state: ConnectionState, reason: str = "") -> bool:
        """
        Thread-safe state transition with validation.
        Returns True if transition was valid and executed.
        """
        with self._state_lock:
            old_state = self._state

            valid_transitions = {
                ConnectionState.DISCONNECTED: {ConnectionState.CONNECTING},
                ConnectionState.CONNECTING: {ConnectionState.CONNECTED, ConnectionState.DISCONNECTED},
                ConnectionState.CONNECTED: {ConnectionState.AUTHENTICATING, ConnectionState.AUTHENTICATED, ConnectionState.DISCONNECTED},
                ConnectionState.AUTHENTICATING: {ConnectionState.AUTHENTICATED, ConnectionState.CONNECTED, ConnectionState.DISCONNECTED},
                ConnectionState.AUTHENTICATED: {ConnectionState.DISCONNECTED, ConnectionState.CONNECTING},
            }

            if new_state not in valid_transitions.get(old_state, set()):
                logger.debug(f"Invalid state transition: {old_state.name} -> {new_state.name} ({reason})")
                return False

            self._state = new_state
            logger.debug(f"State: {old_state.name} -> {new_state.name} ({reason})")
            self._state_condition.notify_all()
            return True

    def _force_state(self, new_state: ConnectionState, reason: str = ""):
        """Force state change without validation (for error recovery)."""
        with self._state_lock:
            old_state = self._state
            self._state = new_state
            logger.debug(f"State FORCED: {old_state.name} -> {new_state.name} ({reason})")
            self._state_condition.notify_all()

    # =========================================================================
    # SMART TRANSPORT LAYER - Same interface, different transport
    # =========================================================================

    def _send(
        self,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        use_obfuscation: bool = True,
        timeout: float = 30.0
    ) -> Dict[str, Any]:
        """
        Smart send - automatically uses HTTP or Socket based on mode.

        This is the core abstraction that makes both modes work identically.
        """
        payload = data or {}
        encrypted = self._encrypt(payload, use_obfuscation)

        if self.mode == "socket" and self._sio and self._sio.connected:
            logger.debug(f"[{endpoint}] Sending via WebSocket")
            raw_response = self._socket_send(endpoint, encrypted, timeout)
        else:
            # Log why we're using HTTP
            if self.mode == "socket":
                reason = "socket not initialized" if not self._sio else "socket not connected"
                logger.debug(f"[{endpoint}] Fallback to HTTP ({reason})")
            else:
                logger.debug(f"[{endpoint}] Sending via HTTP (mode={self.mode})")
            raw_response = self._http_send(endpoint, encrypted)

        # Decrypt response if needed
        if raw_response and 'data' in raw_response and isinstance(raw_response['data'], str):
            try:
                decrypted = self._decrypt(raw_response['data'], use_obfuscation)
                logger.debug(f"Decrypted response: {decrypted}")
                return decrypted
            except Exception as e:
                # Decryption failed - this usually means wrong keys
                logger.debug(f"Decryption failed: {e}")
                logger.debug(f"Raw response was: {raw_response}")
                # Return raw response if it has error info, otherwise report decrypt failure
                if 'error' in raw_response or 'message' in raw_response:
                    return raw_response
                return {
                    'success': False,
                    'error': f'Decryption failed. Check your client_key and server_key. Details: {e}'
                }

        # If raw_response has success/error fields directly, return it
        if raw_response and ('success' in raw_response or 'error' in raw_response or 'message' in raw_response):
            logger.debug(f"Returning raw response: {raw_response}")
            return raw_response

        return raw_response or {'success': False, 'error': 'Empty response from server'}

    def _http_send(self, endpoint: str, encrypted_data: str) -> Dict[str, Any]:
        """Send via HTTP POST with detailed error handling."""
        headers = {'Session-ID': self.session_id} if self.session_id else {}

        try:
            response = requests.post(
                f'{self.server_url}/api/1.0/{endpoint}',
                json={'data': encrypted_data},
                headers=headers,
                timeout=30
            )
            return response.json()
        except requests.exceptions.SSLError as e:
            self.last_error = f"SSL error: {e}"
            return {'success': False, 'error': self.last_error}
        except requests.exceptions.ConnectionError as e:
            self.last_error = f"Connection error: Server may be offline"
            return {'success': False, 'error': self.last_error}
        except requests.exceptions.Timeout as e:
            self.last_error = f"Request timeout after 30 seconds"
            return {'success': False, 'error': self.last_error}
        except requests.exceptions.RequestException as e:
            self.last_error = f"Request failed: {e}"
            return {'success': False, 'error': self.last_error}
        except Exception as e:
            self.last_error = str(e)
            return {'success': False, 'error': str(e)}

    def _socket_send(self, endpoint: str, encrypted_data: str, timeout: float) -> Dict[str, Any]:
        """Send via WebSocket and wait for response."""
        # Clear any stale responses from queue
        while not self._response_queue.empty():
            try:
                self._response_queue.get_nowait()
            except queue.Empty:
                break

        self._sio.emit('api_request', {
            'endpoint': endpoint,
            'data': encrypted_data,
            'session_id': self.session_id
        })

        try:
            return self._response_queue.get(timeout=timeout)
        except queue.Empty:
            return {'success': False, 'error': 'Timeout'}

    # =========================================================================
    # ENCRYPTION - Same for both modes
    # =========================================================================

    def _encrypt(self, data: Dict[str, Any], use_obfuscation: bool = True) -> str:
        """Encrypt data using RSA+AES-GCM with optional XOR obfuscation."""
        json_bytes = json.dumps(data, default=str).encode('utf-8')

        # AES-GCM encrypt
        aes_key = generate_aes_key()
        encrypted_payload = encrypt_aes_gcm(json_bytes, aes_key)

        # RSA encrypt the AES key
        encrypted_key = encrypt_with_rsa(aes_key, self._server_public_key)

        # Combine and base64
        combined = base64.urlsafe_b64encode(encrypted_key + encrypted_payload).decode()

        # Optional XOR obfuscation
        if use_obfuscation and self._client_key:
            return xor_obfuscate(combined, self._client_key)
        return combined

    def _decrypt(self, encrypted_data: str, use_obfuscation: bool = True) -> Dict[str, Any]:
        """Decrypt server response."""
        try:
            # Deobfuscate if needed
            if use_obfuscation and self._server_key:
                data = xor_deobfuscate(encrypted_data, self._server_key)
            else:
                data = encrypted_data

            decoded = base64.urlsafe_b64decode(data)

            # Split RSA key (256 bytes) and AES payload
            encrypted_key = decoded[:256]
            encrypted_payload = decoded[256:]

            # Decrypt AES key with RSA
            aes_key = decrypt_with_rsa(encrypted_key, self._private_key)

            # Decrypt payload with AES
            decrypted = decrypt_aes_gcm(encrypted_payload, aes_key)

            return json.loads(decrypted.decode('utf-8'))
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {e}")

    # =========================================================================
    # INITIALIZATION - Smart init for both modes
    # =========================================================================

    def init(self) -> bool:
        """
        Initialize the client connection.
        Works identically for both HTTP and Socket modes.
        """
        if self.initialized:
            return True

        try:
            logger.info(f"Initializing Olivia client in {self.mode} mode")

            # Step 1: Verify SSL certificate FIRST (anti-piracy protection)
            if self.ssl_sha256 and self.server_url.startswith('https://'):
                try:
                    verify_ssl_certificate(self.server_url, self.ssl_sha256)
                    logger.debug("SSL certificate verified successfully")
                except SSLVerificationError as e:
                    self.last_error = str(e)
                    raise  # Re-raise to stop initialization

            # Step 2: Generate RSA keys
            self._private_key, self._public_key = generate_rsa_keypair()

            # Step 3: Connect socket if needed
            if self.mode == "socket":
                if not self._connect_socket():
                    return False

            # Step 4: Create session (same logic, different transport)
            if not self._create_session():
                return False

            # Step 5: Initialize app
            if not self._init_app():
                return False

            # Step 6: Start session heartbeat AFTER init to avoid race conditions
            # The session TTL (300s default) is long enough that we don't need
            # to start heartbeat before init completes
            self._start_session_heartbeat()

            self.initialized = True
            return True

        except SSLVerificationError:
            raise  # Re-raise SSL errors without masking
        except Exception as e:
            self.last_error = str(e)
            return False

    def _connect_socket(self) -> bool:
        """Connect WebSocket if in socket mode."""
        if not self._sio:
            return False

        try:
            # Transition to CONNECTING before attempting connection
            self._force_state(ConnectionState.CONNECTING, "initial_connect")

            self._sio.connect(
                self.server_url,
                transports=['websocket'],
                wait_timeout=10
            )
            return self.connected
        except Exception as e:
            self.last_error = f"WebSocket connection failed: {e}"
            self._force_state(ConnectionState.DISCONNECTED, f"connect_error: {e}")
            return False

    def _create_session(self) -> bool:
        """Create encrypted session - works for both modes."""
        public_key_bytes = serialize_public_key(self._public_key)
        encoded_key = base64.urlsafe_b64encode(public_key_bytes).decode()

        if self.mode == "socket" and self._sio and self._sio.connected:
            # Socket: emit and wait using queue
            while not self._response_queue.empty():
                try:
                    self._response_queue.get_nowait()
                except queue.Empty:
                    break
            self._sio.emit('create_session', {'public_key': encoded_key})

            try:
                data = self._response_queue.get(timeout=10)
            except queue.Empty:
                self.last_error = "Session creation timeout"
                return False
        else:
            # HTTP: POST request with detailed error handling
            try:
                resp = requests.post(
                    f'{self.server_url}/api/1.0/session',
                    json={'data': encoded_key},
                    timeout=30
                )
                if resp.status_code != 200:
                    self.last_error = f"Session failed: HTTP {resp.status_code}"
                    return False
                data = resp.json()
            except requests.exceptions.SSLError as e:
                self.last_error = f"SSL error connecting to {self.server_url}: {e}"
                raise SSLVerificationError(self.last_error)
            except requests.exceptions.ConnectionError as e:
                self.last_error = f"Cannot connect to {self.server_url}: Server may be offline or unreachable"
                raise ConnectionError(self.last_error)
            except requests.exceptions.Timeout as e:
                self.last_error = f"Connection timeout: Server at {self.server_url} did not respond within 30 seconds"
                raise ConnectionError(self.last_error)
            except requests.exceptions.RequestException as e:
                self.last_error = f"Request failed: {e}"
                raise ConnectionError(self.last_error)
            except Exception as e:
                self.last_error = f"Unexpected error: {e}"
                raise ConnectionError(self.last_error)

        # Process response (same for both modes)
        # Socket returns: session_id, server_public_key
        # HTTP returns: extra, data
        self.session_id = data.get('session_id') or data.get('extra')
        server_key_b64 = data.get('server_public_key') or data.get('data')

        if not self.session_id or not server_key_b64:
            self.last_error = "Invalid session response"
            return False

        server_key_bytes = base64.urlsafe_b64decode(server_key_b64)
        self._server_public_key = load_public_key(server_key_bytes)
        return True

    def _init_app(self) -> bool:
        """Initialize app with server - works for both modes."""
        init_data = {
            'ownerID': self.owner_id,
            'appName': self.app_name,
            'version': self.version,
            'hashCheck': self.hash_check
        }

        # Init request is sent WITHOUT obfuscation, response comes WITH
        encrypted = self._encrypt(init_data, use_obfuscation=False)

        if self.mode == "socket" and self._sio and self._sio.connected:
            # Clear queue and emit
            while not self._response_queue.empty():
                try:
                    self._response_queue.get_nowait()
                except queue.Empty:
                    break
            self._sio.emit('api_request', {
                'endpoint': 'init',
                'data': encrypted,
                'session_id': self.session_id
            })
            try:
                raw_response = self._response_queue.get(timeout=10)
            except queue.Empty:
                self.last_error = "Init timeout"
                return False
        else:
            try:
                resp = requests.post(
                    f'{self.server_url}/api/1.0/init',
                    json={'data': encrypted},
                    headers={'Session-ID': self.session_id},
                    timeout=30
                )
                raw_response = resp.json()
            except Exception as e:
                self.last_error = str(e)
                return False

        # Decrypt response (WITH obfuscation)
        if raw_response and 'data' in raw_response:
            try:
                response = self._decrypt(raw_response['data'], use_obfuscation=True)
            except Exception:
                response = raw_response
        else:
            response = raw_response

        # Handle response with user-friendly error messages
        if not response or not response.get('success'):
            error = response.get('message', response.get('error', 'Init failed')) if response else 'Init failed'
            error_lower = error.lower()
            self.last_error = error

            # Detect specific errors - use server message directly (no duplicate prefixes)
            if 'disabled' in error_lower:
                raise AppDisabledError(error)
            elif 'version' in error_lower or 'update' in error_lower:
                raise VersionMismatchError(error)
            elif 'vpn' in error_lower or 'proxy' in error_lower:
                raise VPNBlockedError(error)
            elif 'hash' in error_lower:
                self.last_error = "Invalid application hash"
            elif 'key' in error_lower or 'obfuscation' in error_lower or 'decrypt' in error_lower:
                self.last_error = "Encryption key error. Check your client_key and server_key."
            elif 'not found' in error_lower or 'invalid app' in error_lower:
                self.last_error = "Application not found. Check your owner_id and app_name."
            elif 'owner' in error_lower or 'banned' in error_lower:
                self.last_error = error
            else:
                self.last_error = error

            return False

        return True

    # =========================================================================
    # SOCKET.IO SETUP
    # =========================================================================

    def _setup_socket(self):
        """Setup Socket.IO client with event handlers."""
        if not SOCKETIO_AVAILABLE:
            return

        # CRITICAL: Disable Socket.IO's auto-reconnect - WE control reconnection
        self._sio = socketio.Client(
            reconnection=False,  # We handle reconnection via state machine
        )

        @self._sio.event
        def connect():
            self._last_connect_time = time.time()

            # Transition to CONNECTED
            self._transition_state(ConnectionState.CONNECTED, "socket_connected")

            # Re-authenticate if we have a session (reconnection or refresh case)
            if self.session_id:
                # Use a thread to avoid blocking the event loop
                def delayed_reauth():
                    time.sleep(0.5)  # Wait for connection to stabilize
                    if self._sio and self._sio.connected:
                        self._reauthenticate()

                threading.Thread(target=delayed_reauth, daemon=True).start()

            if self.on_connect:
                try:
                    self.on_connect()
                except Exception:
                    pass

        @self._sio.event
        def disconnect():
            # Calculate how long the connection lasted
            connection_duration = time.time() - self._last_connect_time if self._last_connect_time else 0
            logger.debug(f"WebSocket disconnected after {connection_duration:.1f}s")

            # If this is a preventive refresh, ignore - we'll reconnect immediately
            if self._preventive_refresh:
                return

            # Check current state
            with self._state_lock:
                current_state = self._state
                if current_state == ConnectionState.DISCONNECTED:
                    return  # Already handling
                had_session = self.session_id is not None

            # Mark as disconnected
            self._force_state(ConnectionState.DISCONNECTED, "socket_disconnected")

            if self.on_disconnect:
                try:
                    self.on_disconnect()
                except Exception:
                    pass

            # Unexpected disconnect - try to reconnect
            if had_session and self.session_id:
                self._trigger_reconnect()

        @self._sio.on('connected')
        def on_connected(data):
            pass  # Server confirmed connection

        @self._sio.on('session_created')
        def on_session_created(data):
            self._response_queue.put(data)

        @self._sio.on('api_response')
        def on_api_response(data):
            self._response_queue.put(data)

        @self._sio.on('api_error')
        def on_api_error(data):
            # Server sends 'message' field, also check 'error' as fallback
            error_msg = data.get('message', data.get('error', 'Unknown error'))
            self._response_queue.put({'success': False, 'error': error_msg, 'message': error_msg})

        @self._sio.on('heartbeat_ack')
        def on_heartbeat_ack(data):
            # Check if session was killed by server
            if isinstance(data, dict):
                session_dead = False
                reason = ""

                # Check authenticated field (when session not found in server)
                # BUT ignore during reconnection (state != AUTHENTICATED means we're reconnecting)
                if data.get('authenticated') is False:
                    with self._state_lock:
                        current_state = self._state
                    # Only consider session dead if we WERE authenticated
                    # During reconnection, authenticated=False is expected until re-auth completes
                    if current_state == ConnectionState.AUTHENTICATED:
                        session_dead = True
                        reason = "authenticated=False"
                # Check session_alive field (more reliable - server actually checked the session)
                elif data.get('session_alive') is False:
                    session_dead = True
                    reason = "session_alive=False"
                # Also decrypt and check success field for killed sessions
                elif data.get('data'):
                    try:
                        decrypted = self._decrypt(data['data'])
                        if not decrypted.get('success', True):
                            session_dead = True
                            reason = f"decrypted.success=False: {decrypted.get('message', 'no message')}"
                    except Exception:
                        pass

                if session_dead:
                    logger.warning(f"Server killed session: {reason}")
                    self._handle_session_killed()

        @self._sio.on('auth_response')
        def on_auth_response(data):
            """Handle re-authentication response after reconnection/refresh."""
            if data.get('success'):
                self._transition_state(ConnectionState.AUTHENTICATED, "reauth_success")
            else:
                msg = data.get('message', 'Unknown error')
                logger.warning(f"Re-authentication failed: {msg}")
                # Session is invalid/expired - stop everything
                if 'invalid' in msg.lower() or 'expired' in msg.lower():
                    self._handle_session_killed()

        @self._sio.on('session_expired')
        def on_session_expired(data=None):
            reason = "unknown"
            if isinstance(data, dict):
                reason = data.get('reason', data.get('message', 'unknown'))
            logger.warning(f"Server sent session_expired event: {reason}")
            self.initialized = False
            self._handle_session_killed()

        @self._sio.on('commands_subscribed')
        def on_commands_subscribed(data):
            self._response_queue.put(data)

        @self._sio.on('server_command')
        def on_server_command(data):
            # Decrypt if encrypted
            if isinstance(data.get('data'), str):
                try:
                    data = self._decrypt(data['data'])
                except Exception:
                    return
            self._handle_server_command(data)

    # =========================================================================
    # COMMAND SYSTEM (Socket Mode Only)
    # =========================================================================

    def on_command(self, command_name: str) -> Callable:
        """
        Decorator to register a command handler (socket mode only).

        Example:
            >>> @api.on_command("show_notification")
            >>> def handle_notification(params):
            ...     print(f"Notification: {params['message']}")
            ...     return {"displayed": True}
        """
        def decorator(func: Callable[[Dict[str, Any]], Any]) -> Callable:
            self._command_handlers[command_name] = func
            return func
        return decorator

    def register_command(self, name: str, handler: Callable):
        """Register a command handler programmatically."""
        self._command_handlers[name] = handler

    def get_registered_commands(self) -> List[str]:
        """Get list of registered command names."""
        return list(self._command_handlers.keys())

    def _handle_server_command(self, data: Dict[str, Any]):
        """Process incoming server command."""
        command_id = data.get('command_id', '')
        command_name = data.get('command', '')
        params = data.get('params', {})
        timestamp = data.get('timestamp', 0)
        signature = data.get('signature', '')

        # Validate duplicate
        if command_id in self._processed_commands:
            self._send_command_ack(command_id, "failed", error="Duplicate")
            return

        # Validate signature
        if self._server_key:
            payload = f"{command_id}:{command_name}:{timestamp}"
            expected = hmac.new(
                self._server_key.encode(),
                payload.encode(),
                hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(signature, expected):
                self._send_command_ack(command_id, "failed", error="Invalid signature")
                return

        # Validate timestamp (30 second window)
        if abs(time.time() - timestamp) > 30:
            self._send_command_ack(command_id, "failed", error="Expired")
            return

        # Mark processed
        self._processed_commands[command_id] = time.time()

        # Cleanup old (keep 5 min)
        now = time.time()
        self._processed_commands = {k: v for k, v in self._processed_commands.items() if now - v < 300}

        # Send received ACK
        self._send_command_ack(command_id, "received")

        # Execute handler
        if command_name not in self._command_handlers:
            self._send_command_ack(command_id, "failed", error=f"Unknown: {command_name}")
            return

        try:
            result = self._command_handlers[command_name](params)
            response = result if isinstance(result, dict) else {"result": result}
            self._send_command_ack(command_id, "executed", response=response)
        except Exception as e:
            self._send_command_ack(command_id, "failed", error=str(e))

    def _send_command_ack(self, command_id: str, status: str, response: Dict = None, error: str = None):
        """Send command acknowledgment."""
        if not self._sio or not self._sio.connected:
            return

        ack = {'command_id': command_id, 'status': status}
        if response:
            ack['response'] = response
        if error:
            ack['error'] = error

        self._sio.emit('command_ack', ack)

    def _subscribe_to_commands(self):
        """Subscribe to server commands after auth."""
        if not self._sio or not self._sio.connected:
            return

        # Clear queue and emit
        while not self._response_queue.empty():
            try:
                self._response_queue.get_nowait()
            except queue.Empty:
                break
        self._sio.emit('subscribe_commands', {})

        try:
            data = self._response_queue.get(timeout=10)
            if data and data.get('success'):
                self._channel_id = data.get('channel_id')
        except queue.Empty:
            pass  # Timeout is ok here, commands subscription is optional

    # =========================================================================
    # AUTHENTICATION - Same API for both modes
    # =========================================================================

    def license(self, license_key: str, hwid: Optional[str] = None) -> bool:
        """
        Authenticate using a license key.

        Works identically in both HTTP and Socket modes.
        """
        if not self.initialized:
            raise NotInitializedError()

        response = self._send('license', {
            'license': license_key,
            'hwid': hwid or generate_hwid()
        })

        return self._handle_auth_response(response)

    def login(self, username: str, password: str, hwid: Optional[str] = None, two_factor_code: Optional[str] = None) -> bool:
        """
        Login with username and password.

        Works identically in both HTTP and Socket modes.
        """
        if not self.initialized:
            raise NotInitializedError()

        data = {
            'username': username,
            'password': password,
            'hwid': hwid or generate_hwid()
        }
        if two_factor_code:
            data['twoFactorCode'] = two_factor_code

        response = self._send('login', data)
        return self._handle_auth_response(response)

    def register(self, license_key: str, username: str, password: str, hwid: Optional[str] = None) -> bool:
        """
        Register a new account with a license key.

        Works identically in both HTTP and Socket modes.
        """
        if not self.initialized:
            raise NotInitializedError()

        response = self._send('register', {
            'license': license_key,
            'username': username,
            'password': password,
            'hwid': hwid or generate_hwid()
        })

        if response.get('success'):
            self.last_error = None
            return True

        self.last_error = response.get('message', response.get('error', 'Registration failed'))
        return False

    def _handle_auth_response(self, response: Dict[str, Any]) -> bool:
        """Process auth response - same for both modes with user-friendly errors."""
        if not response.get('success'):
            error = response.get('message', response.get('error', 'Auth failed'))
            error_lower = error.lower().strip()

            # Detect specific errors - use server message directly (no duplicate prefixes)
            if 'hwid' in error_lower:
                self.last_error = error
                raise HWIDMismatchError(error)
            elif 'banned' in error_lower:
                self.last_error = error
                raise UserBannedError(error)
            elif 'expired' in error_lower or 'subscription' in error_lower:
                self.last_error = error
                raise SubscriptionExpiredError(error)
            elif '2fa' in error_lower or 'two' in error_lower or 'factor' in error_lower:
                self.last_error = error
                raise TwoFactorRequiredError(error)
            elif 'invalid' in error_lower and 'license' in error_lower:
                self.last_error = error
            elif 'used' in error_lower or 'already' in error_lower:
                self.last_error = error
            elif 'not found' in error_lower:
                self.last_error = error
            elif 'password' in error_lower or 'credentials' in error_lower:
                self.last_error = error
            elif 'session' in error_lower:
                self.last_error = "Session error. Try restarting the application."
            elif error_lower == 'error' or error_lower == 'auth failed':
                # Generic error from server - provide helpful hint
                self.last_error = "Authentication failed. Check your license key."
            else:
                self.last_error = error
            return False

        # Set user data
        user_data = response.get('data', response.get('info', {}))
        self.user = UserData(user_data)
        self.last_error = None

        # Transition to AUTHENTICATED state
        self._transition_state(ConnectionState.AUTHENTICATED, "login_success")

        # Start background services
        self._start_heartbeat()
        self._start_watchdog()
        if self.mode == "socket":
            self._start_refresh_timer()  # Refresh connection every 50s for Cloudflare
            self._subscribe_to_commands()

        return True

    # =========================================================================
    # HEARTBEAT
    # =========================================================================

    def heartbeat(self) -> bool:
        """
        Send heartbeat to keep session alive.

        Note: This works even before authentication to prevent session expiration
        during the auth flow. Only requires a valid session_id.

        In socket mode, relies on socket.io's auto-reconnection if disconnected.
        Does NOT manually reconnect to avoid race conditions.
        """
        if not self.session_id:
            return False

        if self.mode == "socket" and self._sio:
            # Only send heartbeat if connected AND authenticated (or not yet authenticated for pre-auth heartbeat)
            # During reconnection, skip heartbeat to avoid confusing server
            with self._state_lock:
                current_state = self._state

            # Skip heartbeat during reconnection (CONNECTING, AUTHENTICATING, DISCONNECTED)
            # Only send if AUTHENTICATED or CONNECTED (initial pre-auth heartbeat)
            if current_state not in (ConnectionState.AUTHENTICATED, ConnectionState.CONNECTED):
                return False

            if self._sio.connected:
                self._sio.emit('heartbeat', {'session_id': self.session_id})
                return True
            # Not connected - socket.io is handling reconnection, just return False
            return False
        else:
            # HTTP mode: use encrypted request if authenticated
            if self.authenticated and self._server_public_key:
                try:
                    response = self._send('heartbeat', {})
                    if isinstance(response, dict):
                        success = response.get('success', False)
                        if not success:
                            # Session was killed/deleted on server
                            self._handle_session_killed()
                            return False
                        return True
                    return bool(response)
                except Exception:
                    return False
            else:
                # Pre-auth: simple request to keep session alive
                try:
                    resp = requests.post(
                        f'{self.server_url}/api/1.0/heartbeat',
                        json={'data': ''},
                        headers={'Session-ID': self.session_id},
                        timeout=10
                    )
                    if resp.status_code == 401:
                        # Session expired or deleted
                        self._handle_session_killed()
                        return False
                    return resp.status_code == 200
                except Exception:
                    return False

    def _start_session_heartbeat(self):
        """
        Start heartbeat immediately after session creation.

        This is crucial to prevent session expiration during the authentication flow.
        Uses a shorter interval (15s) to ensure the session stays alive while
        the user enters their credentials.
        """
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            return

        self._heartbeat_stop.clear()

        # Send first heartbeat IMMEDIATELY
        self.heartbeat()

        # Use shorter interval pre-auth (15s) to be safe with 300s session TTL
        interval = 15

        def loop():
            while not self._heartbeat_stop.wait(interval):
                if not self.session_id:
                    break
                # Heartbeat will handle reconnection if socket is disconnected
                self.heartbeat()

        self._heartbeat_thread = threading.Thread(target=loop, daemon=True)
        self._heartbeat_thread.start()

    def _start_heartbeat(self):
        """
        Start automatic heartbeat for authenticated sessions.

        After authentication, we can use longer intervals since the user is
        actively using the app. This is called from _handle_auth_response().
        """
        # Heartbeat is already running from _start_session_heartbeat()
        # Just update the interval if needed
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            # Heartbeat already running, no need to restart
            # The interval will naturally be 15s but that's fine
            return

        self._heartbeat_stop.clear()

        # Use user-configured heartbeat_interval
        # Default is 60s, but user can override (e.g., 20s for Cloudflare compatibility)
        # Socket mode benefits from shorter intervals to keep connection alive
        interval = self.heartbeat_interval

        def loop():
            while not self._heartbeat_stop.wait(interval):
                if not self.authenticated:
                    break
                # Heartbeat will handle reconnection if socket is disconnected
                self.heartbeat()

        self._heartbeat_thread = threading.Thread(target=loop, daemon=True)
        self._heartbeat_thread.start()

    def _stop_heartbeat(self):
        """Stop heartbeat thread."""
        self._heartbeat_stop.set()
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=1)

    # =========================================================================
    # WEBSOCKET REFRESH SYSTEM (Simple & Robust)
    # =========================================================================
    #
    # Design:
    # - Preventive refresh every 50s to avoid Cloudflare 100s timeout
    # - Simple disconnect -> connect -> re-authenticate cycle
    # - Separate handling for unexpected disconnects vs intentional refresh
    #

    def _start_refresh_timer(self):
        """Start the WebSocket refresh timer (runs every 50s after auth)."""
        if self.mode != "socket":
            return

        # Don't start if already running
        if self._reconnect_thread and self._reconnect_thread.is_alive():
            return

        def refresh_loop():
            while not self._reconnect_stop.is_set():
                # Wait 50 seconds
                if self._reconnect_stop.wait(50):
                    break  # Stop requested

                # Only refresh if authenticated
                if not self.authenticated:
                    continue

                # Do the refresh
                self._do_refresh()

        self._reconnect_stop.clear()
        self._reconnect_thread = threading.Thread(
            target=refresh_loop,
            daemon=True,
            name="OliviaRefresh"
        )
        self._reconnect_thread.start()

    def _do_refresh(self):
        """
        Refresh the WebSocket connection (preventive, every 50s).
        Simple: disconnect -> connect -> re-authenticate
        """
        if not self._sio or not self.session_id:
            return

        # Guard against concurrent refresh attempts
        if self._refresh_in_progress:
            return
        self._refresh_in_progress = True
        self._preventive_refresh = True

        try:
            # 1. Disconnect and cleanup current connection
            if self._sio.connected:
                try:
                    self._sio.disconnect()
                except Exception:
                    pass

            # 2. Wait for connection to fully close
            time.sleep(2.0)

            # 3. Recreate the socket client (clean state)
            self._setup_socket()

            # 4. Connect with the fresh client
            self._sio.connect(
                self.server_url,
                transports=['websocket'],
                wait_timeout=15
            )

            # 5. Verify connection
            if not self._sio.connected or not self._sio.sid:
                raise Exception("Connection established but no sid")

        except Exception:
            # Fall back to reconnect logic
            self._preventive_refresh = False
            self._refresh_in_progress = False
            self._trigger_reconnect()
        finally:
            self._preventive_refresh = False
            self._refresh_in_progress = False

    def _trigger_reconnect(self):
        """Handle unexpected disconnect - try to reconnect with backoff."""
        if self.mode != "socket":
            return

        # Don't start another thread if one is already running
        if self._reconnect_thread and self._reconnect_thread.is_alive():
            return

        def reconnect_loop():
            attempt = 0
            max_attempts = 50

            while not self._reconnect_stop.is_set() and attempt < max_attempts:
                attempt += 1

                # Exponential backoff: 0.5, 1, 2, 4, 8... max 30s
                delay = min(0.5 * (2 ** (attempt - 1)), 30)

                if self._reconnect_stop.wait(delay):
                    return  # Stop requested

                try:
                    self._sio.connect(
                        self.server_url,
                        transports=['websocket'],
                        wait_timeout=10
                    )
                    # Success! connect handler will re-authenticate
                    # Switch to refresh timer mode
                    self._start_refresh_timer()
                    return

                except Exception as e:
                    logger.debug(f"Reconnect attempt {attempt} failed: {e}")
                    continue

            # Max attempts reached
            self._handle_permanent_disconnect()

        self._reconnect_stop.clear()
        self._reconnect_thread = threading.Thread(
            target=reconnect_loop,
            daemon=True,
            name="OliviaReconnect"
        )
        self._reconnect_thread.start()

    def _reauthenticate(self):
        """Send session re-authentication after reconnect."""
        if not self.session_id or not self._sio:
            return

        if not self._sio.connected:
            return

        try:
            self._transition_state(ConnectionState.AUTHENTICATING, "reauth_start")
            self._sio.emit('authenticate', {'session_id': self.session_id})

            # Wait for auth_response with timeout
            # The response will be handled by on_auth_response handler
            # which will transition state to AUTHENTICATED
            start_time = time.time()
            while time.time() - start_time < 5.0:  # 5 second timeout
                with self._state_lock:
                    if self._state == ConnectionState.AUTHENTICATED:
                        return  # Success!
                    if self._state == ConnectionState.DISCONNECTED:
                        return
                time.sleep(0.1)

        except Exception:
            pass

    def _handle_session_killed(self):
        """Handle session killed by server."""
        self._force_state(ConnectionState.DISCONNECTED, "session_killed")
        self._reconnect_stop.set()  # Stop all reconnection/refresh attempts

        if self.auto_exit:
            print("\n[Olivia] Session expired or was terminated. Closing application...")
            if self.on_session_expired:
                try:
                    self.on_session_expired()
                except Exception:
                    pass
            os._exit(1)

    def _handle_permanent_disconnect(self):
        """Called when all reconnection attempts exhausted."""
        logger.error("Connection permanently lost after max attempts")
        self._force_state(ConnectionState.DISCONNECTED, "max_attempts_reached")

        if self.auto_exit:
            print("\n[Olivia Auth] Failed to reconnect after multiple attempts. Closing...")
            if self.on_session_expired:
                try:
                    self.on_session_expired()
                except Exception:
                    pass
            os._exit(1)

    # =========================================================================
    # WATCHDOG - Auto-exit if authentication is lost
    # =========================================================================

    def _start_watchdog(self):
        """
        Start watchdog thread.

        With the new state machine, the watchdog is simplified:
        - Reconnection is handled by _reconnect_loop()
        - Session killing is handled by _handle_session_killed()
        - Watchdog just keeps the thread alive for callbacks

        NOTE: Most termination logic is now in _handle_session_killed()
        and _handle_permanent_disconnect().
        """
        if not self.auto_exit:
            return

        if self._watchdog_thread and self._watchdog_thread.is_alive():
            return

        self._watchdog_stop.clear()

        def watchdog_loop():
            # Simplified: state machine and reconnect_loop handle everything
            # This just keeps the thread alive
            while not self._watchdog_stop.wait(5):
                pass  # State machine handles all termination logic

        self._watchdog_thread = threading.Thread(
            target=watchdog_loop,
            daemon=True,
            name="OliviaWatchdog"
        )
        self._watchdog_thread.start()

    def _stop_watchdog(self):
        """Stop watchdog thread."""
        self._watchdog_stop.set()
        if self._watchdog_thread:
            self._watchdog_thread.join(timeout=1)

    # =========================================================================
    # APP VARIABLES & WEBHOOKS - Same for both modes
    # =========================================================================

    def get_app_var(self, name: str) -> Optional[Any]:
        """Get an application variable."""
        if not self.initialized:
            raise NotInitializedError()

        response = self._send('getAppVar', {'variableName': name})
        if response.get('success'):
            return response.get('data')
        self.last_error = response.get('message', 'Failed')
        if 'authentication required' in self.last_error.lower():
            print(f"[Olivia] Variable '{name}' requires authentication. Use license() or login() first.")
        return None

    def get_all_app_vars(self) -> Optional[Dict[str, Any]]:
        """Get all application variables."""
        if not self.initialized:
            raise NotInitializedError()

        response = self._send('getAllAppVar', {})
        if response.get('success'):
            return response.get('data')
        self.last_error = response.get('message', 'Failed')
        return None

    def call_webhook(self, webhook_id: str, payload: Dict = None, method: str = "POST") -> Optional[Any]:
        """Call a webhook defined in your app."""
        if not self.initialized:
            raise NotInitializedError()

        response = self._send('webhook', {
            'id': webhook_id,
            'payload': payload or {},
            'method': method.upper(),
            'timeout': 30,
            'contentType': 'application/json'
        })

        if response.get('success'):
            return response.get('data')
        self.last_error = response.get('message', 'Webhook failed')
        if 'not authenticated' in self.last_error.lower() or 'authentication required' in self.last_error.lower():
            print(f"[Olivia] Webhook '{webhook_id}' requires authentication. Use license() or login() first.")
        return None

    # =========================================================================
    # FILE DOWNLOADS
    # =========================================================================

    def download_file(self, download_id: str, save_path: str, show_progress: bool = True) -> bool:
        """
        Download a file by ID.

        Supports both PUBLIC and PRIVATE downloads:
        - PUBLIC: No authentication needed, anyone can download
        - PRIVATE: Requires authenticated session with valid subscription

        If you're already logged in (license/login), this automatically
        uses your session for private downloads.

        Args:
            download_id: Download ID (get from server/dashboard)
            save_path: Where to save (e.g., "update.zip")
            show_progress: Show progress bar (default: True)

        Returns:
            True if successful

        Example:
            >>> # Download when already logged in (works for private files)
            >>> api = Olivia(...)
            >>> api.license("XXXX-XXXX")
            >>> api.download_file("abc123", "update.zip")

            >>> # Download public file (no login needed)
            >>> api = Olivia(...)
            >>> api.download_file("xyz789", "public.zip")
        """
        try:
            url = f"{self.server_url}/api/1.0/download/{download_id}"
            headers = {}

            # If authenticated, add session for private downloads
            if self.authenticated and self.session_id:
                headers['Session-ID'] = self.session_id

            if show_progress:
                print("[Olivia] Downloading...")

            response = requests.get(url, headers=headers, stream=True, timeout=120)

            # Handle errors
            if response.status_code == 401:
                self.last_error = "Authentication required. Please use license() or login() first."
                if show_progress:
                    print(f"[Olivia] {self.last_error}")
                return False

            if response.status_code == 403:
                # Could be banned, paused, or wrong app
                try:
                    error_data = response.json()
                    self.last_error = error_data.get('message', 'Access forbidden')
                except:
                    self.last_error = "Access forbidden - check your subscription status"
                if show_progress:
                    print(f"[Olivia] {self.last_error}")
                return False

            if response.status_code == 404:
                self.last_error = "Download not found or not available"
                if show_progress:
                    print(f"[Olivia] {self.last_error}")
                return False

            if response.status_code == 429:
                try:
                    error_data = response.json()
                    self.last_error = error_data.get('message', 'Rate limit exceeded')
                except:
                    self.last_error = "Too many downloads - try again later"
                if show_progress:
                    print(f"[Olivia] {self.last_error}")
                return False

            if response.status_code != 200:
                self.last_error = f"Download failed: HTTP {response.status_code}"
                if show_progress:
                    print(f"[Olivia] {self.last_error}")
                return False

            # Download file with progress
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0

            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)

                        if show_progress and total_size > 0:
                            percent = (downloaded / total_size) * 100
                            mb_downloaded = downloaded / (1024 * 1024)
                            mb_total = total_size / (1024 * 1024)
                            print(f"\r[Olivia] Downloading... {percent:.1f}% [{mb_downloaded:.2f} MB / {mb_total:.2f} MB]", end='', flush=True)

            if show_progress:
                print(f"\n[Olivia] Download complete: {save_path}")

            self.last_error = None
            return True

        except requests.exceptions.RequestException as e:
            self.last_error = f"Network error: {e}"
            if show_progress:
                print(f"\n[Olivia] {self.last_error}")
            return False
        except IOError as e:
            self.last_error = f"Failed to save file: {e}"
            if show_progress:
                print(f"\n[Olivia] {self.last_error}")
            return False
        except Exception as e:
            self.last_error = f"Error: {e}"
            if show_progress:
                print(f"\n[Olivia] {self.last_error}")
            return False

    def get_download_info(self, download_id: str) -> Optional[Dict[str, Any]]:
        """
        Get download metadata without downloading the file.

        Args:
            download_id: Download ID

        Returns:
            Dict with info (name, description, fileSize, authenticated, etc.)

        Example:
            >>> info = api.get_download_info("abc123")
            >>> if info:
            ...     print(f"{info['name']} - {info['fileSize']} bytes")
            ...     if info['authenticated']:
            ...         print("Requires login")
        """
        try:
            url = f"{self.server_url}/api/1.0/download/{download_id}/info"
            response = requests.get(url, timeout=30)

            if response.status_code != 200:
                self.last_error = f"Failed to get info: HTTP {response.status_code}"
                return None

            data = response.json()
            if not data.get('success'):
                self.last_error = data.get('message', 'Failed to get download info')
                return None

            return data.get('download')

        except Exception as e:
            self.last_error = str(e)
            return None

    @staticmethod
    def quick_download(server_url: str, download_id: str, save_path: str, show_progress: bool = True) -> bool:
        """
        Quick download for PUBLIC files (no authentication).

        Use this for public downloads without creating a session.
        For PRIVATE downloads, use the regular download_file() method after logging in.

        Args:
            server_url: Server URL (e.g., "https://api.oliviauth.xyz")
            download_id: Download ID
            save_path: Where to save the file
            show_progress: Show progress bar

        Returns:
            True if successful

        Example:
            >>> Olivia.quick_download(
            ...     "https://api.oliviauth.xyz",
            ...     "download123",
            ...     "update.zip"
            ... )
            Downloading... 100% [2.5 MB / 2.5 MB]
            Download complete!
            True
        """
        try:
            url = f"{server_url.rstrip('/')}/api/1.0/download/{download_id}"

            if show_progress:
                print("[Olivia] Downloading...")

            response = requests.get(url, stream=True, timeout=120)

            if response.status_code == 401:
                if show_progress:
                    print("[Olivia] This is a private download - authentication required")
                    print("[Olivia] Use the regular download_file() method after logging in")
                return False

            if response.status_code == 429:
                if show_progress:
                    print("[Olivia] Rate limit exceeded - try again later")
                return False

            if response.status_code != 200:
                if show_progress:
                    print(f"[Olivia] Download failed: HTTP {response.status_code}")
                return False

            # Download with progress
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0

            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)

                        if show_progress and total_size > 0:
                            percent = (downloaded / total_size) * 100
                            mb_downloaded = downloaded / (1024 * 1024)
                            mb_total = total_size / (1024 * 1024)
                            print(f"\r[Olivia] Downloading... {percent:.1f}% [{mb_downloaded:.2f} MB / {mb_total:.2f} MB]", end='', flush=True)

            if show_progress:
                print(f"\n[Olivia] Download complete: {save_path}")

            return True

        except Exception as e:
            if show_progress:
                print(f"\n[Olivia] Error: {e}")
            return False

    # =========================================================================
    # UTILITY
    # =========================================================================

    def wait(self):
        """
        Wait/block - keeps app running to receive commands (socket mode).
        In HTTP mode, just blocks while authenticated.
        """
        if self.mode == "socket" and self._sio:
            try:
                self._sio.wait()
            except KeyboardInterrupt:
                pass
        else:
            try:
                while self.authenticated:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass

    def close(self):
        """Close client and cleanup all threads."""
        # Stop reconnection first to prevent new connection attempts
        self._reconnect_stop.set()
        if self._reconnect_thread:
            self._reconnect_thread.join(timeout=2)

        # Stop other threads
        self._stop_watchdog()
        self._stop_heartbeat()

        # Disconnect socket
        if self._sio and self._sio.connected:
            try:
                self._sio.disconnect()
            except Exception:
                pass

        # Reset state
        self._force_state(ConnectionState.DISCONNECTED, "close")
        self.initialized = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
        return False

    def __del__(self):
        try:
            self._reconnect_stop.set()
            self._stop_watchdog()
            self._stop_heartbeat()
            if self._sio and self._sio.connected:
                self._sio.disconnect()
        except Exception:
            pass
