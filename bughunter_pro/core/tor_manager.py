#!/usr/bin/env python3
"""
BugHunter Pro - Tor Service Manager

Handles:
  - Detecting Tor installation across platforms
  - Auto-starting/stopping Tor service on Linux and macOS
  - Providing SOCKS5 proxy configuration for requests
  - Verifying Tor connectivity
  - Renewing Tor circuits (new identity)
  - Graceful fallback on Windows
"""

import os
import sys
import time
import socket
import logging
import platform
import subprocess
import shutil
from typing import Dict, Optional, Tuple

logger = logging.getLogger("bughunter")

# Default Tor SOCKS5 proxy settings
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051


class TorManager:
    """Manages Tor service lifecycle and proxy configuration."""

    def __init__(
        self,
        socks_port: int = TOR_SOCKS_PORT,
        control_port: int = TOR_CONTROL_PORT,
        control_password: str = "",
    ):
        self.socks_host = TOR_SOCKS_HOST
        self.socks_port = socks_port
        self.control_port = control_port
        self.control_password = control_password
        self.system = platform.system().lower()
        self.tor_started_by_us = False
        self.is_connected = False
        self.original_ip: Optional[str] = None
        self.tor_ip: Optional[str] = None

    # ================================================================
    # PUBLIC API
    # ================================================================

    def setup(self) -> bool:
        """
        Full Tor setup: detect, install if needed, start, verify.
        Returns True if Tor is usable.
        """
        logger.info("[TOR] Setting up Tor service...")
        logger.info(f"[TOR] Platform: {self.system} ({platform.platform()})")

        # Windows: skip with warning
        if self.system == "windows":
            logger.warning(
                "[TOR] Tor auto-configuration is not supported on Windows."
            )
            logger.warning(
                "[TOR] To use Tor on Windows:"
            )
            logger.warning(
                "[TOR]   1. Download Tor Expert Bundle: "
                "https://www.torproject.org/download/tor/"
            )
            logger.warning(
                "[TOR]   2. Run tor.exe manually before starting the scan"
            )
            logger.warning(
                "[TOR]   3. Or install Tor Browser and enable SOCKS proxy"
            )

            # Check if Tor is already running (user started manually)
            if self._is_tor_port_open():
                logger.info(
                    "[TOR] Detected Tor running on Windows (manual start). Using it."
                )
                return self._verify_tor_connection()
            else:
                logger.warning("[TOR] Tor is NOT running. Proceeding without Tor.")
                return False

        # Linux / macOS: auto-detect and start
        return self._setup_unix()

    def teardown(self) -> None:
        """Stop Tor if we started it."""
        if self.tor_started_by_us:
            logger.info("[TOR] Stopping Tor service (started by us)...")
            self._stop_tor_service()
            self.tor_started_by_us = False
        self.is_connected = False

    def get_proxy_dict(self) -> Dict[str, str]:
        """Return requests-compatible proxy dictionary."""
        if not self.is_connected:
            return {}
        proxy_url = f"socks5h://{self.socks_host}:{self.socks_port}"
        return {
            "http": proxy_url,
            "https": proxy_url,
        }

    def get_session_proxies(self) -> Dict[str, str]:
        """Alias for get_proxy_dict for clarity."""
        return self.get_proxy_dict()

    def renew_circuit(self) -> bool:
        """
        Request a new Tor circuit (new identity / IP address).
        Requires Tor ControlPort to be enabled.
        """
        logger.info("[TOR] Requesting new Tor circuit (new identity)...")

        try:
            from stem import Signal
            from stem.control import Controller

            with Controller.from_port(
                address=self.socks_host, port=self.control_port
            ) as controller:
                if self.control_password:
                    controller.authenticate(password=self.control_password)
                else:
                    controller.authenticate()

                controller.signal(Signal.NEWNYM)
                time.sleep(5)  # Wait for new circuit
                logger.info("[TOR] New circuit established")

                # Verify new IP
                new_ip = self._get_current_ip_via_tor()
                if new_ip and new_ip != self.tor_ip:
                    logger.info(f"[TOR] New IP: {new_ip} (was: {self.tor_ip})")
                    self.tor_ip = new_ip
                return True

        except ImportError:
            logger.warning(
                "[TOR] stem library needed for circuit renewal. "
                "Install: pip install stem"
            )
            return False
        except Exception as e:
            logger.warning(f"[TOR] Circuit renewal failed: {e}")
            return False

    def get_status(self) -> Dict:
        """Return current Tor status information."""
        return {
            "platform": self.system,
            "connected": self.is_connected,
            "socks_proxy": f"{self.socks_host}:{self.socks_port}",
            "original_ip": self.original_ip,
            "tor_ip": self.tor_ip,
            "started_by_us": self.tor_started_by_us,
        }

    # ================================================================
    # UNIX (Linux / macOS) SETUP
    # ================================================================

    def _setup_unix(self) -> bool:
        """Setup Tor on Linux or macOS."""

        # Step 1: Check if Tor is already running
        if self._is_tor_port_open():
            logger.info("[TOR] Tor is already running")
            return self._verify_tor_connection()

        # Step 2: Check if Tor is installed
        tor_path = self._find_tor_binary()
        if not tor_path:
            logger.info("[TOR] Tor not found. Attempting to install...")
            if not self._install_tor():
                logger.error(
                    "[TOR] Could not install Tor. "
                    "Please install manually: sudo apt install tor"
                )
                return False
            tor_path = self._find_tor_binary()
            if not tor_path:
                logger.error("[TOR] Tor still not found after install attempt")
                return False

        logger.info(f"[TOR] Tor binary found: {tor_path}")

        # Step 3: Start Tor service
        if not self._start_tor_service():
            logger.error("[TOR] Failed to start Tor service")
            return False

        # Step 4: Wait for Tor to bootstrap
        if not self._wait_for_tor(timeout=60):
            logger.error("[TOR] Tor failed to become ready within timeout")
            return False

        # Step 5: Verify connection
        return self._verify_tor_connection()

    # ================================================================
    # TOR BINARY DETECTION
    # ================================================================

    def _find_tor_binary(self) -> Optional[str]:
        """Find the Tor binary on the system."""
        tor_path = shutil.which("tor")
        if tor_path:
            return tor_path

        # Common locations
        common_paths = [
            "/usr/bin/tor",
            "/usr/sbin/tor",
            "/usr/local/bin/tor",
            "/opt/homebrew/bin/tor",  # macOS ARM Homebrew
            "/usr/local/Cellar/tor",  # macOS Intel Homebrew
            "/snap/bin/tor",
        ]
        for path in common_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path

        return None

    # ================================================================
    # TOR INSTALLATION
    # ================================================================

    def _install_tor(self) -> bool:
        """Attempt to install Tor using the system package manager."""
        logger.info("[TOR] Attempting automatic Tor installation...")

        if self.system == "darwin":
            return self._install_tor_macos()
        elif self.system == "linux":
            return self._install_tor_linux()
        return False

    def _install_tor_linux(self) -> bool:
        """Install Tor on Linux using detected package manager."""
        package_managers = [
            # (check_cmd, install_cmd)
            (
                ["apt-get", "--version"],
                ["sudo", "apt-get", "install", "-y", "tor"],
            ),
            (
                ["dnf", "--version"],
                ["sudo", "dnf", "install", "-y", "tor"],
            ),
            (
                ["yum", "--version"],
                ["sudo", "yum", "install", "-y", "tor"],
            ),
            (
                ["pacman", "--version"],
                ["sudo", "pacman", "-Sy", "--noconfirm", "tor"],
            ),
            (
                ["zypper", "--version"],
                ["sudo", "zypper", "install", "-y", "tor"],
            ),
            (
                ["apk", "--version"],
                ["sudo", "apk", "add", "tor"],
            ),
            (
                ["emerge", "--version"],
                ["sudo", "emerge", "net-vpn/tor"],
            ),
        ]

        for check_cmd, install_cmd in package_managers:
            try:
                subprocess.run(
                    check_cmd,
                    capture_output=True, timeout=5,
                )
                logger.info(
                    f"[TOR] Using package manager: {check_cmd[0]}"
                )

                # Update package index for apt
                if check_cmd[0] == "apt-get":
                    subprocess.run(
                        ["sudo", "apt-get", "update", "-qq"],
                        capture_output=True, timeout=120,
                    )

                result = subprocess.run(
                    install_cmd,
                    capture_output=True, text=True, timeout=300,
                )
                if result.returncode == 0:
                    logger.info("[TOR] Tor installed successfully")
                    return True
                else:
                    logger.warning(
                        f"[TOR] Install returned code {result.returncode}: "
                        f"{result.stderr[:200]}"
                    )
            except FileNotFoundError:
                continue
            except subprocess.TimeoutExpired:
                logger.warning(
                    f"[TOR] Install via {check_cmd[0]} timed out"
                )
                continue
            except Exception as e:
                logger.debug(f"[TOR] {check_cmd[0]} failed: {e}")
                continue

        return False

    def _install_tor_macos(self) -> bool:
        """Install Tor on macOS using Homebrew."""
        try:
            brew_path = shutil.which("brew")
            if not brew_path:
                logger.warning(
                    "[TOR] Homebrew not found. "
                    "Install from https://brew.sh"
                )
                return False

            logger.info("[TOR] Installing Tor via Homebrew...")
            result = subprocess.run(
                ["brew", "install", "tor"],
                capture_output=True, text=True, timeout=300,
            )
            return result.returncode == 0

        except Exception as e:
            logger.error(f"[TOR] Homebrew install failed: {e}")
            return False

    # ================================================================
    # TOR SERVICE MANAGEMENT
    # ================================================================

    def _start_tor_service(self) -> bool:
        """Start the Tor service."""
        logger.info("[TOR] Starting Tor service...")

        if self.system == "darwin":
            return self._start_tor_macos()
        elif self.system == "linux":
            return self._start_tor_linux()
        return False

    def _start_tor_linux(self) -> bool:
        """Start Tor on Linux using systemctl or service command."""
        # Try systemctl first
        if shutil.which("systemctl"):
            try:
                # Enable the service
                subprocess.run(
                    ["sudo", "systemctl", "enable", "tor"],
                    capture_output=True, timeout=30,
                )
                # Start the service
                result = subprocess.run(
                    ["sudo", "systemctl", "start", "tor"],
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0:
                    self.tor_started_by_us = True
                    logger.info("[TOR] Started via systemctl")
                    return True
                else:
                    logger.debug(
                        f"[TOR] systemctl start failed: {result.stderr}"
                    )
            except Exception as e:
                logger.debug(f"[TOR] systemctl failed: {e}")

        # Try service command
        if shutil.which("service"):
            try:
                result = subprocess.run(
                    ["sudo", "service", "tor", "start"],
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0:
                    self.tor_started_by_us = True
                    logger.info("[TOR] Started via service command")
                    return True
            except Exception as e:
                logger.debug(f"[TOR] service command failed: {e}")

        # Try running tor directly in background
        try:
            tor_path = self._find_tor_binary()
            if tor_path:
                process = subprocess.Popen(
                    [tor_path, "--runasdaemon", "1"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                time.sleep(3)
                if process.poll() is None or self._is_tor_port_open():
                    self.tor_started_by_us = True
                    logger.info("[TOR] Started as background daemon")
                    return True
        except Exception as e:
            logger.debug(f"[TOR] Direct tor start failed: {e}")

        return False

    def _start_tor_macos(self) -> bool:
        """Start Tor on macOS."""
        # Try brew services
        if shutil.which("brew"):
            try:
                result = subprocess.run(
                    ["brew", "services", "start", "tor"],
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0:
                    self.tor_started_by_us = True
                    logger.info("[TOR] Started via brew services")
                    return True
            except Exception as e:
                logger.debug(f"[TOR] brew services failed: {e}")

        # Try running tor directly
        try:
            tor_path = self._find_tor_binary()
            if tor_path:
                process = subprocess.Popen(
                    [tor_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                time.sleep(3)
                if process.poll() is None or self._is_tor_port_open():
                    self.tor_started_by_us = True
                    logger.info("[TOR] Started as background process")
                    return True
        except Exception as e:
            logger.debug(f"[TOR] Direct tor start failed: {e}")

        return False

    def _stop_tor_service(self) -> None:
        """Stop the Tor service."""
        if self.system == "darwin":
            try:
                subprocess.run(
                    ["brew", "services", "stop", "tor"],
                    capture_output=True, timeout=15,
                )
            except Exception:
                pass
        elif self.system == "linux":
            try:
                if shutil.which("systemctl"):
                    subprocess.run(
                        ["sudo", "systemctl", "stop", "tor"],
                        capture_output=True, timeout=15,
                    )
                elif shutil.which("service"):
                    subprocess.run(
                        ["sudo", "service", "tor", "stop"],
                        capture_output=True, timeout=15,
                    )
            except Exception:
                pass

        logger.info("[TOR] Tor service stopped")

    # ================================================================
    # CONNECTION VERIFICATION
    # ================================================================

    def _is_tor_port_open(self) -> bool:
        """Check if the Tor SOCKS port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.socks_host, self.socks_port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _wait_for_tor(self, timeout: int = 60) -> bool:
        """Wait for Tor to become ready (port open)."""
        logger.info(f"[TOR] Waiting for Tor to bootstrap (timeout: {timeout}s)...")
        start = time.time()

        while (time.time() - start) < timeout:
            if self._is_tor_port_open():
                elapsed = time.time() - start
                logger.info(
                    f"[TOR] Tor is ready (took {elapsed:.1f}s)"
                )
                return True
            time.sleep(2)
            elapsed = time.time() - start
            if int(elapsed) % 10 == 0:
                logger.debug(
                    f"[TOR] Still waiting... ({elapsed:.0f}s/{timeout}s)"
                )

        return False

    def _verify_tor_connection(self) -> bool:
        """Verify that requests actually go through Tor."""
        logger.info("[TOR] Verifying Tor connection...")

        # Get original IP first
        self.original_ip = self._get_current_ip_direct()
        logger.info(f"[TOR] Original IP: {self.original_ip or 'unknown'}")

        # Get Tor IP
        self.tor_ip = self._get_current_ip_via_tor()

        if self.tor_ip:
            if self.original_ip and self.tor_ip != self.original_ip:
                logger.info(
                    f"[TOR] ✅ Tor is working! "
                    f"Tor IP: {self.tor_ip} (Original: {self.original_ip})"
                )
                self.is_connected = True
                return True
            elif not self.original_ip:
                # Can't verify different IP, but Tor responded
                logger.info(
                    f"[TOR] ✅ Tor appears to be working. "
                    f"Tor IP: {self.tor_ip}"
                )
                self.is_connected = True
                return True
            else:
                logger.warning(
                    f"[TOR] ⚠️ Same IP through Tor ({self.tor_ip}). "
                    "Tor may not be routing properly."
                )
                self.is_connected = True  # Still use it
                return True
        else:
            logger.error("[TOR] ❌ Could not verify Tor connection")
            return False

    def _get_current_ip_direct(self) -> Optional[str]:
        """Get current public IP without Tor."""
        import requests

        ip_services = [
            "https://api.ipify.org?format=text",
            "https://ifconfig.me/ip",
            "https://icanhazip.com",
            "https://checkip.amazonaws.com",
        ]

        for url in ip_services:
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200:
                    return resp.text.strip()
            except Exception:
                continue
        return None

    def _get_current_ip_via_tor(self) -> Optional[str]:
        """Get current public IP through Tor proxy."""
        import requests

        proxy = {
            "http": f"socks5h://{self.socks_host}:{self.socks_port}",
            "https": f"socks5h://{self.socks_host}:{self.socks_port}",
        }

        ip_services = [
            "https://api.ipify.org?format=text",
            "https://check.torproject.org/api/ip",
            "https://ifconfig.me/ip",
            "https://icanhazip.com",
        ]

        for url in ip_services:
            try:
                resp = requests.get(url, proxies=proxy, timeout=15)
                if resp.status_code == 200:
                    text = resp.text.strip()
                    # Handle JSON response from Tor project
                    if "{" in text:
                        import json
                        data = json.loads(text)
                        return data.get("IP", text)
                    return text
            except Exception:
                continue
        return None

    # ================================================================
    # CONTEXT MANAGER SUPPORT
    # ================================================================

    def __enter__(self):
        self.setup()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.teardown()
        return False