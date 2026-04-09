#!/usr/bin/env python3
"""
BugHunter Pro - Installer & SecLists Downloader

This module handles:
  1. Downloading SecLists repository into the wordlists directory
  2. Verifying the installation
  3. Creating fallback wordlists if download fails
"""

import os
import sys
import shutil
import zipfile
import logging
import platform
import subprocess
from pathlib import Path
from typing import Optional

# Determine project root relative to this file's installed location
PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent
WORDLIST_DIR = PROJECT_ROOT / "wordlists"
SECLISTS_DIR = WORDLIST_DIR / "SecLists"

SECLISTS_GIT_URL = "https://github.com/danielmiessler/SecLists.git"
SECLISTS_ZIP_URL = (
    "https://github.com/danielmiessler/SecLists/archive/refs/heads/master.zip"
)

# Specific SecLists files we use
SECLISTS_PATHS = {
    "subdomains": [
        "Discovery/DNS/subdomains-top1million-5000.txt",
        "Discovery/DNS/subdomains-top1million-20000.txt",
        "Discovery/DNS/subdomains-top1million-110000.txt",
        "Discovery/DNS/bitquark-subdomains-top100000.txt",
        "Discovery/DNS/fierce-hostlist.txt",
        "Discovery/DNS/namelist.txt",
        "Discovery/DNS/dns-Jhaddix.txt",
    ],
    "directories": [
        "Discovery/Web-Content/directory-list-2.3-medium.txt",
        "Discovery/Web-Content/directory-list-2.3-small.txt",
        "Discovery/Web-Content/common.txt",
        "Discovery/Web-Content/big.txt",
        "Discovery/Web-Content/raft-medium-directories.txt",
        "Discovery/Web-Content/raft-medium-files.txt",
    ],
    "api_endpoints": [
        "Discovery/Web-Content/api/api-endpoints.txt",
        "Discovery/Web-Content/api/api-seen-in-wild.txt",
        "Discovery/Web-Content/api/objects.txt",
        "Discovery/Web-Content/api/actions.txt",
    ],
    "sqli": [
        "Fuzzing/SQLi/Generic-SQLi.txt",
        "Fuzzing/SQLi/quick-SQLi.txt",
    ],
    "xss": [
        "Fuzzing/XSS/XSS-BruteLogic.txt",
        "Fuzzing/XSS/XSS-Jhaddix.txt",
        "Fuzzing/XSS/XSS-RSNAKE.txt",
    ],
    "lfi": [
        "Fuzzing/LFI/LFI-Jhaddix.txt",
        "Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
    ],
    "ssrf": [
        "Fuzzing/SSRFmap-params.txt" if False else None,
        # SecLists may not have a dedicated SSRF file; we use built-in
    ],
    "passwords": [
        "Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
        "Passwords/Common-Credentials/best1050.txt",
    ],
    "usernames": [
        "Usernames/top-usernames-shortlist.txt",
        "Usernames/Names/names.txt",
    ],
}


def setup_logging() -> logging.Logger:
    """Setup basic console logging for the installer."""
    logger = logging.getLogger("bughunter_installer")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.INFO)
        fmt = logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s",
                                datefmt="%H:%M:%S")
        handler.setFormatter(fmt)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


def check_git_available() -> bool:
    """Check if git is available on the system."""
    try:
        subprocess.run(
            ["git", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def download_via_git(logger: logging.Logger) -> bool:
    """Clone SecLists using git (shallow clone for speed)."""
    logger.info("Downloading SecLists via git (shallow clone)...")

    try:
        if SECLISTS_DIR.exists():
            logger.info("SecLists directory exists. Pulling updates...")
            subprocess.run(
                ["git", "-C", str(SECLISTS_DIR), "pull", "--depth=1"],
                capture_output=True, text=True, timeout=600,
            )
            return True

        subprocess.run(
            [
                "git", "clone", "--depth=1",
                SECLISTS_GIT_URL,
                str(SECLISTS_DIR),
            ],
            capture_output=False,
            timeout=900,  # 15 minute timeout for slow connections
        )
        return SECLISTS_DIR.exists()

    except subprocess.TimeoutExpired:
        logger.error("Git clone timed out (15 min limit)")
        return False
    except Exception as e:
        logger.error(f"Git clone failed: {e}")
        return False


def download_via_zip(logger: logging.Logger) -> bool:
    """Download SecLists as a ZIP archive (fallback)."""
    logger.info("Downloading SecLists as ZIP archive...")

    try:
        import requests
    except ImportError:
        logger.error("requests library not available for ZIP download")
        return False

    zip_path = WORDLIST_DIR / "seclists-master.zip"

    try:
        logger.info(f"Downloading from {SECLISTS_ZIP_URL} ...")
        resp = requests.get(SECLISTS_ZIP_URL, stream=True, timeout=600)
        resp.raise_for_status()

        total_size = int(resp.headers.get("content-length", 0))
        downloaded = 0

        with open(zip_path, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=8192):
                fh.write(chunk)
                downloaded += len(chunk)
                if total_size > 0:
                    pct = (downloaded / total_size) * 100
                    print(f"\r  Progress: {pct:.1f}% ({downloaded // 1024 // 1024}MB)", end="", flush=True)

        print()  # newline after progress
        logger.info("Download complete. Extracting...")

        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(WORDLIST_DIR)

        # Rename extracted directory
        extracted_dir = WORDLIST_DIR / "SecLists-master"
        if extracted_dir.exists():
            if SECLISTS_DIR.exists():
                shutil.rmtree(SECLISTS_DIR)
            extracted_dir.rename(SECLISTS_DIR)

        # Clean up zip
        zip_path.unlink(missing_ok=True)

        return SECLISTS_DIR.exists()

    except Exception as e:
        logger.error(f"ZIP download failed: {e}")
        zip_path.unlink(missing_ok=True)
        return False


def generate_fallback_wordlists(logger: logging.Logger) -> None:
    """Generate minimal fallback wordlists if SecLists download fails."""
    logger.warning("Generating fallback wordlists (limited)...")

    fallback_dir = WORDLIST_DIR / "fallback"
    fallback_dir.mkdir(parents=True, exist_ok=True)

    # Subdomain fallback
    subdomains = [
        "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
        "beta", "portal", "app", "m", "mobile", "blog", "shop", "store",
        "cdn", "media", "static", "assets", "docs", "wiki", "help",
        "support", "status", "dashboard", "panel", "auth", "login", "sso",
        "vpn", "remote", "git", "jenkins", "ci", "deploy", "internal",
        "backup", "db", "database", "mysql", "redis", "elastic", "grafana",
        "prometheus", "kibana", "monitor", "log", "staging", "preprod",
        "sandbox", "demo", "uat", "qa", "ns1", "ns2", "smtp", "webmail",
    ]
    (fallback_dir / "subdomains.txt").write_text("\n".join(subdomains) + "\n")

    # Directory fallback
    directories = [
        "admin", "login", "dashboard", "api", "api/v1", "api/v2",
        "config", "backup", ".env", ".git", ".git/HEAD", "robots.txt",
        "sitemap.xml", "phpinfo.php", "server-status", ".htaccess",
        "wp-admin", "wp-login.php", "wp-json", "phpmyadmin",
        "swagger", "graphql", "debug", "test", "console",
        "uploads", "images", "static", "assets", "docs",
        ".well-known/security.txt", "health", "status", "metrics",
    ]
    (fallback_dir / "directories.txt").write_text("\n".join(directories) + "\n")

    # API fallback
    api_endpoints = [
        "api/users", "api/login", "api/auth", "api/token", "api/admin",
        "api/config", "api/search", "api/upload", "api/profile", "api/me",
        "api/v1/users", "api/v1/auth", "api/health", "api/status",
        "api/docs", "api/swagger", "api/graphql", "api/internal",
    ]
    (fallback_dir / "api_endpoints.txt").write_text("\n".join(api_endpoints) + "\n")

    logger.info(f"Fallback wordlists created in {fallback_dir}")


def verify_installation(logger: logging.Logger) -> bool:
    """Verify SecLists is properly installed."""
    if not SECLISTS_DIR.exists():
        return False

    # Check for a few key files
    key_files = [
        "Discovery/DNS/subdomains-top1million-5000.txt",
        "Discovery/Web-Content/common.txt",
    ]

    all_found = True
    for rel_path in key_files:
        full_path = SECLISTS_DIR / rel_path
        if full_path.exists():
            logger.info(f"  ✅ {rel_path}")
        else:
            logger.warning(f"  ❌ {rel_path} not found")
            all_found = False

    return all_found


def get_seclists_path(category: str, index: int = 0) -> Optional[str]:
    """
    Get the absolute path to a SecLists wordlist file.
    Falls back to next available file in the category if preferred one missing.
    Falls back to fallback wordlists if SecLists not installed.
    """
    if category in SECLISTS_PATHS:
        paths = [p for p in SECLISTS_PATHS[category] if p is not None]
        for i, rel_path in enumerate(paths):
            if i < index:
                continue
            full_path = SECLISTS_DIR / rel_path
            if full_path.exists():
                return str(full_path)

    # Fallback
    fallback_map = {
        "subdomains": WORDLIST_DIR / "fallback" / "subdomains.txt",
        "directories": WORDLIST_DIR / "fallback" / "directories.txt",
        "api_endpoints": WORDLIST_DIR / "fallback" / "api_endpoints.txt",
    }

    fallback = fallback_map.get(category)
    if fallback and fallback.exists():
        return str(fallback)

    return None


def download_seclists() -> bool:
    """Main download function. Tries git first, then ZIP."""
    logger = setup_logging()

    logger.info("=" * 50)
    logger.info("BugHunter Pro - SecLists Installer")
    logger.info("=" * 50)

    # Create wordlists directory
    WORDLIST_DIR.mkdir(parents=True, exist_ok=True)

    # Check if already installed
    if SECLISTS_DIR.exists() and verify_installation(logger):
        logger.info("SecLists is already installed and verified!")
        return True

    # Try git clone
    success = False
    if check_git_available():
        success = download_via_git(logger)
    else:
        logger.info("Git not available, trying ZIP download...")

    # Fallback to ZIP
    if not success:
        success = download_via_zip(logger)

    # Verify
    if success and verify_installation(logger):
        logger.info("✅ SecLists installed successfully!")
        return True

    # Generate fallback
    logger.warning("SecLists download failed. Creating fallback wordlists...")
    generate_fallback_wordlists(logger)
    return False


def show_wordlist_info() -> None:
    """Display information about available wordlists."""
    logger = setup_logging()

    logger.info("=" * 50)
    logger.info("Available Wordlists")
    logger.info("=" * 50)

    for category, paths in SECLISTS_PATHS.items():
        logger.info(f"\n📁 {category.upper()}:")
        valid_paths = [p for p in paths if p is not None]
        for rel_path in valid_paths:
            full_path = SECLISTS_DIR / rel_path
            if full_path.exists():
                size = full_path.stat().st_size
                lines = sum(1 for _ in open(full_path, errors="ignore"))
                logger.info(f"   ✅ {rel_path} ({lines:,} entries, {size // 1024}KB)")
            else:
                logger.info(f"   ❌ {rel_path} (not found)")


def main():
    """Entry point for bughunter-install command."""
    import argparse

    parser = argparse.ArgumentParser(
        description="BugHunter Pro - SecLists Installer & Wordlist Manager"
    )
    parser.add_argument(
        "--info", action="store_true",
        help="Show information about available wordlists",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Force re-download of SecLists",
    )
    parser.add_argument(
        "--fallback-only", action="store_true",
        help="Only generate fallback wordlists (skip SecLists download)",
    )

    args = parser.parse_args()
    logger = setup_logging()

    if args.info:
        show_wordlist_info()
        return

    if args.fallback_only:
        WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
        generate_fallback_wordlists(logger)
        return

    if args.force and SECLISTS_DIR.exists():
        logger.info("Force flag set. Removing existing SecLists...")
        shutil.rmtree(SECLISTS_DIR)

    download_seclists()


if __name__ == "__main__":
    main()