#!/usr/bin/env python3
"""
NetRecon - Asynchronous TCP port scanner with service detection.

Author: vanyanch
License: GPL v3
"""

import asyncio
import socket
import sys
import argparse
from typing import Optional, Dict, List, Set

# -----------------------------------------------------------------------------
# Terminal UI Configuration
# -----------------------------------------------------------------------------

# ANSI escape codes for colored terminal output
# These work on Linux/macOS and Windows 10+ (with ANSI support enabled)
GREEN = "\033[92m"
BLUE = "\033[94m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"

# -----------------------------------------------------------------------------
# Service Definitions
# -----------------------------------------------------------------------------

# Common services based on IANA port assignments and real-world usage
# Includes ports frequently encountered during internal network audits
KNOWN_SERVICES: Dict[int, str] = {
    21: "FTP",           # File Transfer Protocol
    22: "SSH",           # Secure Shell
    23: "Telnet",        # Remote terminal (legacy)
    25: "SMTP",          # Email submission
    53: "DNS",           # Domain Name System
    80: "HTTP",          # Web server
    110: "POP3",         # Email retrieval (legacy)
    143: "IMAP",         # Email retrieval
    443: "HTTPS",        # Secure web server
    3306: "MySQL",       # MySQL database
    3389: "RDP",         # Remote Desktop Protocol
    5432: "PostgreSQL",  # PostgreSQL database
    5900: "VNC",         # Virtual Network Computing (default)
    5901: "VNC (Display 1)",   # First VNC display
    5902: "VNC (Display 2)",   # Second VNC display
    5903: "VNC (Display 3)",   # Third VNC display
    6379: "Redis",       # Redis key-value store
    8080: "HTTP-Proxy",  # Alternate HTTP/Proxy port
}

# Additional VNC ports that are common in enterprise environments
# Range covers typical VNC display numbers 0-9
VNC_PORT_RANGE: Set[int] = set(range(5900, 5910))

# -----------------------------------------------------------------------------
# State Management (for progress tracking)
# -----------------------------------------------------------------------------

# Global counters - yes, globals are generally bad, but for a single-threaded
# async script with progress tracking, this is the simplest approach.
# I've been meaning to refactor this into a class, but it works for now.
scanned_count: int = 0
total_ports: int = 0

# -----------------------------------------------------------------------------
# UI Helper Functions
# -----------------------------------------------------------------------------

def draw_progress_bar() -> None:
    """
    Display a dynamic progress bar in the terminal.
    
    Shows percentage complete and a visual bar. Overwrites the current line
    to avoid scrolling. Uses global counters for state tracking.
    
    Note: This function relies on ANSI escape sequences and may not work
    correctly in all terminal emulators (tested on iTerm2, Windows Terminal,
    and GNOME Terminal).
    """
    if total_ports == 0:
        return
    
    percent = (scanned_count / total_ports) * 100
    bar_length = 30
    filled_length = int(bar_length * scanned_count // total_ports)
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    
    # Use \r to return to start of line, then overwrite with progress
    sys.stdout.write(f"\r{BLUE}[*] Progress: |{bar}| {percent:.1f}% Complete{RESET}")
    sys.stdout.flush()


def clear_line() -> None:
    """
    Clear the current terminal line.
    
    Used before printing open port results to avoid visual interference
    with the progress bar. 
    
    FIXME: This doesn't work perfectly in all terminals when the line
    contains wide Unicode characters. Known issue, but rare.
    """
    sys.stdout.write("\r\033[K")


# -----------------------------------------------------------------------------
# Banner Grabbing Functions
# -----------------------------------------------------------------------------

async def grab_vnc_banner(reader: asyncio.StreamReader) -> Optional[str]:
    """
    Read and parse VNC/RFB protocol handshake.
    
    The RFB protocol sends a version string immediately after connection.
    Format: "RFB 003.008\n" (for version 3.8)
    
    Args:
        reader: Asyncio stream reader for the connected socket
    
    Returns:
        Formatted VNC version string or None if unrecognized
    
    Note:
        - Some older VNC servers (3.3) use "RFB 003.003"
        - TightVNC may include additional negotiation bytes
        - If handshake fails, we silently return None (not critical)
    """
    try:
        data = await asyncio.wait_for(reader.read(12), timeout=1.0)
        if data and data.startswith(b"RFB"):
            # Decode and clean up the version string
            version = data.decode('utf-8', errors='ignore').strip()
            return f"VNC Protocol: {version}"
    except (asyncio.TimeoutError, ConnectionError, UnicodeDecodeError):
        # Common failures: timeout, connection reset, non-UTF8 data
        # This is normal for non-VNC services or network issues
        pass
    return None


async def grab_generic_banner(reader: asyncio.StreamReader, timeout: float = 0.8) -> Optional[str]:
    """
    Read initial service banner from connected socket.
    
    Many services (SSH, FTP, SMTP) send a greeting banner immediately.
    This function attempts to read that banner.
    
    Args:
        reader: Asyncio stream reader
        timeout: Maximum time to wait for data (short, as we don't want to hang)
    
    Returns:
        Decoded banner string or None if no data/error
    
    Notes:
        - HTTP/HTTPS servers typically don't send banners (they wait for requests)
        - Some services may send binary data (SSL/TLS) - we ignore decoding errors
        - Banner length is limited to 256 chars (enough for version strings)
    """
    try:
        raw_banner = await asyncio.wait_for(reader.read(256), timeout)
        if raw_banner:
            # Replace newlines with spaces for cleaner display
            banner = raw_banner.decode('utf-8', errors='ignore').strip()
            return banner.replace('\n', ' ')
    except (asyncio.TimeoutError, UnicodeDecodeError):
        # Timeout is expected (services with no banner)
        # Unicode errors happen with binary data (SSL/TLS)
        pass
    return None


# -----------------------------------------------------------------------------
# Core Scanning Logic
# -----------------------------------------------------------------------------

async def scan_port(target_ip: str, port: int, semaphore: asyncio.Semaphore, timeout: float = 1.0) -> None:
    """
    Scan a single port on the target host.
    
    This function attempts to connect to a port, grabs any available banner,
    and updates the UI with results. It handles all expected failures gracefully.
    
    Args:
        target_ip: Resolved IP address of the target
        port: TCP port to scan
        semaphore: Asyncio semaphore for concurrency control
        timeout: Connection timeout in seconds
    
    Note:
        - Uses a semaphore to prevent socket descriptor exhaustion
        - Open ports are printed immediately for user feedback
        - VNC ports get special handling for protocol detection
    """
    global scanned_count
    
    async with semaphore:
        try:
            # Attempt connection with timeout
            # Using asyncio.open_connection for proper async I/O
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port), 
                timeout=timeout
            )
            
            # Determine service name from known ports
            service_name = KNOWN_SERVICES.get(port, "Unknown Service")
            
            # Clear progress line and print open port result
            clear_line()
            print(f"{GREEN}[+] Port {port:<5} [OPEN] -> {service_name}{RESET}")
            
            # Try to grab a banner
            banner = None
            
            # VNC requires special handshake parsing
            # Note: Port range 5900-5909 is used for VNC displays 0-9
            # Some admins use 5901 for display :1, 5902 for :2, etc.
            if "VNC" in service_name or (5900 <= port <= 5910):
                banner = await grab_vnc_banner(reader)
            else:
                # Generic banner grab for other services
                # This works well for SSH, FTP, SMTP, POP3, etc.
                # It won't work for HTTP, but that's fine - those services don't
                # send greetings without a request
                banner = await grab_generic_banner(reader)
            
            if banner:
                clear_line()
                # Truncate long banners to prevent UI clutter
                display_banner = banner[:80]
                if len(banner) > 80:
                    display_banner += "..."
                print(f"    {CYAN}└── Banner: {display_banner}{RESET}")
                
            # Clean shutdown
            writer.close()
            await writer.wait_closed()
            
        except (socket.gaierror, ConnectionRefusedError, OSError, asyncio.TimeoutError):
            # Expected failures:
            # - socket.gaierror: DNS resolution issues (shouldn't happen after initial resolve)
            # - ConnectionRefusedError: Port closed or filtered
            # - OSError: Network unreachable, no route to host
            # - asyncio.TimeoutError: Packet dropped or filtered
            # These are normal scan results and shouldn't be logged
            pass
        except Exception as e:
            # Unexpected errors - log but don't crash
            # This catches things like "Too many open files" (shouldn't happen with semaphore)
            # or weird OS-level socket issues
            clear_line()
            print(f"{RED}[!] Error scanning port {port}: {e}{RESET}")
        finally:
            # Always update progress, regardless of result
            scanned_count += 1
            draw_progress_bar()


# -----------------------------------------------------------------------------
# Main Scanning Orchestration
# -----------------------------------------------------------------------------

async def run_scan(target_ip: str, ports_to_scan: List[int], concurrency: int) -> None:
    """
    Orchestrate the scanning process with asynchronous tasks.
    
    Args:
        target_ip: Resolved IP address
        ports_to_scan: List of ports to scan
        concurrency: Maximum parallel connections
    
    Implementation notes:
        - Creates a semaphore to limit concurrent connections
        - Uses asyncio.gather to wait for all tasks to complete
        - Progress bar updates as each port scan finishes
    """
    global total_ports, scanned_count
    
    # Reset global state
    scanned_count = 0
    total_ports = len(ports_to_scan)
    
    # Create semaphore for concurrency control
    # This prevents "Too many open files" errors on most systems
    semaphore = asyncio.Semaphore(concurrency)
    
    # Draw initial progress bar
    draw_progress_bar()
    
    # Create tasks for all ports
    # Each task independently handles its port, updates the UI, and manages its own errors
    tasks = [scan_port(target_ip, port, semaphore) for port in ports_to_scan]
    
    # Wait for all tasks to complete
    # asyncio.gather is preferred over asyncio.wait for exception handling
    await asyncio.gather(*tasks)
    
    # Clear the progress line and show final status
    clear_line()


def main() -> None:
    """
    Main entry point for the NetRecon scanner.
    
    Handles command-line argument parsing, target resolution, port list
    construction, and orchestrates the asynchronous scan.
    """
    global total_ports
    
    parser = argparse.ArgumentParser(
        description="High-speed asynchronous port scanner with UI.",
        epilog="Example: python netrecon.py scanme.nmap.org --concurrency 500"
    )
    parser.add_argument("target", help="Target host or IP address")
    parser.add_argument(
        "--all", 
        action="store_true", 
        help="Scan all ports (1-65535) — slower but thorough"
    )
    parser.add_argument(
        "--concurrency", 
        type=int, 
        default=1000, 
        help="Socket concurrency limit (default: 1000)"
    )
    parser.add_argument(
        "--timeout", 
        type=float, 
        default=1.0, 
        help="Connection timeout in seconds (default: 1.0)"
    )
    args = parser.parse_args()

    # Resolve target hostname to IP
    # We do this once upfront to avoid repeated lookups and to fail early
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"{RED}[!] Error: Could not resolve hostname '{args.target}'{RESET}")
        sys.exit(1)

    # Print startup banner
    print(f"{BOLD}🚀 Launching scan for: {YELLOW}{args.target}{RESET} ({target_ip})")
    
    # Build port list based on scan mode
    if args.all:
        # Full scan: all 65,535 TCP ports
        # This will take a while — consider lowering concurrency for stability
        ports_to_scan = list(range(1, 65536))
        print(f"🔍 Mode: {YELLOW}Full Scan (1 - 65535 ports){RESET}")
    else:
        # Quick scan: combine known services with VNC range
        # VNC range 5900-5909 covers display 0-9
        # The union operation ensures no duplicates in case VNC ports overlap with known services
        ports_to_scan = sorted(list(set(KNOWN_SERVICES.keys()).union(VNC_PORT_RANGE)))
        print(f"🔍 Mode: {YELLOW}Popular ports & VNC range ({len(ports_to_scan)} ports){RESET}")

    print(f"⚙️  Socket concurrency limit: {args.concurrency}")
    print("-" * 60)

    # Store total port count for progress bar
    total_ports = len(ports_to_scan)
    
    # Run the asynchronous scan
    try:
        asyncio.run(run_scan(target_ip, ports_to_scan, args.concurrency))
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        # The user will see the interruption, but we don't want a stack trace
        clear_line()
        print(f"\n{RED}[!] Scan interrupted by user.{RESET}")
        sys.exit(1)
    except Exception as e:
        # Unexpected errors during the scan process
        clear_line()
        print(f"\n{RED}[!] Unexpected error: {e}{RESET}")
        sys.exit(1)
    else:
        # Success path
        print("-" * 60)
        print(f"{GREEN}{BOLD}🎯 Target scanning completed successfully.{RESET}")


# -----------------------------------------------------------------------------
# Entry Point
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    # Windows-specific compatibility
    # The default ProactorEventLoop on Windows has issues with certain operations
    # Using SelectorEventLoop provides better compatibility for this use case
    if sys.platform == 'win32':
        # Enable ANSI colors on Windows 10+ (only works in Windows Terminal or modern consoles)
        import os
        os.system('color')
        # Set the event loop policy to use the more compatible selector loop
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    # Run the main function with proper error handling
    try:
        main()
    except KeyboardInterrupt:
        # Handle Ctrl+C at the outermost level as well
        print(f"\n{RED}[!] Scan interrupted by user.{RESET}")
        sys.exit(1)