import re
import time
import subprocess
import logging
import threading

from rich import box
from rich.panel import Panel
from .console import console, Live, Table
from .scanner import passive_arp_scan

log = logging.getLogger("throttnux")


def run(cmd):
    """Executes a shell command and captures its standard output."""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def format_bytes(b):
    """Converts raw byte counts into human-readable strings."""
    if b < 1024:
        return f"{b} B"
    elif b < 1024 ** 2:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 ** 3:
        return f"{b / 1024 ** 2:.1f} MB"
    return f"{b / 1024 ** 3:.2f} GB"


def check_online(interface, ip_address):
    """
    Checks if a device is reachable via ARP — more reliable than ping
    since many devices block ICMP but always respond to ARP requests.
    Falls back to ARP cache check if arping is unavailable.
    """
    # Primary: arping via ARP request (works even on devices that block ICMP)
    try:
        result = subprocess.run(
            ["arping", "-c", "1", "-W", "1", "-I", interface, ip_address],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if result.returncode == 0:
            return True
    except FileNotFoundError:
        pass

    # Fallback: check OS ARP cache
    try:
        result = run(f"ip neigh show {ip_address}")
        output = result.stdout.strip()
        if output and "FAILED" not in output and "INCOMPLETE" not in output:
            return True
    except Exception:
        pass

    return False


def get_tc_stats_per_class(interface):
    """
    Parses tc output to extract traffic statistics per HTB class.

    Returns:
        dict: Mapping of class IDs (int) to total_bytes (int).
              Example: {10: 15420, 11: 5320}
    """
    result = run(f"tc -s class show dev {interface}")
    lines  = result.stdout.splitlines()

    stats            = {}
    current_class_id = None

    for line in lines:
        class_match = re.search(r"class htb 1:(\d+)", line)
        if class_match:
            current_class_id = int(class_match.group(1))
            continue

        if current_class_id is not None:
            sent_match = re.search(r"Sent\s+(\d+)\s+bytes", line)
            if sent_match:
                stats[current_class_id] = int(sent_match.group(1))
                current_class_id = None

    return stats


def verify_spoofing(interface, stop_event):
    """
    Verifies ARP spoofing is working by checking if traffic is flowing
    through tc classes. Waits up to 5 seconds for packets to appear.
    Returns (True, packet_count) if successful, (False, 0) if not.
    """
    for _ in range(5):
        if stop_event.is_set():
            return False, 0
            
        result = run(f"tc -s class show dev {interface}")
        lines = result.stdout.splitlines()
        
        total_pkts = 0
        for idx, line in enumerate(lines):
            if "class htb 1:" in line:
                if idx + 1 < len(lines):
                    m = re.search(r"Sent \d+ bytes (\d+) pkt", lines[idx + 1])
                    if m:
                        total_pkts += int(m.group(1))
                        
        if total_pkts > 0:
            return True, total_pkts
            
        time.sleep(1)
        
    return False, 0


def live_monitor(interface, targets, limit_mbps, stop_event,
                 router_ip=None, whitelist_ips=None, on_new_device=None):
    """
    Orchestrates the live CLI dashboard.
    Uses a background thread for ARP probing to keep UI non-blocking.
    Uses a background thread for passive ARP scanning to dynamically add new devices (whitelist mode).
    Uses threading.Lock to prevent race conditions on shared state.
    """
    states      = {}
    states_lock = threading.Lock()
    known_macs  = set()
    known_ips   = set()

    for i, tgt in enumerate(targets):
        ip = tgt["ip"] if isinstance(tgt, dict) else tgt
        mac = tgt.get("mac", "").lower() if isinstance(tgt, dict) else ""
        vendor = tgt.get("vendor", "Unknown") if isinstance(tgt, dict) else "Unknown"

        known_ips.add(ip)
        if mac:
            known_macs.add(mac)

        states[ip] = {
            "class_id":   10 + i,
            "total_bytes": 0,
            "last_bytes":  0,
            "start_time":  time.time(),
            "is_online":   True,
            "needs_probe": False,
            "vendor":      vendor,
            "added_time":  0,
        }

    safe_ips_set = set(whitelist_ips) if whitelist_ips is not None else set()

    def background_prober():
        """
        Runs ARP probes asynchronously for IPs that need connectivity check.
        Uses Lock to safely update shared state.
        """
        while not stop_event.is_set():
            with states_lock:
                ips_to_probe = [
                    ip for ip, state in states.items()
                    if state["needs_probe"]
                ]

            for ip in ips_to_probe:
                if stop_event.is_set():
                    break
                is_online = check_online(interface, ip)
                with states_lock:
                    if ip in states:
                        states[ip]["is_online"]   = is_online
                        states[ip]["needs_probe"] = False

            stop_event.wait(2)

    def network_watcher():
        """
        Periodically runs a background passive ARP scan to detect new devices.
        In whitelist mode, any newly discovered device not in the whitelist is
        dynamically shaped, spoofed, and added to the monitor.
        """
        while not stop_event.is_set():
            if stop_event.wait(10):
                break

            try:
                found_devices = passive_arp_scan(interface, router_ip)
            except Exception as e:
                log.debug(f"Passive ARP scan error: {e}")
                continue

            for dev in found_devices:
                if stop_event.is_set():
                    break

                dev_ip = dev["ip"]
                dev_mac = dev.get("mac", "").lower()

                # Check if already tracked or whitelisted
                with states_lock:
                    if dev_ip in states or (dev_mac and dev_mac in known_macs):
                        continue
                    if dev_ip in safe_ips_set:
                        continue

                    class_id = None
                    if on_new_device:
                        try:
                            class_id = on_new_device(dev)
                        except Exception as e:
                            log.error(f"Failed to dynamically throttle {dev_ip}: {e}")

                    if class_id is None:
                        class_id = 10 + len(states)

                    now = time.time()
                    states[dev_ip] = {
                        "class_id":   class_id,
                        "total_bytes": 0,
                        "last_bytes":  0,
                        "start_time":  now,
                        "is_online":   True,
                        "needs_probe": False,
                        "vendor":      dev.get("vendor", "Unknown"),
                        "added_time":  now,
                    }
                    known_ips.add(dev_ip)
                    if dev_mac:
                        known_macs.add(dev_mac)

                    if not any((d.get("ip") if isinstance(d, dict) else d) == dev_ip for d in targets):
                        targets.append(dev)

    threading.Thread(target=background_prober, daemon=True).start()

    if router_ip and whitelist_ips is not None:
        threading.Thread(target=network_watcher, daemon=True).start()

    prev_time = time.time()

    with Live(console=console, refresh_per_second=2) as live:
        while not stop_event.is_set():
            now     = time.time()
            elapsed = now - prev_time

            tc_stats = get_tc_stats_per_class(interface)

            table = Table(
                box=box.SIMPLE,
                show_header=True,
                expand=False,
            )
            table.add_column("STATUS",        justify="left")
            table.add_column("TARGET IP",     justify="left")
            table.add_column("DEVICE",        justify="left")
            table.add_column("LIMIT SPEED",   justify="right")
            table.add_column("CURRENT SPEED", justify="right")
            table.add_column("TOTAL DATA",    justify="right")
            table.add_column("SESSION TIME",  justify="center")

            with states_lock:
                target_items = list(targets)

                if not target_items:
                    table.add_row(
                        "[dim cyan]SCANNING[/dim cyan]",
                        "[dim white]Waiting for new devices...[/dim white]",
                        "[dim white]-[/dim white]",
                        f"[dim white]{limit_mbps} Mbps[/dim white]",
                        "[dim white]0.00 Mbps[/dim white]",
                        "[dim white]0 B[/dim white]",
                        "[dim white]00:00:00[/dim white]",
                    )
                else:
                    for tgt in target_items:
                        ip    = tgt["ip"] if isinstance(tgt, dict) else tgt
                        state = states.get(ip)
                        if not state:
                            continue

                        vendor = tgt.get("vendor", "") if isinstance(tgt, dict) else state.get("vendor", "")
                        if not vendor or "locally administered" in vendor.lower():
                            vendor = "Unknown"
                        if len(vendor) > 20:
                            vendor = vendor[:20]

                        current_bytes = tc_stats.get(state["class_id"], state["last_bytes"])
                        delta_bytes   = max(0, current_bytes - state["last_bytes"])

                        mbps = 0.0
                        if elapsed > 0:
                            mbps = (delta_bytes * 8) / (elapsed * 1_000_000)

                        is_new = (state.get("added_time", 0) > 0) and ((now - state["added_time"]) < 30)

                        # Traffic-first: if traffic flowing, device is definitely online
                        if mbps > 0.05:
                            state["needs_probe"] = False
                            state["is_online"]   = True
                            if is_new:
                                status_display = "[bold cyan]NEW • ACTIVE[/bold cyan]"
                            else:
                                status_display = "[bold green]ACTIVE[/bold green]"
                            speed_text = f"[bold green]{mbps:.2f} Mbps[/bold green]"
                            text_style = "white"
                        else:
                            # No traffic — delegate reachability check to background prober
                            state["needs_probe"] = True
                            if is_new:
                                status_display = "[bold cyan]NEW[/bold cyan]"
                                speed_text     = "[dim white]0.00 Mbps[/dim white]"
                                text_style     = "white"
                            elif state["is_online"]:
                                status_display = "[dim white]IDLE[/dim white]"
                                speed_text     = "[dim white]0.00 Mbps[/dim white]"
                                text_style     = "dim white"
                            else:
                                status_display = "[bold magenta]PAUSED[/bold magenta]"
                                speed_text     = "[dim red][OFFLINE][/dim red]"
                                text_style     = "dim white"

                        state["total_bytes"] = current_bytes
                        state["last_bytes"]  = current_bytes

                        uptime     = int(now - state["start_time"])
                        m, s       = divmod(uptime, 60)
                        h, m       = divmod(m, 60)
                        uptime_str = f"{h:02d}:{m:02d}:{s:02d}"
                        total_str  = format_bytes(state["total_bytes"])

                        table.add_row(
                            status_display,
                            f"[{text_style}]{ip}[/{text_style}]",
                            f"[{text_style}]{vendor}[/{text_style}]",
                            f"[{text_style}]{limit_mbps} Mbps[/{text_style}]",
                            speed_text,
                            f"[{text_style}]{total_str}[/{text_style}]",
                            f"[{text_style}]{uptime_str}[/{text_style}]",
                        )

            prev_time = now

            subtitle_str = (
                "[dim cyan]• Dynamic ARP scan active (whitelist mode)[/dim cyan]  [dim white]• Press Ctrl+C to terminate[/dim white]"
                if (whitelist_ips is not None and router_ip)
                else "[dim white]Press Ctrl+C to terminate[/dim white]"
            )

            live.update(Panel(
                table,
                subtitle=subtitle_str,
                title_align="left",
                subtitle_align="right",
                padding=(0, 1),
                expand=False,
            ))

            stop_event.wait(0.5)