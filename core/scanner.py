import re
import sys
import subprocess
import logging
import questionary
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

from .console import (
    console,
    Table,
    box,
    qselect
    )

log = logging.getLogger("throttnux")

# In-memory hostname cache to avoid duplicate DNS lookups
_HOSTNAME_CACHE = {}


def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def resolve_hostname(ip, timeout=0.25):
    """
    Ultra-lightweight reverse DNS / NetBIOS hostname resolution.
    Returns hostname string or '' if not found.
    """
    if not ip or ip == "-" or ip == "Unknown":
        return ""
    if ip in _HOSTNAME_CACHE:
        return _HOSTNAME_CACHE[ip]

    name = ""
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        host, _, _ = socket.gethostbyaddr(ip)
        socket.setdefaulttimeout(old_timeout)
        if host and host != ip:
            # Clean up domain suffix e.g. "my-phone.lan" -> "my-phone"
            name = host.split('.')[0] if not host.endswith('.local') else host
    except Exception:
        name = ""

    _HOSTNAME_CACHE[ip] = name
    return name


def populate_hostnames(devices):
    """
    Lightweight concurrent hostname resolver across a batch of devices.
    Runs non-blocking threads with 0.25s timeout.
    """
    ips_to_query = [
        d["ip"] for d in devices
        if d.get("ip") and d["ip"] != "-" and d["ip"] != "Unknown" and not d.get("hostname")
    ]

    if ips_to_query:
        try:
            with ThreadPoolExecutor(max_workers=min(len(ips_to_query), 12)) as executor:
                results = list(executor.map(resolve_hostname, ips_to_query))
            ip_map = dict(zip(ips_to_query, results))
            for d in devices:
                ip = d.get("ip")
                if ip in ip_map and ip_map[ip]:
                    d["hostname"] = ip_map[ip]
                elif "hostname" not in d:
                    d["hostname"] = ""
        except Exception:
            for d in devices:
                if "hostname" not in d:
                    d["hostname"] = ""
    else:
        for d in devices:
            if "hostname" not in d:
                d["hostname"] = ""

    return devices


def device_sort_key(dev):
    """
    Safe sorting key for device dictionaries.
    Sorts valid IPv4/IPv6 addresses numerically first.
    Sorts unknown, missing, or '-' IP addresses alphabetically by MAC.
    """
    if not isinstance(dev, dict):
        return (2, str(dev))
    ip_str = dev.get("ip")
    if ip_str and ip_str != "Unknown" and ip_str != "-":
        try:
            return (0, int(ipaddress.ip_address(ip_str)))
        except ValueError:
            pass
    return (1, dev.get("mac", "").lower())


def passive_arp_scan(interface, router_ip):
    """
    Lightweight silent ARP scan for background polling and active discovery.
    Includes fast hostname lookup.
    """
    result = run(f"arp-scan --localnet -I {interface}")

    devices = []
    for line in result.stdout.splitlines():
        match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([\w:]+)\s*(.*)", line)
        if match:
            ip, mac, vendor = match.groups()
            if ip == router_ip:
                continue
            
            vendor_clean = vendor.strip()

            if not vendor_clean or "locally administered" in vendor_clean.lower():
                vendor_name = "Unknown"
            else:
                vendor_name = vendor_clean
            
            devices.append({
                "ip":       ip,
                "mac":      mac.lower(),
                "vendor":   vendor_name,
                "hostname": ""
            })
    
    devices = populate_hostnames(devices)
    devices.sort(key=device_sort_key)
    return devices


def merge_devices(existing_devices, new_devices):
    """
    Merge existing scanned devices with newly scanned devices.
    Retains all previously discovered devices so none are lost on rescan.
    Updates IP, Vendor, and Hostname if changed.
    """
    if not existing_devices:
        return list(new_devices)

    merged = {d["mac"].lower(): dict(d) for d in existing_devices if d.get("mac") and d["mac"] != "Unknown"}
    by_ip = {d["ip"]: dict(d) for d in existing_devices if (not d.get("mac") or d["mac"] == "Unknown") and d.get("ip") and d["ip"] != "-"}

    for dev in new_devices:
        mac = dev.get("mac", "").lower()
        ip = dev.get("ip", "-")
        hostname = dev.get("hostname", "")
        vendor = dev.get("vendor", "")

        if mac and mac != "Unknown":
            if mac in merged:
                if ip and ip != "-":
                    merged[mac]["ip"] = ip
                if vendor and vendor != "Unknown":
                    merged[mac]["vendor"] = vendor
                if hostname:
                    merged[mac]["hostname"] = hostname
            else:
                merged[mac] = dict(dev)
        elif ip and ip != "-":
            if ip in by_ip:
                if vendor and vendor != "Unknown":
                    by_ip[ip]["vendor"] = vendor
                if hostname:
                    by_ip[ip]["hostname"] = hostname
            else:
                by_ip[ip] = dict(dev)

    result = list(merged.values()) + list(by_ip.values())
    result.sort(key=device_sort_key)
    return result



def resolve_mac(ip, interface=None):
    """
    Attempt to resolve MAC address for an IP address by checking ARP cache
    and sending an ICMP echo (ping) to trigger kernel ARP resolution.
    """
    if not ip or ip == "-" or ip == "Unknown":
        return ""

    # 1. Quick check in existing kernel ARP/neighbor table
    try:
        res = run(f"ip neigh show {ip}")
        m = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", res.stdout)
        if m:
            return m.group(1).lower()
        res = run(f"arp -n {ip}")
        m = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", res.stdout)
        if m:
            return m.group(1).lower()
    except Exception:
        pass

    # 2. Ping once to prompt ARP resolution
    try:
        ping_cmd = f"ping -I {interface} -c 1 -W 1 {ip}" if interface else f"ping -c 1 -W 1 {ip}"
        run(ping_cmd)

        res = run(f"ip neigh show {ip}")
        m = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", res.stdout)
        if m:
            return m.group(1).lower()

        res = run(f"arp -n {ip}")
        m = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", res.stdout)
        if m:
            return m.group(1).lower()
    except Exception:
        pass

    return ""


def prompt_manual_device(interface=None):
    """
    Prompt user to manually input IP address or MAC address,
    auto-resolving the other when possible, plus optional friendly name/label.
    IP is completely optional when entering a MAC address.
    Returns: {"ip": ip, "mac": mac, "vendor": vendor} or None.
    """
    console.print("\n [bold white]Manual Device Entry[/bold white]")
    try:
        user_input = input("  Enter IP or MAC address (e.g. 192.168.1.50 or aa:bb:cc:dd:ee:ff): ").strip()
        if not user_input:
            console.print("  [warning]No address entered. Cancelled.[/warning]\n")
            return None

        clean_input = user_input.replace("-", ":").strip().lower()
        is_mac = bool(re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", clean_input))

        if is_mac:
            mac = clean_input
            # Auto-detect IP silently from kernel neighbor cache if available
            ip = "-"
            try:
                res = run("ip neigh show")
                for line in res.stdout.splitlines():
                    if mac in line.lower():
                        parts = line.split()
                        if parts:
                            ip = parts[0]
                            console.print(f"  [dim]Auto-detected active IP: {ip}[/dim]")
                            break
            except Exception:
                pass
        else:
            try:
                ipaddress.ip_address(user_input)
                ip = user_input
            except ValueError:
                console.print(f"  [error]Invalid IP or MAC format: '{user_input}'[/error]\n")
                return None

            # Attempt to auto-detect MAC
            with console.status("Checking local ARP cache for MAC...", spinner="dots"):
                resolved_mac = resolve_mac(ip, interface)
            if resolved_mac:
                console.print(f"  [dim]Auto-detected MAC address: {resolved_mac}[/dim]")
                mac_input = input(f"  Enter MAC address [{resolved_mac}]: ").strip().lower()
                mac = mac_input.replace("-", ":") if mac_input else resolved_mac
            else:
                mac_input = input("  Enter MAC address (optional, e.g. aa:bb:cc:dd:ee:ff): ").strip().lower()
                mac = mac_input.replace("-", ":") if mac_input else "Unknown"

        name_input = input("  Enter friendly name/label (optional, e.g. My Phone): ").strip()
        vendor = name_input if name_input else "Manual Entry"

        dev = {
            "ip": ip,
            "mac": mac,
            "vendor": vendor
        }
        if ip and ip != "-":
            console.print(f"  [success]✓ Added device: {ip} ({mac}) - {vendor}[/success]\n")
        else:
            console.print(f"  [success]✓ Added device: {mac} ({vendor})[/success]\n")
        return dev
    except KeyboardInterrupt:
        console.print("\n  [dim]Cancelled manual entry.[/dim]\n")
        return None


def scan_devices(interface, router_ip, existing_devices=None, status_msg="Scanning network for active devices..."):
    """Scan all active devices on the local network using arp-scan, merging with existing devices if provided."""
    with console.status(status_msg, spinner="dots"):
        fresh_devices = passive_arp_scan(interface, router_ip)
        devices = merge_devices(existing_devices, fresh_devices)
        
    if not devices:
        console.print(" [warning]No devices automatically detected via ARP scan.[/warning]")
        choice = qselect(
            "What would you like to do?",
            choices=[
                questionary.Choice("Add target/safe device manually (IP/MAC)", value="manual"),
                questionary.Choice("Rescan network", value="rescan"),
                questionary.Choice("Exit", value="exit"),
            ]
        )
        if choice == "manual":
            devices = []
            while True:
                dev = prompt_manual_device(interface)
                if dev:
                    devices.append(dev)
                if not devices:
                    sys.exit(0)
                try:
                    more = questionary.confirm("Add another device?", default=False).ask()
                    if not more:
                        break
                except KeyboardInterrupt:
                    break
            return devices
        elif choice == "rescan":
            return scan_devices(interface, router_ip, existing_devices=None, status_msg=status_msg)
        else:
            sys.exit(0)
    else:
        if existing_devices:
            added = len(devices) - len(existing_devices)
            if added > 0:
                console.print(f" [success]Found {len(fresh_devices)} active devices ({added} new device(s) added, {len(devices)} total)[/success]")
            else:
                console.print(f" [success]Found {len(fresh_devices)} active devices ({len(devices)} total retained)[/success]")
        else:
            console.print(f" [success]Found {len(devices)} devices detected on network[/success]")
        
        return devices


def display_devices(config, matched_devices, devices, last_ips=None):
    mode_str = config.get("operational_mode", "Blacklist") if config else "Blacklist"
    limit = config.get("limit_mbps", 1.0) if config else 1.0
    
    if matched_devices and config:
        if len(matched_devices) == len(devices):
            console.print(f" [success]Last session: all devices {mode_str} {limit} Mbps[/success]")
        else:
            console.print(f" [success]Last session: {len(matched_devices)} devices {mode_str} {limit} Mbps[/success]")
            
        for dev in matched_devices:
            vendor = dev.get("vendor", "Unknown")
            if not vendor or "locally administered" in vendor.lower():
                vendor = "Unknown"
            
            if len(vendor) > 25:
                vendor = vendor[:25]
            
    table = Table(box=box.SIMPLE, title_style="bold", show_header=True)
    table.add_column("IP Address",  style="")
    table.add_column("MAC Address", style="")
    table.add_column("Device",      style="")

    last_ips = last_ips or []
    
    for dev in devices:
        dev_ip = dev.get("ip") if dev.get("ip") and dev.get("ip") != "Unknown" else "-"
        is_last = dev_ip in last_ips
        
        vendor = dev.get("vendor", "Unknown")
        hostname = dev.get("hostname", "")
        if not vendor or "locally administered" in vendor.lower():
            vendor = "Unknown"
        
        if hostname:
            device_str = f"{hostname} ({vendor})" if vendor != "Unknown" else hostname
        else:
            device_str = vendor

        if len(device_str) > 32:
            device_str = device_str[:32] + "…"
        
        ip_cell     = f"[success]{dev_ip}[/success]" if is_last else dev_ip
        mac_cell    = f"[success]{dev.get('mac', 'Unknown')}[/success]" if is_last else dev.get('mac', 'Unknown')
        vendor_cell = f"[success]{device_str}[/success]" if is_last else device_str
    
        table.add_row(ip_cell, mac_cell, vendor_cell)
      
    console.print(table)


def pick_limit(prompt_fn=None):
    """Prompt user to select a bandwidth limit."""
    
    choice = qselect(
        "Select bandwidth limit:",
        choices=[
            questionary.Choice("1 Mbps — Heavy buffering, no HD YouTube",  value="1"),
            questionary.Choice("2 Mbps — Stuck at 480p",                   value="2"),
            questionary.Choice("3 Mbps — Occasional buffering at 720p",    value="3"),
            questionary.Choice("0.5 Mbps — FUCKEM ALL",                    value="x"),
            questionary.Choice("Custom",                                    value="4")
            ]
        )
    
    if choice is None:
        console.print(" [error]Cancelled by user.[/error]")
        sys.exit(0)
        
    presets = {"1": 1.0, "2": 2.0, "3": 3.0, "x": 0.5}
    
    if choice in presets:
        limit_value = presets[choice]
        return limit_value
        
    if choice == "4":
        while True:
            try:
                console.print()
                console.print(
                "[dim]"
                "  • Enter bandwidth limit in Mbps\n"
                "  • Use decimals (.) for values below 1 Mbps (e.g. 0.1, 0.10)\n"
                "  • Recommended range: 0.5 - 20 Mbps\n"
                "[/dim]"
                )

                val = float(input("  Enter limit in Mbps: ").strip())

                if val <= 0:
                    console.print("  [error]Limit must be greater than 0.0 Mbps.[/error]")
                    continue
                
                return val

            except ValueError:
                console.print("  [error]Invalid input. Please enter a valid decimal number.[/error]")
            except KeyboardInterrupt:
                console.print(" [error]Cancelled by user.[/error]")
                sys.exit(0)