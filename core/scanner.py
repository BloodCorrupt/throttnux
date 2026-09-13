import re
import sys
import subprocess
import logging
import questionary
import ipaddress

from .console import (
    console,
    Table,
    box,
    qselect
    )

log = logging.getLogger("throttnux")


def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def passive_arp_scan(interface, router_ip):
    """
    Lightweight silent ARP scan for background polling.
    Does not write to console or exit if no devices are found.
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
                "ip":     ip,
                "mac":    mac.lower(),
                "vendor": vendor_name
            })
    
    devices.sort(key=lambda dev: ipaddress.ip_address(dev["ip"]))
    return devices


def merge_devices(existing_devices, new_devices):
    """
    Merge existing scanned devices with newly scanned devices.
    Retains all previously discovered devices so none are lost on rescan.
    Updates IP and Vendor if changed for a known MAC.
    """
    if not existing_devices:
        return list(new_devices)

    merged = {d["mac"].lower(): dict(d) for d in existing_devices if d.get("mac")}
    by_ip = {d["ip"]: dict(d) for d in existing_devices if not d.get("mac")}

    for dev in new_devices:
        mac = dev.get("mac", "").lower()
        ip = dev.get("ip")
        if mac:
            if mac in merged:
                merged[mac]["ip"] = ip
                if dev.get("vendor") and dev["vendor"] != "Unknown":
                    merged[mac]["vendor"] = dev["vendor"]
            else:
                merged[mac] = dict(dev)
        elif ip:
            by_ip[ip] = dict(dev)

    result = list(merged.values()) + list(by_ip.values())
    result.sort(key=lambda dev: ipaddress.ip_address(dev["ip"]))
    return result


def scan_devices(interface, router_ip, existing_devices=None, status_msg="Scanning network for active devices..."):
    """Scan all active devices on the local network using arp-scan, merging with existing devices if provided."""
    with console.status(status_msg, spinner="dots"):
        fresh_devices = passive_arp_scan(interface, router_ip)
        devices = merge_devices(existing_devices, fresh_devices)
        
        if not devices:
            console.print(" [error]No devices found on the network.[/error]")
            sys.exit(1)
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
        is_last   = dev["ip"] in last_ips
        
        vendor = dev.get("vendor", "unknown")
        if not vendor or "locally administered" in vendor.lower():
            vendor = "Unknown"
        if len(vendor) > 25:
            vendor = vendor[:25]
        
        ip_cell     = f"[success]{dev['ip']}[/success]" if is_last else dev["ip"]
        mac_cell    = f"[success]{dev['mac']}[/success]" if is_last else dev["mac"]
        vendor_cell = f"[success]{vendor}[/success]" if is_last else vendor
    
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
            questionary.Choice("Custom",                                    value="4")
            ]
        )
    
    if choice is None:
        console.print(" [error]Cancelled by user.[/error]")
        sys.exit(0)
        
    presets = {"1": 1.0, "2": 2.0, "3": 3.0}
    
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