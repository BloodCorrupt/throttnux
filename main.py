#!/usr/bin/env python3

import sys
import signal
import logging
import threading
import time
import ipaddress

from core.console import console
from pyfiglet import figlet_format

from core import (
    check_os,
    check_root,
    check_dependencies,
    pick_interface,
    pick_router,
    scan_devices,
    display_devices,
    pick_limit,
    enable_ip_forward,
    disable_ip_forward,
    setup_traffic_shaping,
    cleanup_traffic_shaping,
    add_target_shaping,
    arp_spoof_loop,
    verify_spoofing,
    live_monitor,
    save_config,
    load_config,
    clear_saved_config,
    ask_user_action,
    prompt_operational_mode,
    prompt_blacklist_selection,
    prompt_whitelist_selection,
    prompt_session_review,
    match_saved_config,
    match_saved_whitelist,
    prompt_manage_rules,
    prompt_manual_device,
    device_sort_key,
    get_predefined_whitelist,
    get_predefined_blacklist
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("throttnux")

stop_event = threading.Event()


def prompt(text, valid_range=None):
    """Generic prompt with optional range validation."""
    while True:
        try:
            choice = input(text).strip()
            if valid_range is not None:
                idx = int(choice) - 1
                if 0 <= idx < valid_range:
                    return idx
                print(f"  [!] Enter a number between 1 and {valid_range}")
            else:
                return choice
        except ValueError:
            print("  [!] Invalid input.")
        except KeyboardInterrupt:
            print("\n  Cancelled.")
            sys.exit(0)


def banner():
    print()    
    print(figlet_format("Throttnux", font="standard").rstrip())
    console.print("  [dim]Per-device bandwidth limiter via ARP spoofing[/dim]")
    print()    


def signal_handler(sig, frame):
    stop_event.set()


def main():
    check_os()
    check_root()
    check_dependencies()

    banner()

    interface  = None
    router_ip  = None
    limit_mbps = None
    used_saved = False
    targets_to_throttle = []
    safe_devices = []
    safe_ips = set()
    safe_macs = set()
    
    interface = pick_interface()
    router_ip = pick_router(interface)

    config  = load_config()
    devices = scan_devices(interface, router_ip)

    # 1. Validate targets with live network data before rendering
    has_saved = bool(config and config.get("interface") == interface and config.get("router_ip") == router_ip)
    saved_mode = config.get("operational_mode", "blacklist") if has_saved else None

    if has_saved and saved_mode == "whitelist":
        matched_whitelisted = match_saved_whitelist(config, devices)
        matched_dev = match_saved_config(config, devices)
        last_ips = [d["ip"] for d in (matched_whitelisted or [])]
    elif has_saved:
        matched_whitelisted = None
        matched_dev = match_saved_config(config, devices)
        last_ips = [d["ip"] for d in (matched_dev or [])]
    else:
        matched_whitelisted = None
        matched_dev = None
        last_ips = []
        console.print(" [dim]No previous session found on this network.[/dim]\n")
    
    # 2. Display devices UI with table 
    display_devices(config if has_saved else None, matched_whitelisted if saved_mode == "whitelist" else matched_dev, devices, last_ips=last_ips)
    
    while True:
        action = ask_user_action(has_saved=has_saved)

        if action == "add_device":
            dev = prompt_manual_device(interface)
            if dev:
                mac = dev.get("mac", "").lower()
                existing_idx = None
                for idx, d in enumerate(devices):
                    d_mac = d.get("mac", "").lower()
                    if (mac and mac != "unknown" and d_mac == mac) or (dev.get("ip") and dev["ip"] != "-" and d.get("ip") == dev["ip"]):
                        existing_idx = idx
                        break
                if existing_idx is not None:
                    devices[existing_idx] = dev
                else:
                    devices.append(dev)
                devices.sort(key=device_sort_key)
            console.clear()
            console.print()
            display_devices(config if has_saved else None, matched_whitelisted if saved_mode == "whitelist" else matched_dev, devices, last_ips=last_ips)
            continue
        elif action == "manage_rules":
            prompt_manage_rules(devices, interface=interface)
            console.clear()
            console.print()
            display_devices(config if has_saved else None, matched_whitelisted if saved_mode == "whitelist" else matched_dev, devices, last_ips=last_ips)
            continue
        elif action == "clear_cache":
            clear_saved_config()
            config = None
            has_saved = False
            matched_dev = None
            matched_whitelisted = None
            last_ips = []
            console.clear()
            console.print(" [success]Saved session and device cache cleared.[/success]\n")
            devices = scan_devices(interface, router_ip, existing_devices=None, status_msg="Scanning network for active devices...")
            display_devices(None, None, devices, last_ips=[])
            continue
        elif action == "rescan":
            console.clear()
            console.print()
            
            devices = scan_devices(interface, router_ip, existing_devices=devices, status_msg="Rescanning network, please wait...")
            
            # Re-validate dynamically on rescan
            if has_saved:
                if saved_mode == "whitelist":
                    matched_whitelisted = match_saved_whitelist(config, devices)
                    matched_dev = match_saved_config(config, devices)
                    last_ips_rescan = [d["ip"] for d in (matched_whitelisted or [])]
                else:
                    matched_whitelisted = None
                    matched_dev = match_saved_config(config, devices)
                    last_ips_rescan = [d["ip"] for d in (matched_dev or [])]
            else:
                matched_dev = None
                matched_whitelisted = None
                last_ips_rescan = []
                
            display_devices(config if has_saved else None, matched_whitelisted if saved_mode == "whitelist" else matched_dev, devices, last_ips=last_ips_rescan)
            continue
        else:
            break
    
    if action == "use_saved":
        limit_mbps = config["limit_mbps"]
        operational_mode = config.get("operational_mode", "blacklist")
        if operational_mode == "whitelist":
            saved_whitelisted = config.get("whitelisted", [])
            safe_devices = match_saved_whitelist(config, devices) or [
                d for d in saved_whitelisted if isinstance(d, dict)
            ]
            safe_macs = {d["mac"].lower() for d in safe_devices if isinstance(d, dict) and d.get("mac")}
            safe_ips = {d["ip"] if isinstance(d, dict) else d for d in safe_devices}
            
            targets_to_throttle = [
                d for d in devices
                if not ((d.get("mac") and d["mac"].lower() in safe_macs) or d.get("ip") in safe_ips)
            ]
        else:
            targets_to_throttle = matched_dev or []
        used_saved = True
    elif action == "new_scan":
        operational_mode = prompt_operational_mode()


    if not used_saved:
        if operational_mode == "blacklist" or operational_mode is None:
            targets_to_throttle = prompt_blacklist_selection(devices, matched_dev, interface=interface)

        elif operational_mode == "whitelist":
            safe_devices = prompt_whitelist_selection(devices, matched_whitelisted, interface=interface)
            safe_macs = {d["mac"].lower() for d in safe_devices if isinstance(d, dict) and d.get("mac")}
            safe_ips = {d["ip"] if isinstance(d, dict) else d for d in safe_devices}
            
            targets_to_throttle = [
                d for d in devices
                if not ((d.get("mac") and d["mac"].lower() in safe_macs) or d.get("ip") in safe_ips)
            ]

            if not targets_to_throttle:
                console.print(" [info]All current devices whitelisted. Dynamic scanner will throttle any new device that connects.[/info]")
                
        limit_mbps = pick_limit(prompt)
        
    if not used_saved:
        prompt_session_review(interface, router_ip, operational_mode, limit_mbps, targets_to_throttle)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    spoof_threads = []
    success = False

    def on_new_device(dev):
        """Callback triggered by monitor's dynamic ARP scanner in whitelist mode."""
        dev_mac = dev.get("mac", "").lower()
        dev_ip = dev.get("ip")
        predefined_wl_macs = set(get_predefined_whitelist().keys())
        if operational_mode == "whitelist":
            if (dev_mac and (dev_mac in safe_macs or dev_mac in predefined_wl_macs)) or (dev_ip and dev_ip in safe_ips):
                log.info(f"Refusing to throttle whitelisted device: {dev_ip} ({dev_mac})")
                return None

        class_id = 10 + len(targets_to_throttle)
        add_target_shaping(interface, dev["ip"], class_id, limit_mbps)
        t = threading.Thread(
            target=arp_spoof_loop,
            args=(interface, dev["ip"], router_ip, stop_event),
            daemon=True
        )
        t.start()
        spoof_threads.append(t)
        targets_to_throttle.append(dev)
        return class_id

    try:
        with console.status("Starting session...", spinner="dots"):
            save_config(
                interface,
                router_ip,
                operational_mode,
                targets_to_throttle,
                limit_mbps,
                whitelisted=safe_devices if operational_mode == "whitelist" else None
            )
            
            enable_ip_forward()
            
            setup_traffic_shaping(interface, targets_to_throttle, limit_mbps)
            
            for tgt in targets_to_throttle:
                t = threading.Thread(
                    target=arp_spoof_loop,
                    args=(interface, tgt["ip"], router_ip, stop_event),
                    daemon=True
                )
                t.start()
                spoof_threads.append(t)
            
            if targets_to_throttle:
                success = verify_spoofing(interface, stop_event)
                if not success:
                    stop_event.set()
            else:
                success = True

        if success:
            if targets_to_throttle:
                console.print(" [success]Session started. Launching live monitor...[/success]")
            else:
                console.print(" [success]Session started in whitelist mode. Waiting for new devices...[/success]")
            time.sleep(1.5)
            monitor_thread = threading.Thread(
                target=live_monitor,
                args=(interface, targets_to_throttle, limit_mbps, stop_event),
                kwargs={
                    "router_ip": router_ip,
                    "whitelist_devices": safe_devices if operational_mode == "whitelist" else None,
                    "on_new_device": on_new_device if operational_mode == "whitelist" else None,
                },
                daemon=True
            )
            monitor_thread.start()
        else:
            console.print(" [error]Target device does not appear to be using the network. Stopping...[/error]")

        try:
            while not stop_event.is_set():
                stop_event.wait(0.1)
        except KeyboardInterrupt:
            stop_event.set()

        if success and 'monitor_thread' in locals():
            monitor_thread.join(timeout=2)

    finally:
        with console.status("Stopping session...", spinner="dots"):
            for t in spoof_threads:
                t.join(timeout=5)

            cleanup_traffic_shaping(interface)

            disable_ip_forward()

        console.print("\n [error]Session terminated.[/error]")
        console.print(" [success]Network restored and traffic shaping rules cleared.[/success]")


if __name__ == "__main__":
    main()