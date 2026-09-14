import json
import os
import logging
import sys
import re
import ipaddress
import questionary


from .console import (custom_style,
                      console,
                      Panel,
                      Group,
                      Table,
                      box,
                      qselect)
from .scanner import prompt_manual_device

log = logging.getLogger("throttnux")

CONFIG_DIR  = os.path.expanduser("~/.config/throttnux")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")


def save_config(interface, router_ip, mode, targets, limit_mbps, whitelisted=None):
    """Save last session config to ~/.config/throttnux/config.json."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    
    config = {
        "interface":        interface,
        "router_ip":        router_ip,
        "operational_mode": mode,
        "targets":          targets,
        "limit_mbps":       limit_mbps,
    }
    if whitelisted is not None:
        config["whitelisted"] = whitelisted
    
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)  
    except Exception as e:
        log.warning(f"Failed to save config: {e}")


def load_config():
    """Load config from ~/.config/throttnux/config.json if it exists."""
    if not os.path.exists(CONFIG_FILE):
        return None
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        log.warning(f"Failed to load config: {e}")
        return None


def clear_saved_config():
    """Delete ~/.config/throttnux/config.json if it exists."""
    if os.path.exists(CONFIG_FILE):
        try:
            os.remove(CONFIG_FILE)
            return True
        except Exception as e:
            log.warning(f"Failed to clear config file: {e}")
            return False
    return True


def match_saved_config(config, devices):
    """
    Check if saved config target IP is present in current network scan.
    Returns the matched device dict or None.
    """
    if not config:
        return None
    
    saved_targets = config.get("targets", [])
    if not saved_targets and "target_ip" in config:
        saved_targets = [{
            "ip": config.get("target_ip"),
            "mac": config.get("target_mac", ""),
            "vendor": config.get("target_vendor", "")
        }]
    
    matched = []
    for saved in saved_targets:
        saved_mac = saved.get("mac", "").lower() if isinstance(saved, dict) else ""
        saved_ip = saved.get("ip") if isinstance(saved, dict) else saved
        
        for d in devices:
            if saved_mac and d["mac"].lower() == saved_mac:
                matched.append(d)
                break
            elif not saved_mac and d["ip"] == saved_ip:
                matched.append(d)
                break
                
    return matched if matched else None


def match_saved_whitelist(config, devices):
    """
    Check if saved whitelisted devices are present in current network scan.
    Returns the matched whitelisted device dicts or None.
    """
    if not config or not config.get("whitelisted"):
        return None
    
    saved_whitelisted = config.get("whitelisted", [])
    matched = []
    for saved in saved_whitelisted:
        saved_mac = saved.get("mac", "").lower() if isinstance(saved, dict) else ""
        saved_ip = saved.get("ip") if isinstance(saved, dict) else saved
        
        for d in devices:
            if saved_mac and d.get("mac", "").lower() == saved_mac:
                matched.append(d)
                break
            elif not saved_mac and d.get("ip") == saved_ip:
                matched.append(d)
                break
                
    return matched if matched else None
    
    
RULES_FILE  = os.path.join(CONFIG_DIR, "rules.json")


def load_predefined_rules():
    """
    Load predefined whitelist and blacklist rules from ~/.config/throttnux/rules.json.
    Returns:
        dict: {"whitelist": {mac_lower: name}, "blacklist": {mac_lower: name}}
    """
    if not os.path.exists(RULES_FILE):
        return {"whitelist": {}, "blacklist": {}}
    
    try:
        with open(RULES_FILE, "r") as f:
            data = json.load(f)
            
        rules = {"whitelist": {}, "blacklist": {}}
        for category in ("whitelist", "blacklist"):
            items = data.get(category, [])
            for item in items:
                if isinstance(item, dict):
                    mac = item.get("mac", "").lower().strip()
                    name = item.get("name", "").strip()
                    if mac:
                        rules[category][mac] = name
                elif isinstance(item, str):
                    mac = item.lower().strip()
                    if mac:
                        rules[category][mac] = ""
        return rules
    except Exception as e:
        log.warning(f"Failed to load predefined rules: {e}")
        return {"whitelist": {}, "blacklist": {}}


def save_predefined_rules(rules):
    """
    Save predefined rules to ~/.config/throttnux/rules.json.
    rules: dict {"whitelist": {mac: name}, "blacklist": {mac: name}}
    """
    os.makedirs(CONFIG_DIR, exist_ok=True)
    
    formatted_data = {
        "whitelist": [
            {"mac": mac, "name": name} if name else mac
            for mac, name in rules.get("whitelist", {}).items()
        ],
        "blacklist": [
            {"mac": mac, "name": name} if name else mac
            for mac, name in rules.get("blacklist", {}).items()
        ]
    }
    
    try:
        with open(RULES_FILE, "w") as f:
            json.dump(formatted_data, f, indent=4)
        return True
    except Exception as e:
        log.warning(f"Failed to save predefined rules: {e}")
        return False


def get_predefined_whitelist():
    """Return dict of {mac_lower: name} for predefined global whitelist."""
    return load_predefined_rules().get("whitelist", {})


def get_predefined_blacklist():
    """Return dict of {mac_lower: name} for predefined global blacklist."""
    return load_predefined_rules().get("blacklist", {})


def prompt_manage_rules(devices=None, interface=None):
    """
    Interactive menu to view, add, and remove global whitelist/blacklist rules.
    """
    devices = devices if devices is not None else []
    
    while True:
        rules = load_predefined_rules()
        wl = rules.get("whitelist", {})
        bl = rules.get("blacklist", {})

        action = qselect(
            "Global Rules Management (by MAC address):",
            choices=[
                questionary.Choice(f"View current global rules ({len(wl)} whitelisted, {len(bl)} blacklisted)", value="view"),
                questionary.Choice("Add to global Whitelist (from scan or manual IP/MAC)", value="add_scan_wl"),
                questionary.Choice("Add to global Blacklist (from scan or manual IP/MAC)", value="add_scan_bl"),
                questionary.Choice("Remove a rule", value="remove"),
                questionary.Choice("Back to main menu", value="back"),
            ]
        )

        if action is None or action == "back":
            break

        if action == "view":
            console.print()
            table = Table(box=box.SIMPLE, title="[bold white]Global Pre-Defined Rules[/bold white]", show_header=True)
            table.add_column("Type", style="bold")
            table.add_column("MAC Address", style="")
            table.add_column("Label / Device Name", style="")

            if not wl and not bl:
                table.add_row("[dim]Empty[/dim]", "[dim]No predefined rules configured[/dim]", "[dim]-[/dim]")
            else:
                for mac, name in wl.items():
                    table.add_row("[green]WHITELIST[/green]", mac, name or "[dim]No label[/dim]")
                for mac, name in bl.items():
                    table.add_row("[red]BLACKLIST[/red]", mac, name or "[dim]No label[/dim]")

            console.print(table)
            console.print(f" [dim]Rules config file: {RULES_FILE}[/dim]\n")
            input("  Press Enter to continue...")

        elif action in ("add_scan_wl", "add_scan_bl"):
            is_wl = action == "add_scan_wl"
            target_list_name = "whitelist" if is_wl else "blacklist"

            max_ip_len = max((len(dev['ip']) for dev in devices), default=15)
            choices = []
            choices.append(questionary.Choice(title="+ [Add device manually by IP or MAC]", value="__manual__"))
            
            for dev in devices:
                mac = dev.get("mac", "").lower()
                already_in = mac in rules[target_list_name]
                display_line = f"{dev['ip']:<{max_ip_len}}  {mac:<17}  {dev['vendor']}"
                choices.append(questionary.Choice(title=display_line, value=dev, checked=already_in))

            selected = questionary.checkbox(
                f"Select devices to add to global {target_list_name}:",
                qmark="",
                instruction="(Space to select, Enter to confirm)",
                choices=choices,
                style=custom_style
            ).ask(kbi_msg="")

            if selected:
                if "__manual__" in selected:
                    manual_dev = prompt_manual_device(interface)
                    if manual_dev:
                        mac = manual_dev.get("mac", "").lower()
                        key = mac if mac != "unknown" and mac else manual_dev["ip"]
                        rules[target_list_name][key] = manual_dev.get("vendor", "")
                        if not any(d.get("ip") == manual_dev["ip"] for d in devices):
                            devices.append(manual_dev)
                            devices.sort(key=lambda dev: ipaddress.ip_address(dev["ip"]))

                for dev in selected:
                    if dev == "__manual__":
                        continue
                    mac = dev.get("mac", "").lower()
                    if mac:
                        vendor = dev.get("vendor", "")
                        if vendor and "locally administered" not in vendor.lower() and vendor != "Unknown":
                            name = rules[target_list_name].get(mac) or vendor
                        else:
                            name = rules[target_list_name].get(mac) or ""
                        rules[target_list_name][mac] = name
                save_predefined_rules(rules)
                count = len([d for d in selected if d != "__manual__"]) + (1 if "__manual__" in selected else 0)
                console.print(f" [success]Updated global {target_list_name} ({count} device(s)).[/success]\n")

        elif action == "remove":
            remove_choices = []
            for mac, name in wl.items():
                label = f"[WL] {mac} ({name})" if name else f"[WL] {mac}"
                remove_choices.append(questionary.Choice(title=label, value=("whitelist", mac)))
            for mac, name in bl.items():
                label = f"[BL] {mac} ({name})" if name else f"[BL] {mac}"
                remove_choices.append(questionary.Choice(title=label, value=("blacklist", mac)))

            if not remove_choices:
                console.print(" [info]No rules to remove.[/info]")
                continue

            remove_choices.append(questionary.Choice("Cancel", value=None))
            to_remove = qselect("Select rule to remove:", choices=remove_choices)
            if to_remove:
                cat, mac = to_remove
                if mac in rules[cat]:
                    del rules[cat][mac]
                    save_predefined_rules(rules)
                    console.print(f" [success]Removed {mac} from global {cat}.[/success]\n")


def ask_user_action(has_saved=True):
    choices = []
    if has_saved:
        choices.append(questionary.Choice("Resume last session", value="use_saved"))
    choices.append(questionary.Choice("Start new session", value="new_scan"))
    choices.append(questionary.Choice("Rescan network", value="rescan"))
    choices.append(questionary.Choice("Add device manually (IP/MAC)", value="add_device"))
    choices.append(questionary.Choice("Manage global rules (whitelist/blacklist)", value="manage_rules"))
    choices.append(questionary.Choice("Clear saved session & cache", value="clear_cache"))
    choices.append(questionary.Choice("Exit", value="exit"))

    answer = qselect(
        "What do you want to do?",
        choices=choices,
    )
 
    if answer is None:
        console.print(" [error]Cancelled by user.[/error]")
        sys.exit(0)

    if answer == "exit":
        sys.exit(0)
 
    return answer


def prompt_operational_mode():
    """Ask user to select operational mode when starting a new session."""
    try:
        answer = qselect(
            "Select mode:",
            [
                questionary.Choice("Blacklist - throttle selected devices", value="blacklist"),
                questionary.Choice("Whitelist - throttle all except selected", value="whitelist")
            ],
            )

        if answer is None:
            console.print(" [error]Cancelled by user.[/error]")
            sys.exit(0)
        
        return answer

    except KeyboardInterrupt:
        console.print(" [error]Cancelled by user.[/error]")
        sys.exit(0)


def prompt_blacklist_selection(devices, default_targets=None, interface=None):
    if default_targets is None:
        default_targets = []
        
    default_macs = [t.get("mac", "").lower() for t in default_targets if isinstance(t, dict) and t.get("mac")]
    default_ips = [t.get("ip") if isinstance(t, dict) else t for t in default_targets]
    
    predefined_bl = get_predefined_blacklist()
    
    choices = []
    initial_focus = None
    max_ip_len = max((len(dev['ip']) for dev in devices), default=15)
    
    choices.append(questionary.Choice(title="+ [Add device manually by IP/MAC]", value="__manual__"))

    for dev in devices:
        mac = dev.get("mac", "Unknown")
        mac_lower = mac.lower()
        vendor = dev.get("vendor", "")
        
        is_predefined = mac_lower in predefined_bl or dev["ip"] in predefined_bl
        rule_name = predefined_bl.get(mac_lower, "") or predefined_bl.get(dev["ip"], "")
        
        if is_predefined and rule_name:
            display_line = f"{dev['ip']:<{max_ip_len}}  {mac:<17}  {vendor} ({rule_name})"
        elif is_predefined:
            display_line = f"{dev['ip']:<{max_ip_len}}  {mac:<17}  {vendor} [Global Blacklist]"
        else:
            display_line = f"{dev['ip']:<{max_ip_len}}  {mac:<17}  {vendor}"
        
        is_checked = (mac_lower in default_macs) or (dev["ip"] in default_ips) or is_predefined
        
        choice = questionary.Choice(title=display_line, value=dev, checked=is_checked)
        choices.append(choice)
        
        if is_checked and initial_focus is None:
            initial_focus = choice

    if initial_focus is None and choices:
        initial_focus = choices[0]
    
    try:
        answer = questionary.checkbox(
            "Select targets:",
            qmark="",
            instruction="(Space to select, Enter to confirm)",
            choices=choices,
            initial_choice=initial_focus,
            style=custom_style,
            pointer=">",
        ).ask(kbi_msg="")
        
        if answer is None:
            console.print(" [error]Cancelled by user.[/error]")
            sys.exit(0)

        selected_targets = [d for d in answer if d != "__manual__"]

        if "__manual__" in answer:
            while True:
                dev = prompt_manual_device(interface)
                if dev:
                    if not any(d.get("ip") == dev["ip"] for d in devices):
                        devices.append(dev)
                        devices.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
                    if not any(d.get("ip") == dev["ip"] for d in selected_targets):
                        selected_targets.append(dev)
                try:
                    more = questionary.confirm("Add another manual target?", default=False).ask()
                    if not more:
                        break
                except KeyboardInterrupt:
                    break
        
        if not selected_targets:
            console.print(" [error]Cancelled. No devices selected.[/error]")
            sys.exit(0)
        
        return selected_targets
    
    except KeyboardInterrupt:
        console.print(" [error]Cancelled by user.[/error]")
        sys.exit(0)


def prompt_whitelist_selection(devices, default_whitelisted=None, interface=None):
    if default_whitelisted is None:
        default_whitelisted = []
        
    default_macs = {t.get("mac", "").lower() for t in default_whitelisted if isinstance(t, dict) and t.get("mac")}
    default_ips = {t.get("ip") if isinstance(t, dict) else t for t in default_whitelisted}
    
    predefined_wl = get_predefined_whitelist()
    
    choices = []
    initial_focus = None
    max_ip_len = max((len(dev['ip']) for dev in devices), default=15)
    
    choices.append(questionary.Choice(title="+ [Add device manually by IP/MAC]", value="__manual__"))

    for dev in devices:
        mac = dev.get("mac", "Unknown")
        mac_lower = mac.lower()
        vendor = dev.get("vendor", "")
        
        is_predefined = mac_lower in predefined_wl or dev["ip"] in predefined_wl
        rule_name = predefined_wl.get(mac_lower, "") or predefined_wl.get(dev["ip"], "")
        
        if is_predefined and rule_name:
            display_line = f"{dev['ip']:<{max_ip_len}}  {mac:<17}  {vendor} ({rule_name})"
        elif is_predefined:
            display_line = f"{dev['ip']:<{max_ip_len}}  {mac:<17}  {vendor} [Global Whitelist]"
        else:
            display_line = f"{dev['ip']:<{max_ip_len}}  {mac:<17}  {vendor}"

        is_checked = (mac_lower in default_macs) or (dev["ip"] in default_ips) or is_predefined
                
        choice = questionary.Choice(title=display_line, value=dev, checked=is_checked)
        choices.append(choice)
        
        if is_checked and initial_focus is None:
            initial_focus = choice

    if initial_focus is None and choices:
        initial_focus = choices[0]
    
    try:
        answer = questionary.checkbox(
            "Select whitelisted (safe) devices:",
            qmark="",
            instruction="(Space to select, Enter to confirm)",
            choices=choices,
            initial_choice=initial_focus,
            style=custom_style
        ).ask(kbi_msg="")

        if answer is None:
            console.print(" [error]Cancelled by user.[/error]")
            sys.exit(0)

        selected_safe = [d for d in answer if d != "__manual__"]

        if "__manual__" in answer:
            while True:
                dev = prompt_manual_device(interface)
                if dev:
                    if not any(d.get("ip") == dev["ip"] for d in devices):
                        devices.append(dev)
                        devices.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
                    if not any(d.get("ip") == dev["ip"] for d in selected_safe):
                        selected_safe.append(dev)
                try:
                    more = questionary.confirm("Add another manual whitelisted device?", default=False).ask()
                    if not more:
                        break
                except KeyboardInterrupt:
                    break

        if not selected_safe:
            console.print(" [error]Cancelled. No devices selected.[/error]")
            sys.exit(0)
        
        return selected_safe
    
    except KeyboardInterrupt:
        console.print(" [error]Cancelled by user.[/error]")
        sys.exit(0)


def prompt_session_review(interface, router_ip, mode, limit_mbps, targets):
    console.print()
    
    mode_str = mode.capitalize() if mode else "Blacklist"
    
    summary_text = (
        f"Operational Mode : {mode_str}\n"
        f"Interface        : {interface}\n"
        f"Router IP        : {router_ip}\n"
        f"Bandwidth Limit  : {limit_mbps} Mbps\n\n"
        f"Targets ({len(targets)}):"
    )
    
    max_ip_len = max([len(tgt["ip"]) for tgt in targets]) if targets else 15
    
    target_lines = []
    if targets:
        for tgt in targets:
            vendor = tgt.get("vendor", "Unknown Vendor")
            
            if not vendor or "locally administered" in vendor.lower():
                vendor = "Unknown"
        
            if len(vendor) > 25:
                vendor = vendor[:25]
                
            mac = tgt.get("mac", "Unknown")
            
            target_lines.append(f"[white]{tgt['ip']:<{max_ip_len}}  {mac:<17}  {vendor}[/white]")
    else:
        target_lines.append("[dim white]None (all current devices safe — new devices will be dynamically auto-throttled)[/dim white]")
    
    content_group = Group(
        summary_text,
        *target_lines
    )
    
    console.print(
        Panel(
            content_group,
            title="[bold white]Configuration Review[/bold white]",
            title_align="center",
            expand=False,
            box=box.HORIZONTALS
        )
    )

    try:
        confirm = questionary.confirm(
            "Do you want to start the throttling session?",
            default=True,
            style=custom_style,
            qmark=""
        ).ask(kbi_msg="")
        
        if not confirm:
            console.print(" [error]Cancelled by user.[/error]")
            sys.exit(0)

        return confirm

    except KeyboardInterrupt:
        console.print(" [error]Cancelled by user.[/error]")
        sys.exit(0)