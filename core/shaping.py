import subprocess
import logging

log = logging.getLogger("throttnux")

# System kernel parameter to control IPv4 packet forwarding
SYSCTL_IP_FORWARD_PATH = "/proc/sys/net/ipv4/ip_forward"


def run(cmd, check=True):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        log.error(f"Command failed: {cmd}\n{result.stderr.strip()}")
    return result


def enable_ip_forward():
    run(f"echo 1 > {SYSCTL_IP_FORWARD_PATH}")


def disable_ip_forward():
    run(f"echo 0 > {SYSCTL_IP_FORWARD_PATH}")


def ensure_traffic_shaping_root(interface):
    """
    Ensure the root HTB qdisc (handle 1:) and default parent class (1:1 & 1:99) exist on the interface.
    """
    chk = run(f"tc qdisc show dev {interface}", check=False)
    if "qdisc htb 1:" not in chk.stdout:
        run(f"tc qdisc del dev {interface} root", check=False)
        run(f"tc qdisc add dev {interface} root handle 1: htb default 99", check=False)
        run(f"tc class replace dev {interface} parent 1: classid 1:1 htb rate 1000mbit", check=False)
        run(f"tc class replace dev {interface} parent 1:1 classid 1:99 htb rate 1000mbit", check=False)


def setup_traffic_shaping(interface, targets, limit_mbps):
    """
    Setup tc HTB hierarchy for one or multiple targets.
    targets: list of dicts with "ip" key, or list of IP strings.
    Each target gets its own class ID: 1:10, 1:11, 1:12, ...
    """
    if isinstance(targets, str):
        targets = [{"ip": targets}]

    # 1. Reset and establish root qdisc & parent classes
    run(f"tc qdisc del dev {interface} root", check=False)
    run(f"tc qdisc add dev {interface} root handle 1: htb default 99", check=True)
    run(f"tc class add dev {interface} parent 1: classid 1:1 htb rate 1000mbit", check=True)
    run(f"tc class add dev {interface} parent 1:1 classid 1:99 htb rate 1000mbit", check=True)

    limit_kbit = int(limit_mbps * 1000)
    burst_kb = max(int(limit_kbit / 8), 15)

    # 2. Add classes and filters for each target
    for i, tgt in enumerate(targets):
        ip = tgt.get("ip") if isinstance(tgt, dict) else tgt
        if not ip or ip == "-":
            continue

        class_id = 10 + i
        prio_base = (class_id - 10) * 2 + 1
        run(f"tc class replace dev {interface} parent 1:1 classid 1:{class_id} htb rate {limit_kbit}kbit ceil {limit_kbit}kbit burst {burst_kb}k", check=True)
        run(f"tc filter replace dev {interface} parent 1: protocol ip prio {prio_base} u32 match ip dst {ip}/32 flowid 1:{class_id}", check=True)
        run(f"tc filter replace dev {interface} parent 1: protocol ip prio {prio_base+1} u32 match ip src {ip}/32 flowid 1:{class_id}", check=True)


def add_target_shaping(interface, ip, class_id, limit_mbps):
    """
    Hotplug a single new target into an existing HTB qdisc without resetting existing rules.
    """
    if not ip or ip == "-":
        return

    # Ensure root qdisc and parent class 1:1 exist
    ensure_traffic_shaping_root(interface)

    limit_kbit = int(limit_mbps * 1000)
    burst_kb = max(int(limit_kbit / 8), 15)
    prio_base = (class_id - 10) * 2 + 1

    run(f"tc class replace dev {interface} parent 1:1 classid 1:{class_id} htb rate {limit_kbit}kbit ceil {limit_kbit}kbit burst {burst_kb}k", check=True)
    run(f"tc filter replace dev {interface} parent 1: protocol ip prio {prio_base} u32 match ip dst {ip}/32 flowid 1:{class_id}", check=True)
    run(f"tc filter replace dev {interface} parent 1: protocol ip prio {prio_base+1} u32 match ip src {ip}/32 flowid 1:{class_id}", check=True)


def cleanup_traffic_shaping(interface):
    """Clean up tc qdisc rules from interface."""
    run(f"tc qdisc del dev {interface} root", check=False)