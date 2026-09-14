import threading
import time
import re
import logging
import subprocess

from .network import get_interfaces, get_default_gateway
from .scanner import passive_arp_scan, merge_devices, resolve_mac, device_sort_key
from .shaping import (
    enable_ip_forward,
    disable_ip_forward,
    setup_traffic_shaping,
    cleanup_traffic_shaping,
    add_target_shaping
)
from .spoof import arp_spoof_loop
from .config import (
    load_config,
    save_config,
    get_predefined_whitelist,
    get_predefined_blacklist,
    load_predefined_rules,
    save_predefined_rules
)

log = logging.getLogger("throttnux")


def run_cmd(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


class ThrottnuxEngine:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(ThrottnuxEngine, cls).__new__(cls)
                cls._instance._init_engine()
            return cls._instance

    def _init_engine(self):
        self.lock = threading.Lock()
        self.status = "IDLE"  # "IDLE", "SCANNING", "RUNNING", "STOPPING"
        self.devices = []
        self.current_interface = None
        self.current_router_ip = None
        self.operational_mode = "blacklist"  # "blacklist" or "whitelist"
        self.limit_mbps = 1.0
        
        self.targets = []
        self.whitelisted = []
        self.session_start_time = None
        
        self.stop_event = None
        self.spoof_threads = []
        self.monitor_thread = None
        self.watcher_thread = None
        
        self.device_telemetry = {}
        
        # Detect defaults
        self._detect_defaults()

    def _detect_defaults(self):
        interfaces = get_interfaces()
        if interfaces:
            self.current_interface = interfaces[0]
            gw = get_default_gateway(self.current_interface)
            self.current_router_ip = gw if gw else "192.168.1.1"

    def get_interfaces(self):
        return get_interfaces()

    def get_default_gateway(self, interface=None):
        iface = interface or self.current_interface
        return get_default_gateway(iface) if iface else None

    def scan(self, interface=None, router_ip=None):
        """Perform active network scan and merge results."""
        iface = interface or self.current_interface
        router = router_ip or self.current_router_ip
        if not iface or not router:
            return self.devices

        with self.lock:
            was_running = self.status == "RUNNING"
            if not was_running:
                self.status = "SCANNING"

        try:
            fresh = passive_arp_scan(iface, router)
            with self.lock:
                self.devices = merge_devices(self.devices, fresh)
                self.current_interface = iface
                self.current_router_ip = router
                return list(self.devices)
        finally:
            with self.lock:
                if not was_running:
                    self.status = "IDLE"

    def add_manual_device(self, ip=None, mac=None, vendor="Manual Entry"):
        """Add or update a device manually."""
        with self.lock:
            mac_clean = mac.replace("-", ":").strip().lower() if mac else ""
            ip_clean = ip.strip() if ip else "-"
            
            if ip_clean != "-" and not mac_clean:
                # Attempt to resolve MAC
                mac_clean = resolve_mac(ip_clean, self.current_interface) or "Unknown"
            elif not mac_clean:
                mac_clean = "Unknown"

            dev = {
                "ip": ip_clean,
                "mac": mac_clean,
                "vendor": vendor or "Manual Entry"
            }

            # Update existing or append
            existing_idx = None
            for idx, d in enumerate(self.devices):
                if (mac_clean != "Unknown" and d.get("mac", "").lower() == mac_clean) or (ip_clean != "-" and d.get("ip") == ip_clean):
                    existing_idx = idx
                    break

            if existing_idx is not None:
                self.devices[existing_idx] = dev
            else:
                self.devices.append(dev)

            self.devices.sort(key=device_sort_key)
            return dev

    def clear_cache(self):
        """Clear device cache and saved session."""
        with self.lock:
            if self.status == "RUNNING":
                return False, "Cannot clear cache while session is running."
            self.devices = []
            return True, "Device cache cleared."

    def start_session(self, interface, router_ip, mode, targets, limit_mbps, whitelisted=None):
        """Launch traffic shaping and ARP spoofing session."""
        with self.lock:
            if self.status == "RUNNING":
                return False, "A session is already running."

            self.status = "RUNNING"
            self.current_interface = interface
            self.current_router_ip = router_ip
            self.operational_mode = mode
            self.limit_mbps = float(limit_mbps)
            self.targets = list(targets)
            self.whitelisted = list(whitelisted) if whitelisted else []
            self.session_start_time = time.time()
            self.stop_event = threading.Event()
            self.spoof_threads = []
            self.device_telemetry = {}

        try:
            # 1. Enable IP forwarding
            enable_ip_forward()

            # 2. Setup traffic shaping
            setup_traffic_shaping(interface, self.targets, self.limit_mbps)

            # 3. Start ARP spoofers
            for tgt in self.targets:
                tgt_ip = tgt.get("ip") if isinstance(tgt, dict) else tgt
                if tgt_ip and tgt_ip != "-":
                    t = threading.Thread(
                        target=arp_spoof_loop,
                        args=(interface, tgt_ip, router_ip, self.stop_event),
                        daemon=True
                    )
                    t.start()
                    self.spoof_threads.append(t)

            # 4. Save session config
            save_config(interface, router_ip, mode, self.targets, self.limit_mbps, whitelisted=self.whitelisted)

            # 5. Initialize telemetry dictionary
            for i, tgt in enumerate(self.targets):
                ip = tgt.get("ip") if isinstance(tgt, dict) else tgt
                mac = tgt.get("mac", "Unknown") if isinstance(tgt, dict) else "Unknown"
                vendor = tgt.get("vendor", "Unknown") if isinstance(tgt, dict) else "Unknown"
                if ip and ip != "-":
                    self.device_telemetry[ip] = {
                        "class_id": 10 + i,
                        "mac": mac,
                        "vendor": vendor,
                        "speed_kbps": 0.0,
                        "total_bytes": 0,
                        "last_bytes": 0,
                        "last_time": time.time(),
                        "is_online": True,
                        "is_new": False,
                        "added_time": time.time(),
                    }

            # 6. Start background telemetry collector thread
            self.monitor_thread = threading.Thread(target=self._telemetry_worker, daemon=True)
            self.monitor_thread.start()

            # 7. Start dynamic whitelist watcher if in whitelist mode
            if mode == "whitelist":
                self.watcher_thread = threading.Thread(target=self._whitelist_watcher_worker, daemon=True)
                self.watcher_thread.start()

            return True, "Session started successfully."
        except Exception as e:
            log.error(f"Failed to start session: {e}")
            self.stop_session()
            return False, str(e)

    def stop_session(self):
        """Safely stop traffic shaping and spoofing."""
        with self.lock:
            if self.status != "RUNNING":
                return True, "Session is not running."
            self.status = "STOPPING"

        if self.stop_event:
            self.stop_event.set()

        # Wait for spoof threads
        for t in self.spoof_threads:
            t.join(timeout=2)
        self.spoof_threads.clear()

        # Cleanup traffic shaping
        if self.current_interface:
            cleanup_traffic_shaping(self.current_interface)

        # Disable IP forward
        disable_ip_forward()

        with self.lock:
            self.status = "IDLE"
            self.session_start_time = None
            self.device_telemetry.clear()

        return True, "Session stopped and network restored."

    def _telemetry_worker(self):
        """Collects live throughput numbers and online status from tc classes."""
        while self.stop_event and not self.stop_event.is_set():
            time.sleep(1.0)
            if not self.current_interface:
                continue

            # Read tc class stats
            res = run_cmd(f"tc -s class show dev {self.current_interface}")
            lines = res.stdout.splitlines()

            bytes_map = {}
            for idx, line in enumerate(lines):
                if "class htb 1:" in line:
                    parts = line.split()
                    class_str = parts[2]
                    try:
                        class_id = int(class_str.split(":")[1])
                    except (IndexError, ValueError):
                        continue
                    if idx + 1 < len(lines):
                        m = re.search(r"Sent (\d+) bytes", lines[idx + 1])
                        if m:
                            bytes_map[class_id] = int(m.group(1))

            now = time.time()
            with self.lock:
                for ip, state in self.device_telemetry.items():
                    class_id = state.get("class_id")
                    if class_id in bytes_map:
                        cur_bytes = bytes_map[class_id]
                        last_bytes = state.get("last_bytes", 0)
                        last_time = state.get("last_time", now)
                        dt = max(now - last_time, 0.001)

                        diff = max(cur_bytes - last_bytes, 0)
                        speed_kbps = (diff / 1024.0) / dt

                        state["total_bytes"] = cur_bytes
                        state["last_bytes"] = cur_bytes
                        state["last_time"] = now
                        state["speed_kbps"] = round(speed_kbps, 1)

                    # Badging expiry
                    if state.get("is_new") and (now - state.get("added_time", 0) > 30):
                        state["is_new"] = False

    def _whitelist_watcher_worker(self):
        """Dynamic passive ARP scanner for whitelist mode."""
        safe_macs = {dev.get("mac", "").lower() for dev in self.whitelisted if dev.get("mac")}
        for pmac in get_predefined_whitelist().keys():
            safe_macs.add(pmac.lower())

        safe_ips = {dev.get("ip") for dev in self.whitelisted if dev.get("ip") and dev.get("ip") != "-"}

        while self.stop_event and not self.stop_event.is_set():
            if self.stop_event.wait(10):
                break

            try:
                found = passive_arp_scan(self.current_interface, self.current_router_ip)
            except Exception:
                continue

            for dev in found:
                if self.stop_event.is_set():
                    break

                dev_ip = dev.get("ip")
                dev_mac = dev.get("mac", "").lower()

                if not dev_ip or dev_ip == "-":
                    continue

                # Whitelist protection
                if (dev_mac and dev_mac in safe_macs) or (dev_ip in safe_ips):
                    if dev_mac and dev_mac in safe_macs and dev_ip not in safe_ips:
                        safe_ips.add(dev_ip)
                    continue

                with self.lock:
                    if dev_ip in self.device_telemetry:
                        continue

                    # Hotplug shaping
                    class_id = 10 + len(self.targets)
                    add_target_shaping(self.current_interface, dev_ip, class_id, self.limit_mbps)

                    # Start spoofer
                    t = threading.Thread(
                        target=arp_spoof_loop,
                        args=(self.current_interface, dev_ip, self.current_router_ip, self.stop_event),
                        daemon=True
                    )
                    t.start()
                    self.spoof_threads.append(t)

                    # Record target & telemetry
                    now = time.time()
                    self.targets.append(dev)
                    self.device_telemetry[dev_ip] = {
                        "class_id": class_id,
                        "mac": dev_mac or "Unknown",
                        "vendor": dev.get("vendor", "Unknown"),
                        "speed_kbps": 0.0,
                        "total_bytes": 0,
                        "last_bytes": 0,
                        "last_time": now,
                        "is_online": True,
                        "is_new": True,
                        "added_time": now,
                    }

    def get_state(self):
        """Return comprehensive JSON-serializable snapshot."""
        with self.lock:
            uptime = int(time.time() - self.session_start_time) if self.session_start_time else 0
            
            # Format telemetry list
            telemetry_list = []
            total_speed = 0.0
            total_data = 0

            for ip, data in self.device_telemetry.items():
                total_speed += data.get("speed_kbps", 0.0)
                total_data += data.get("total_bytes", 0)
                telemetry_list.append({
                    "ip": ip,
                    "mac": data.get("mac", "Unknown"),
                    "vendor": data.get("vendor", "Unknown"),
                    "speed_kbps": data.get("speed_kbps", 0.0),
                    "speed_mbps": round(data.get("speed_kbps", 0.0) / 125.0, 2),
                    "total_bytes": data.get("total_bytes", 0),
                    "total_mb": round(data.get("total_bytes", 0) / (1024 * 1024), 2),
                    "is_online": data.get("is_online", True),
                    "is_new": data.get("is_new", False)
                })

            return {
                "status": self.status,
                "interface": self.current_interface,
                "router_ip": self.current_router_ip,
                "operational_mode": self.operational_mode,
                "limit_mbps": self.limit_mbps,
                "uptime": uptime,
                "target_count": len(self.targets),
                "total_speed_kbps": round(total_speed, 1),
                "total_speed_mbps": round(total_speed / 125.0, 2),
                "total_data_mb": round(total_data / (1024 * 1024), 2),
                "targets": self.targets,
                "whitelisted": self.whitelisted,
                "devices": list(self.devices),
                "telemetry": telemetry_list
            }
