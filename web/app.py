import os
import logging
from flask import Flask, render_template, request, jsonify

from core.engine import ThrottnuxEngine
from core.config import (
    load_predefined_rules,
    save_predefined_rules,
    load_config,
    save_config,
    RULES_FILE
)

log = logging.getLogger("throttnux.web")

# Paths
WEB_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(WEB_DIR, "templates")
STATIC_DIR = os.path.join(WEB_DIR, "static")

app = Flask(
    __name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR
)
app.config["SECRET_KEY"] = "throttnux-web-secret-key"

engine = ThrottnuxEngine()


@app.route("/")
def index():
    """Render main web dashboard."""
    return render_template("index.html")


@app.route("/api/status", methods=["GET"])
def get_status():
    """Return engine state snapshot."""
    state = engine.get_state()
    return jsonify({"success": True, "data": state})


@app.route("/api/interfaces", methods=["GET"])
def get_interfaces_list():
    """List available network interfaces and default router IP."""
    ifaces = engine.get_interfaces()
    gw = engine.get_default_gateway()
    return jsonify({
        "success": True,
        "interfaces": ifaces,
        "default_interface": engine.current_interface,
        "default_gateway": gw
    })


@app.route("/api/scan", methods=["POST"])
def scan_network():
    """Trigger active ARP scan."""
    data = request.get_json(silent=True) or {}
    iface = data.get("interface") or engine.current_interface
    router = data.get("router_ip") or engine.current_router_ip

    devices = engine.scan(interface=iface, router_ip=router)
    return jsonify({
        "success": True,
        "devices": devices,
        "count": len(devices)
    })


@app.route("/api/devices/manual", methods=["POST"])
def add_manual_device():
    """Add a manual device by IP/MAC."""
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    mac = data.get("mac")
    vendor = data.get("vendor", "Manual Entry")

    if not ip and not mac:
        return jsonify({"success": False, "error": "IP or MAC address is required."}), 400

    dev = engine.add_manual_device(ip=ip, mac=mac, vendor=vendor)
    return jsonify({"success": True, "device": dev})


@app.route("/api/devices/clear", methods=["POST"])
def clear_devices():
    """Clear scanned devices cache."""
    ok, msg = engine.clear_cache()
    if ok:
        return jsonify({"success": True, "message": msg})
    return jsonify({"success": False, "error": msg}), 400


@app.route("/api/rules", methods=["GET"])
def get_rules():
    """Get predefined global rules."""
    rules = load_predefined_rules()
    return jsonify({"success": True, "rules": rules})


@app.route("/api/rules", methods=["POST"])
def add_rule():
    """Add or update a global rule."""
    data = request.get_json(silent=True) or {}
    category = data.get("category")
    mac = (data.get("mac") or "").lower().strip()
    name = data.get("name", "").strip()

    if category not in ("whitelist", "blacklist"):
        return jsonify({"success": False, "error": "Category must be 'whitelist' or 'blacklist'."}), 400
    if not mac:
        return jsonify({"success": False, "error": "MAC address is required."}), 400

    rules = load_predefined_rules()
    rules[category][mac] = name
    save_predefined_rules(rules)
    return jsonify({"success": True, "rules": rules})


@app.route("/api/rules/<category>/<mac>", methods=["DELETE"])
def delete_rule(category, mac):
    """Delete a global rule."""
    mac_clean = mac.lower().strip()
    if category not in ("whitelist", "blacklist"):
        return jsonify({"success": False, "error": "Category must be 'whitelist' or 'blacklist'."}), 400

    rules = load_predefined_rules()
    if mac_clean in rules.get(category, {}):
        del rules[category][mac_clean]
        save_predefined_rules(rules)
        return jsonify({"success": True, "rules": rules})
    return jsonify({"success": False, "error": "Rule not found."}), 404


@app.route("/api/session/start", methods=["POST"])
def start_session():
    """Start bandwidth shaping session."""
    data = request.get_json(silent=True) or {}
    iface = data.get("interface") or engine.current_interface
    router = data.get("router_ip") or engine.current_router_ip
    mode = data.get("mode", "blacklist")
    targets = data.get("targets", [])
    whitelisted = data.get("whitelisted", [])
    limit_mbps = float(data.get("limit_mbps", 1.0))

    if not iface or not router:
        return jsonify({"success": False, "error": "Network interface and router IP are required."}), 400

    if mode == "blacklist" and not targets:
        return jsonify({"success": False, "error": "Please select at least one target to throttle in Blacklist mode."}), 400

    ok, msg = engine.start_session(
        interface=iface,
        router_ip=router,
        mode=mode,
        targets=targets,
        limit_mbps=limit_mbps,
        whitelisted=whitelisted
    )

    if ok:
        return jsonify({"success": True, "message": msg, "state": engine.get_state()})
    return jsonify({"success": False, "error": msg}), 500


@app.route("/api/session/stop", methods=["POST"])
def stop_session():
    """Stop active bandwidth shaping session."""
    ok, msg = engine.stop_session()
    return jsonify({"success": ok, "message": msg, "state": engine.get_state()})


@app.route("/api/telemetry", methods=["GET"])
def get_telemetry():
    """Real-time throughput metrics."""
    state = engine.get_state()
    return jsonify({
        "success": True,
        "status": state["status"],
        "uptime": state["uptime"],
        "total_speed_kbps": state["total_speed_kbps"],
        "total_speed_mbps": state["total_speed_mbps"],
        "total_data_mb": state["total_data_mb"],
        "target_count": state["target_count"],
        "telemetry": state["telemetry"]
    })


def create_app():
    return app


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
