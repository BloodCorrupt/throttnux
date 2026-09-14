/**
 * Throttnux Web UI Client Application
 */

class ThrottnuxApp {
    constructor() {
        this.state = {
            status: "IDLE",
            mode: "blacklist",
            limit_mbps: 1.0,
            interface: null,
            router_ip: null,
            devices: [],
            rules: { whitelist: {}, blacklist: {} },
            selectedIps: new Set(),
            telemetry: [],
            uptime: 0
        };

        this.pollInterval = null;
        this.timerInterval = null;
        this.isScanning = false;

        this.init();
    }

    async init() {
        this.bindEvents();
        await this.loadInterfaces();
        await this.loadRules();
        await this.fetchStatus();
        this.startTelemetryPolling();
    }

    bindEvents() {
        // Tab Navigation
        document.querySelectorAll('.nav-item').forEach(button => {
            button.addEventListener('click', (e) => {
                const targetTab = button.dataset.tab;
                this.switchTab(targetTab);
            });
        });

        // Mode Toggles (Blacklist vs Whitelist)
        document.getElementById('btnModeBlacklist').addEventListener('click', () => this.setMode('blacklist'));
        document.getElementById('btnModeWhitelist').addEventListener('click', () => this.setMode('whitelist'));

        // Speed Preset Pills
        document.querySelectorAll('.preset-pill').forEach(pill => {
            pill.addEventListener('click', () => {
                document.querySelectorAll('.preset-pill').forEach(p => p.classList.remove('active'));
                pill.classList.add('active');
                document.getElementById('customSpeedInput').value = '';
                this.state.limit_mbps = parseFloat(pill.dataset.speed);
                document.getElementById('statBandwidthLimit').innerHTML = `${this.state.limit_mbps} <span class="unit">Mbps</span>`;
            });
        });

        // Custom Speed Input
        const customInput = document.getElementById('customSpeedInput');
        customInput.addEventListener('input', (e) => {
            const val = parseFloat(e.target.value);
            if (val > 0) {
                document.querySelectorAll('.preset-pill').forEach(p => p.classList.remove('active'));
                this.state.limit_mbps = val;
                document.getElementById('statBandwidthLimit').innerHTML = `${val} <span class="unit">Mbps</span>`;
            }
        });

        // Session Control Button
        document.getElementById('btnSessionControl').addEventListener('click', () => this.toggleSession());

        // Rescan and Add Device Buttons
        document.getElementById('btnRescanTop').addEventListener('click', () => this.triggerScan());
        document.getElementById('btnScanDevicesTab').addEventListener('click', () => this.triggerScan());
        document.getElementById('btnManualAddTop').addEventListener('click', () => this.openModal('manualDeviceModal'));
        document.getElementById('btnManualDeviceTab').addEventListener('click', () => this.openModal('manualDeviceModal'));
        document.getElementById('btnClearCacheTab').addEventListener('click', () => this.clearCache());

        // Submit Manual Device
        document.getElementById('btnSubmitManualDevice').addEventListener('click', () => this.submitManualDevice());

        // Submit Rule
        document.getElementById('btnSubmitRule').addEventListener('click', () => this.submitRule());

        // Save Settings
        document.getElementById('btnSaveSettings').addEventListener('click', () => this.saveSettings());

        // Select All Checkbox
        document.getElementById('selectAllCheckbox').addEventListener('change', (e) => {
            const isChecked = e.target.checked;
            document.querySelectorAll('.device-row-check').forEach(cb => {
                cb.checked = isChecked;
                const ip = cb.dataset.ip;
                if (isChecked) {
                    this.state.selectedIps.add(ip);
                } else {
                    this.state.selectedIps.delete(ip);
                }
            });
        });
    }

    switchTab(tabId) {
        document.querySelectorAll('.nav-item').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tabId);
        });
        document.querySelectorAll('.tab-pane').forEach(pane => {
            pane.classList.toggle('active', pane.id === `pane-${tabId}`);
        });

        if (tabId === 'devices') {
            this.renderScannerTable();
        } else if (tabId === 'rules') {
            this.renderRules();
        }
    }

    setMode(mode) {
        this.state.mode = mode;
        document.getElementById('btnModeBlacklist').classList.toggle('active', mode === 'blacklist');
        document.getElementById('btnModeWhitelist').classList.toggle('active', mode === 'whitelist');
        document.getElementById('statModeSubtitle').textContent = `Mode: ${mode.charAt(0).toUpperCase() + mode.slice(1)}`;
        this.renderDashboardTable();
    }

    async loadInterfaces() {
        try {
            const res = await fetch('/api/interfaces');
            const data = await res.json();
            if (data.success) {
                const select = document.getElementById('settingInterface');
                select.innerHTML = '';
                data.interfaces.forEach(iface => {
                    const opt = document.createElement('option');
                    opt.value = iface;
                    opt.textContent = iface;
                    if (iface === data.default_interface) opt.selected = true;
                    select.appendChild(opt);
                });

                this.state.interface = data.default_interface;
                this.state.router_ip = data.default_gateway || '192.168.1.1';
                document.getElementById('settingRouterIp').value = this.state.router_ip;
            }
        } catch (e) {
            console.error("Failed to load interfaces:", e);
        }
    }

    async loadRules() {
        try {
            const res = await fetch('/api/rules');
            const data = await res.json();
            if (data.success) {
                this.state.rules = data.rules;
                this.renderRules();
            }
        } catch (e) {
            console.error("Failed to load rules:", e);
        }
    }

    async fetchStatus() {
        try {
            const res = await fetch('/api/status');
            const data = await res.json();
            if (data.success) {
                this.updateUIWithState(data.data);
            }
        } catch (e) {
            console.error("Failed to fetch status:", e);
        }
    }

    updateUIWithState(state) {
        this.state.status = state.status;
        this.state.devices = state.devices || [];
        this.state.telemetry = state.telemetry || [];
        this.state.uptime = state.uptime || 0;

        // Update Session Status Pill
        const pill = document.getElementById('sessionStatusPill');
        const text = document.getElementById('sessionStatusText');
        const btn = document.getElementById('btnSessionControl');
        const btnText = document.getElementById('btnSessionControlText');
        const timer = document.getElementById('sessionTimer');

        if (state.status === "RUNNING") {
            pill.className = 'session-status-pill running';
            text.textContent = 'ACTIVE';
            btn.className = 'btn btn-danger btn-glow';
            btn.innerHTML = '<i class="fa-solid fa-stop"></i> <span>Stop Session</span>';
            timer.style.display = 'flex';
        } else if (state.status === "SCANNING") {
            pill.className = 'session-status-pill idle';
            text.textContent = 'SCANNING';
            btn.className = 'btn btn-secondary';
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> <span>Scanning...</span>';
            timer.style.display = 'none';
        } else {
            pill.className = 'session-status-pill idle';
            text.textContent = 'IDLE';
            btn.className = 'btn btn-primary btn-glow';
            btn.innerHTML = '<i class="fa-solid fa-play"></i> <span>Start Session</span>';
            timer.style.display = 'none';
        }

        // Metrics
        document.getElementById('statThroughput').innerHTML = `${state.total_speed_kbps || '0.0'} <span class="unit">KB/s</span>`;
        document.getElementById('statThroughputMbps').textContent = `${state.total_speed_mbps || '0.00'} Mbps total speed`;
        document.getElementById('statTargetCount').textContent = state.target_count || 0;
        document.getElementById('statDataTransferred').innerHTML = `${state.total_data_mb || '0.00'} <span class="unit">MB</span>`;

        this.renderDashboardTable();
    }

    renderDashboardTable() {
        const tbody = document.getElementById('devicesTableBody');
        if (!this.state.devices.length) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" class="empty-state">
                        <i class="fa-solid fa-satellite-dish fa-2x"></i>
                        <p>No active network devices detected. Click "Scan" or "Add Device" above.</p>
                    </td>
                </tr>`;
            return;
        }

        const teleMap = {};
        this.state.telemetry.forEach(t => {
            teleMap[t.ip] = t;
        });

        tbody.innerHTML = '';
        this.state.devices.forEach(dev => {
            const tr = document.createElement('tr');
            const macLower = (dev.mac || '').toLowerCase();
            const ip = dev.ip || '-';

            const isGlobalWl = macLower in (this.state.rules.whitelist || {});
            const isGlobalBl = macLower in (this.state.rules.blacklist || {});
            const wlLabel = (this.state.rules.whitelist || {})[macLower];
            const blLabel = (this.state.rules.blacklist || {})[macLower];

            // Auto select defaults if not interacted with
            let isChecked = this.state.selectedIps.has(ip);
            if (this.state.status !== "RUNNING" && !this.state.selectedIps.size) {
                if (this.state.mode === "blacklist" && isGlobalBl) isChecked = true;
                if (this.state.mode === "whitelist" && isGlobalWl) isChecked = true;
                if (isChecked) this.state.selectedIps.add(ip);
            }

            // Rule Badge
            let badgeHtml = '<span class="text-muted">-</span>';
            if (isGlobalWl) {
                badgeHtml = `<span class="badge badge-whitelist"><i class="fa-solid fa-shield"></i> Safe ${wlLabel ? `(${wlLabel})` : ''}</span>`;
            } else if (isGlobalBl) {
                badgeHtml = `<span class="badge badge-blacklist"><i class="fa-solid fa-skull"></i> Target ${blLabel ? `(${blLabel})` : ''}</span>`;
            }

            // Telemetry stats
            const tele = teleMap[ip];
            let speedHtml = '<span class="text-muted">0.0 KB/s</span>';
            if (tele) {
                speedHtml = `<span class="device-speed-pill">${tele.speed_kbps} KB/s (${tele.speed_mbps} Mbps)</span>`;
            }

            tr.innerHTML = `
                <td>
                    <input type="checkbox" class="custom-checkbox device-row-check" data-ip="${ip}" ${isChecked ? 'checked' : ''} ${this.state.status === 'RUNNING' ? 'disabled' : ''}>
                </td>
                <td class="device-ip">${ip}</td>
                <td class="device-mac">${dev.mac || 'Unknown'}</td>
                <td class="device-vendor">${dev.vendor || 'Unknown'}</td>
                <td>${badgeHtml}</td>
                <td>${speedHtml}</td>
                <td style="text-align: right;">
                    <button class="btn btn-secondary btn-sm" onclick="app.quickAddToRule('${macLower}', '${dev.vendor || ''}')" title="Add to global rules">
                        <i class="fa-solid fa-shield-halved"></i>
                    </button>
                </td>
            `;

            const cb = tr.querySelector('.device-row-check');
            cb.addEventListener('change', (e) => {
                if (e.target.checked) {
                    this.state.selectedIps.add(ip);
                } else {
                    this.state.selectedIps.delete(ip);
                }
            });

            tbody.appendChild(tr);
        });
    }

    renderScannerTable() {
        const tbody = document.getElementById('scannerTableBody');
        if (!this.state.devices.length) {
            tbody.innerHTML = `<tr><td colspan="5" class="empty-state"><p>No devices discovered yet.</p></td></tr>`;
            return;
        }

        tbody.innerHTML = '';
        this.state.devices.forEach(dev => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td class="device-ip">${dev.ip || '-'}</td>
                <td class="device-mac">${dev.mac || 'Unknown'}</td>
                <td class="device-vendor">${dev.vendor || 'Unknown'}</td>
                <td><span class="badge badge-new">Active</span></td>
                <td style="text-align: right;">
                    <button class="btn btn-secondary btn-sm" onclick="app.quickAddToRule('${dev.mac || ''}', '${dev.vendor || ''}')">
                        <i class="fa-solid fa-plus"></i> Rule
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    renderRules() {
        const wlContainer = document.getElementById('whitelistRulesContainer');
        const blContainer = document.getElementById('blacklistRulesContainer');

        const wl = this.state.rules.whitelist || {};
        const bl = this.state.rules.blacklist || {};

        if (!Object.keys(wl).length) {
            wlContainer.innerHTML = '<div class="empty-state"><p>No global whitelist rules configured.</p></div>';
        } else {
            wlContainer.innerHTML = Object.entries(wl).map(([mac, name]) => `
                <div class="rule-item">
                    <div>
                        <div class="rule-mac">${mac}</div>
                        <div class="rule-name">${name || 'No label'}</div>
                    </div>
                    <button class="btn-icon-delete" onclick="app.deleteRule('whitelist', '${mac}')" title="Delete rule">
                        <i class="fa-solid fa-trash-can"></i>
                    </button>
                </div>
            `).join('');
        }

        if (!Object.keys(bl).length) {
            blContainer.innerHTML = '<div class="empty-state"><p>No global blacklist rules configured.</p></div>';
        } else {
            blContainer.innerHTML = Object.entries(bl).map(([mac, name]) => `
                <div class="rule-item">
                    <div>
                        <div class="rule-mac">${mac}</div>
                        <div class="rule-name">${name || 'No label'}</div>
                    </div>
                    <button class="btn-icon-delete" onclick="app.deleteRule('blacklist', '${mac}')" title="Delete rule">
                        <i class="fa-solid fa-trash-can"></i>
                    </button>
                </div>
            `).join('');
        }
    }

    async toggleSession() {
        if (this.state.status === "RUNNING") {
            try {
                const res = await fetch('/api/session/stop', { method: 'POST' });
                const data = await res.json();
                if (data.success) {
                    this.showToast('Session stopped successfully.', 'info');
                    this.updateUIWithState(data.state);
                } else {
                    this.showToast(data.error || 'Failed to stop session.', 'error');
                }
            } catch (e) {
                this.showToast('Network error while stopping session.', 'error');
            }
        } else {
            // Selected devices array
            const selectedDevices = this.state.devices.filter(d => this.state.selectedIps.has(d.ip));
            
            let targets = [];
            let whitelisted = [];

            if (this.state.mode === "blacklist") {
                targets = selectedDevices;
                if (!targets.length) {
                    this.showToast('Please select at least one device to throttle.', 'error');
                    return;
                }
            } else {
                whitelisted = selectedDevices;
                // In whitelist mode, throttle all current devices except selected
                const safeMacs = new Set(whitelisted.map(d => (d.mac || '').toLowerCase()));
                const safeIps = new Set(whitelisted.map(d => d.ip));
                targets = this.state.devices.filter(d => {
                    const mac = (d.mac || '').toLowerCase();
                    return !((mac && safeMacs.has(mac)) || safeIps.has(d.ip));
                });
            }

            try {
                const payload = {
                    interface: this.state.interface,
                    router_ip: this.state.router_ip,
                    mode: this.state.mode,
                    targets: targets,
                    whitelisted: whitelisted,
                    limit_mbps: this.state.limit_mbps
                };

                const res = await fetch('/api/session/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();

                if (data.success) {
                    this.showToast(data.message || 'Session started!', 'success');
                    this.updateUIWithState(data.state);
                } else {
                    this.showToast(data.error || 'Failed to start session.', 'error');
                }
            } catch (e) {
                this.showToast('Error starting session.', 'error');
            }
        }
    }

    async triggerScan() {
        if (this.isScanning) return;
        this.isScanning = true;
        this.showToast('Scanning local network for devices...', 'info');

        try {
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    interface: this.state.interface,
                    router_ip: this.state.router_ip
                })
            });
            const data = await res.json();
            if (data.success) {
                this.state.devices = data.devices;
                this.renderDashboardTable();
                this.renderScannerTable();
                this.showToast(`Scan complete: found ${data.count} device(s).`, 'success');
            } else {
                this.showToast('Scan failed.', 'error');
            }
        } catch (e) {
            this.showToast('Network error during scan.', 'error');
        } finally {
            this.isScanning = false;
        }
    }

    async submitManualDevice() {
        const ip = document.getElementById('manualDeviceIp').value.trim();
        const mac = document.getElementById('manualDeviceMac').value.trim();
        const vendor = document.getElementById('manualDeviceVendor').value.trim();

        if (!ip && !mac) {
            this.showToast('Please enter an IP address or a MAC address.', 'error');
            return;
        }

        try {
            const res = await fetch('/api/devices/manual', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip, mac, vendor })
            });
            const data = await res.json();
            if (data.success) {
                this.closeModal('manualDeviceModal');
                document.getElementById('manualDeviceIp').value = '';
                document.getElementById('manualDeviceMac').value = '';
                document.getElementById('manualDeviceVendor').value = '';
                this.showToast(`Added device: ${data.device.ip} (${data.device.mac})`, 'success');
                await this.fetchStatus();
            } else {
                this.showToast(data.error || 'Failed to add manual device.', 'error');
            }
        } catch (e) {
            this.showToast('Error adding manual device.', 'error');
        }
    }

    async submitRule() {
        const category = document.getElementById('ruleCategoryInput').value;
        const mac = document.getElementById('ruleMacInput').value.trim();
        const name = document.getElementById('ruleNameInput').value.trim();

        if (!mac) {
            this.showToast('MAC address is required.', 'error');
            return;
        }

        try {
            const res = await fetch('/api/rules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ category, mac, name })
            });
            const data = await res.json();
            if (data.success) {
                this.closeModal('addRuleModal');
                document.getElementById('ruleMacInput').value = '';
                document.getElementById('ruleNameInput').value = '';
                this.state.rules = data.rules;
                this.renderRules();
                this.renderDashboardTable();
                this.showToast(`Saved rule for ${mac}`, 'success');
            } else {
                this.showToast(data.error || 'Failed to save rule.', 'error');
            }
        } catch (e) {
            this.showToast('Error saving rule.', 'error');
        }
    }

    async deleteRule(category, mac) {
        try {
            const res = await fetch(`/api/rules/${category}/${encodeURIComponent(mac)}`, { method: 'DELETE' });
            const data = await res.json();
            if (data.success) {
                this.state.rules = data.rules;
                this.renderRules();
                this.renderDashboardTable();
                this.showToast(`Removed rule for ${mac}`, 'info');
            }
        } catch (e) {
            this.showToast('Failed to delete rule.', 'error');
        }
    }

    async clearCache() {
        if (confirm("Are you sure you want to clear device cache and saved session?")) {
            try {
                const res = await fetch('/api/devices/clear', { method: 'POST' });
                const data = await res.json();
                if (data.success) {
                    this.showToast(data.message, 'success');
                    await this.fetchStatus();
                } else {
                    this.showToast(data.error, 'error');
                }
            } catch (e) {
                this.showToast('Error clearing cache.', 'error');
            }
        }
    }

    saveSettings() {
        const iface = document.getElementById('settingInterface').value;
        const router = document.getElementById('settingRouterIp').value.trim();
        const limit = parseFloat(document.getElementById('settingDefaultLimit').value) || 1.0;

        this.state.interface = iface;
        this.state.router_ip = router;
        this.state.limit_mbps = limit;

        this.showToast('Settings saved successfully.', 'success');
    }

    quickAddToRule(mac, vendor) {
        if (!mac || mac === 'Unknown') {
            this.showToast('Cannot create global rule without a MAC address.', 'error');
            return;
        }
        document.getElementById('ruleMacInput').value = mac;
        document.getElementById('ruleNameInput').value = vendor;
        this.openAddRuleModal('whitelist');
    }

    openAddRuleModal(category) {
        document.getElementById('ruleCategoryInput').value = category;
        const title = category === 'whitelist' ? 'Add to Global Whitelist' : 'Add to Global Blacklist';
        document.getElementById('addRuleModalTitle').innerHTML = `<i class="fa-solid fa-shield cyan"></i> ${title}`;
        this.openModal('addRuleModal');
    }

    openModal(modalId) {
        document.getElementById(modalId).classList.add('active');
    }

    closeModal(modalId) {
        document.getElementById(modalId).classList.remove('active');
    }

    showToast(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        let icon = 'fa-info-circle';
        if (type === 'success') icon = 'fa-circle-check';
        if (type === 'error') icon = 'fa-circle-exclamation';

        toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${message}</span>`;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            setTimeout(() => toast.remove(), 300);
        }, 3500);
    }

    startTelemetryPolling() {
        // Poll telemetry every 1.5s
        this.pollInterval = setInterval(async () => {
            if (this.state.status === "RUNNING") {
                try {
                    const res = await fetch('/api/telemetry');
                    const data = await res.json();
                    if (data.success) {
                        document.getElementById('statThroughput').innerHTML = `${data.total_speed_kbps || '0.0'} <span class="unit">KB/s</span>`;
                        document.getElementById('statThroughputMbps').textContent = `${data.total_speed_mbps || '0.00'} Mbps total speed`;
                        document.getElementById('statDataTransferred').innerHTML = `${data.total_data_mb || '0.00'} <span class="unit">MB</span>`;
                        this.state.telemetry = data.telemetry || [];
                        this.renderDashboardTable();
                    }
                } catch (e) {}
            }
        }, 1500);

        // Timer interval
        this.timerInterval = setInterval(() => {
            if (this.state.status === "RUNNING") {
                this.state.uptime += 1;
                const hrs = String(Math.floor(this.state.uptime / 3600)).padStart(2, '0');
                const mins = String(Math.floor((this.state.uptime % 3600) / 60)).padStart(2, '0');
                const secs = String(this.state.uptime % 60).padStart(2, '0');
                document.getElementById('sessionTimeDisplay').textContent = `${hrs}:${mins}:${secs}`;
            }
        }, 1000);
    }
}

// Instantiate on load
let app = null;
window.addEventListener('DOMContentLoaded', () => {
    app = new ThrottnuxApp();
});
