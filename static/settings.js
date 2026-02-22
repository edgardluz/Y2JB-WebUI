document.addEventListener('DOMContentLoaded', loadSettings);

async function loadSettings() {
    try {
        const response = await fetch('/api/settings');
        const config = await response.json();

        if (config.ip) document.getElementById('ip').value = config.ip;
        if (config.ftp_port) document.getElementById('ftp_port').value = config.ftp_port;
        document.getElementById('global_delay').value = config.global_delay || "5";
        
        document.getElementById('ajb').checked = config.ajb === 'true';
        const kstuffCheckbox = document.getElementById('kstuff-toggle');
        if (kstuffCheckbox) kstuffCheckbox.checked = config.kstuff !== 'false';

        const animCheckbox = document.getElementById('ui_animations');
        const animationsEnabled = config.ui_animations === 'true';
        animCheckbox.checked = animationsEnabled;
        
        document.getElementById('debug_mode').checked = config.debug_mode === 'true';
        document.getElementById('auto_update_repos').checked = config.auto_update_repos !== 'false';
        document.getElementById('dns_auto_start').checked = config.dns_auto_start !== 'false';
        
        const compactCheckbox = document.getElementById('compact_mode');
        compactCheckbox.checked = config.compact_mode === 'true';
        if (compactCheckbox.checked) document.body.classList.add('compact-mode');

        localStorage.setItem('animations', animationsEnabled);

    } catch (error) {
        console.error('Error loading settings:', error);
        Toast.show('Failed to load settings', 'error');
    }
}

async function saveAllSettings() {
    const payload = {
        ip: document.getElementById('ip').value,
        ftp_port: document.getElementById('ftp_port').value,
        global_delay: document.getElementById('global_delay').value,
        ajb: document.getElementById('ajb').checked ? "true" : "false",
        kstuff: document.getElementById('kstuff-toggle').checked ? "true" : "false",
        ui_animations: document.getElementById('ui_animations').checked ? "true" : "false",
        debug_mode: document.getElementById('debug_mode').checked ? "true" : "false",
        auto_update_repos: document.getElementById('auto_update_repos').checked ? "true" : "false",
        dns_auto_start: document.getElementById('dns_auto_start').checked ? "true" : "false",
        compact_mode: document.getElementById('compact_mode').checked ? "true" : "false"
    };

    try {
        const response = await fetch('/api/settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload)
        });

        const result = await response.json();

        if (result.success) {
            document.body.classList.toggle('compact-mode', payload.compact_mode === "true");
            localStorage.setItem('animations', payload.ui_animations === "true");
            Toast.show('Settings saved successfully!', 'success');
        } else {
            Toast.show('Error: ' + result.error, 'error');
        }
    } catch (error) {
        console.error('Error saving settings:', error);
        Toast.show('Connection error while saving', 'error');
    }
}

async function manualUpdateCheck() {
    const btn = document.getElementById('btn-update-check');
    const icon = document.getElementById('update-check-icon');
    const statusText = document.getElementById('update-status-text');

    btn.disabled = true;
    icon.classList.add('fa-spin');

    try {
        const res = await fetch('/api/update_check?force=true');
        const data = await res.json();

        if (data.error) {
            statusText.textContent = data.error;
            Toast.show(data.error, 'warning');
        } else if (data.up_to_date) {
            statusText.textContent = `Up to date — v${data.local_version} (${data.local_date || data.local_branch || ''})`;
            Toast.show('You are running the latest version!', 'success');
        } else {
            statusText.textContent = `Update: v${data.local_version} → v${data.remote_version} (${data.remote_date || ''})`;
            Toast.show(`Update available! v${data.remote_version}`, 'info');
        }
    } catch (e) {
        statusText.textContent = 'Failed to check for updates';
        Toast.show('Update check failed', 'error');
    } finally {
        btn.disabled = false;
        icon.classList.remove('fa-spin');
    }
}