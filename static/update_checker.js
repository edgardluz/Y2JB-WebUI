document.addEventListener('DOMContentLoaded', () => {
    checkForUpdates();
});

async function checkForUpdates() {
    try {
        const res = await fetch('/api/update_check');
        const data = await res.json();

        const banner = document.getElementById('update-banner');
        if (!banner) return;

        if (data.error) {
            banner.classList.add('hidden');
            return;
        }

        if (data.up_to_date === false) {
            const msg = banner.querySelector('#update-message');
            const link = banner.querySelector('#update-link');
            const detail = banner.querySelector('#update-commits');

            if (msg) msg.textContent = `Update available: v${data.local_version} → v${data.remote_version}`;
            if (detail) {
                const parts = [];
                if (data.remote_date) parts.push(data.remote_date);
                if (data.remote_description) parts.push(data.remote_description);
                detail.textContent = parts.join(' — ');
            }
            if (link) link.href = data.repo_url + '/releases';

            banner.classList.remove('hidden');
        } else {
            banner.classList.add('hidden');
        }
    } catch (e) {
        console.error('Update check failed:', e);
    }
}

async function dismissUpdate() {
    const banner = document.getElementById('update-banner');
    if (banner) banner.classList.add('hidden');
}
