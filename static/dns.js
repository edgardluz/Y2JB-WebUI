document.addEventListener('DOMContentLoaded', loadRules);

async function loadRules() {
    try {
        const response = await fetch('/api/dns/list');
        const rules = await response.json();
        const container = document.getElementById('rulesList');
        container.innerHTML = '';

        if (!rules || rules.length === 0) {
            container.innerHTML = `
                <div class="flex flex-col items-center justify-center py-16 opacity-20 space-y-4">
                    <i class="fa-solid fa-shield-slash text-6xl"></i>
                    <p class="font-bold tracking-widest uppercase text-xs">No redirection rules active</p>
                </div>`;
            return;
        }

        rules.forEach(rule => {
            const item = document.createElement('div');
            item.className = 'group flex items-center justify-between p-5 bg-white/[0.02] border border-white/5 rounded-2xl hover:border-brand-blue/40 transition-all hover:bg-white/[0.04] hover:shadow-xl hover:shadow-brand-blue/5';
            
            const displayTarget = rule.target === 'SELF' ? 'Host (Self)' : rule.target;
            
            item.innerHTML = `
                <div class="flex items-center gap-5">
                    <div class="w-10 h-10 rounded-xl bg-brand-blue/10 flex items-center justify-center text-brand-light group-hover:scale-110 transition-transform">
                        <i class="fa-solid fa-route"></i>
                    </div>
                    <div class="flex flex-col gap-0.5">
                        <span class="font-bold text-sm text-gray-100">${escapeHtml(rule.name)}</span>
                        <div class="flex items-center gap-2 font-mono text-[11px]">
                            <span class="opacity-40">${escapeHtml(rule.domain)}</span>
                            <i class="fa-solid fa-arrow-right-long opacity-20 text-[8px]"></i>
                            <span class="text-brand-light/70">${escapeHtml(displayTarget)}</span>
                        </div>
                    </div>
                </div>
                <button onclick="deleteRule('${rule.id}')" class="w-10 h-10 flex items-center justify-center rounded-xl bg-red-500/5 text-red-500/40 hover:bg-red-500 hover:text-white transition-all opacity-0 group-hover:opacity-100">
                    <i class="fa-solid fa-trash-can text-sm"></i>
                </button>
            `;
            container.appendChild(item);
        });
    } catch (error) {
        console.error(error);
        if (typeof showToast === 'function') showToast('Error loading rules', 'error');
    }
}

async function addRule() {
    const nameInput = document.getElementById('ruleName');
    const domainInput = document.getElementById('ruleDomain');
    const targetInput = document.getElementById('ruleTarget');

    const name = nameInput.value.trim();
    const domain = domainInput.value.trim();
    const target = targetInput.value.trim() || '0.0.0.0';

    if (!name || !domain) {
        if (typeof showToast === 'function') showToast('Name and Domain are required', 'error');
        return;
    }

    try {
        const response = await fetch('/api/dns/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ name, domain, target })
        });
        
        const result = await response.json();
        if (result.success) {
            if (typeof showToast === 'function') showToast('Rule added successfully');
            nameInput.value = '';
            domainInput.value = '';
            targetInput.value = '0.0.0.0';
            loadRules();
        } else {
            if (typeof showToast === 'function') showToast(result.error, 'error');
        }
    } catch (error) {
        if (typeof showToast === 'function') showToast('Failed to add rule', 'error');
    }
}

async function deleteRule(id) {
    if(!confirm("Are you sure you want to delete this rule?")) return;

    try {
        const response = await fetch('/api/dns/delete', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ id })
        });
        
        if (response.ok) {
            loadRules();
            if (typeof showToast === 'function') showToast('Rule deleted');
        }
    } catch (error) {
        if (typeof showToast === 'function') showToast('Error deleting rule', 'error');
    }
}

function handleFileSelect(input) {
    const label = document.getElementById('fileLabel');
    if (input.files && input.files[0]) {
        label.querySelector('span').textContent = input.files[0].name;
        label.classList.add('opacity-100');
        label.classList.remove('opacity-60');
    }
}

async function importDomains() {
    const textarea = document.getElementById('bulkImportText');
    const fileInput = document.getElementById('bulkImportFile');
    const text = textarea.value.trim();
    const file = fileInput.files && fileInput.files[0];

    if (!text && !file) {
        if (typeof showToast === 'function') showToast('Paste a list or choose a file first', 'error');
        return;
    }

    try {
        const formData = new FormData();
        if (file) {
            formData.append('file', file);
        }
        if (text) {
            formData.append('text', text);
        }

        const response = await fetch('/api/dns/import', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        if (result.success) {
            const msg = `Imported ${result.imported} rules` + (result.skipped > 0 ? `, ${result.skipped} duplicates skipped` : '');
            if (typeof showToast === 'function') showToast(msg);
            textarea.value = '';
            fileInput.value = '';
            const label = document.getElementById('fileLabel');
            label.querySelector('span').textContent = 'Choose .txt file...';
            label.classList.add('opacity-60');
            label.classList.remove('opacity-100');
            loadRules();
        } else {
            if (typeof showToast === 'function') showToast(result.error || 'Import failed', 'error');
        }
    } catch (error) {
        if (typeof showToast === 'function') showToast('Failed to import', 'error');
    }
}

async function clearAllRules() {
    if (!confirm('Are you sure you want to delete ALL DNS rules? This cannot be undone.')) return;

    try {
        const response = await fetch('/api/dns/clear', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'}
        });
        
        if (response.ok) {
            loadRules();
            if (typeof showToast === 'function') showToast('All rules cleared');
        }
    } catch (error) {
        if (typeof showToast === 'function') showToast('Error clearing rules', 'error');
    }
}

function escapeHtml(text) {
    if (!text) return text;
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}