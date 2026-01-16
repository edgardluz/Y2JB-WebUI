let currentRepos = {};

function toggleFields() {
    const type = document.getElementById('repo-type').value;
    const urlField = document.getElementById('field-url');
    const ghField = document.getElementById('field-github');

    if(type === 'direct') {
        urlField.classList.remove('hidden');
        ghField.classList.add('hidden');
    } else {
        urlField.classList.add('hidden');
        ghField.classList.remove('hidden');
    }
}

function openModal(editName = null) {
    const modal = document.getElementById('repoModal');
    const title = document.getElementById('modalTitle');
    const oldNameRef = document.getElementById('old-name-ref');

    document.getElementById('repo-name').value = '';
    document.getElementById('repo-url').value = '';
    document.getElementById('repo-github').value = '';
    document.getElementById('repo-pattern').value = '';
    document.getElementById('repo-type').value = 'direct';

    if (editName && currentRepos[editName]) {
        const data = currentRepos[editName];
        title.textContent = "Modify Repository";
        oldNameRef.value = editName;
        document.getElementById('repo-name').value = editName;
        document.getElementById('repo-type').value = data.type;

        if (data.type === 'direct') {
            document.getElementById('repo-url').value = data.url;
        } else {
            document.getElementById('repo-github').value = data.repo;
            document.getElementById('repo-pattern').value = data.asset_pattern;
        }
    } else {
        title.textContent = "Add Repository";
        oldNameRef.value = "";
    }

    toggleFields();
    modal.classList.remove('hidden');
}

function closeModal() {
    document.getElementById('repoModal').classList.add('hidden');
}

async function loadRepos() {
    const res = await fetch('/api/repos/list');
    currentRepos = await res.json();
    
    const tbody = document.getElementById('repoTable');
    if (document.getElementById('loading')) {
        document.getElementById('loading').classList.add('hidden');
    }
    tbody.innerHTML = '';

    for (const [name, config] of Object.entries(currentRepos)) {
        const tr = document.createElement('tr');
        tr.className = "border-b border-oled-border last:border-0 hover:bg-white/5 transition-colors group";
        tr.innerHTML = `
            <td class="p-4 font-mono text-brand-light" data-label="Filename">
                <div class="flex items-center gap-3">
                    <i class="fa-regular fa-file-code opacity-50"></i>
                    <span>${name}</span>
                </div>
            </td>
            
            <td class="p-4" data-label="Type">
                <span class="px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider ${
                    config.type === 'release' ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20' : 
                    'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                }">
                    ${config.type}
                </span>
            </td>
            
            <td class="p-4 opacity-70 text-xs" data-label="Source">
                <div class="flex flex-col gap-1">
                    <span class="font-bold">${config.repo || 'Direct URL'}</span>
                    <span class="font-mono opacity-50 text-[10px] truncate max-w-[150px] sm:max-w-xs">
                        ${config.asset_pattern || config.url}
                    </span>
                </div>
            </td>
            
            <td class="p-4 text-right" data-label="Actions">
                <div class="flex items-center justify-end gap-2 opacity-100 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity">
                    <button onclick="updateSingleRepo('${name}', this)" class="p-2 text-gray-400 hover:text-brand-light transition-colors" title="Update now">
                        <i class="fa-solid fa-arrows-rotate"></i>
                    </button>
                    <button onclick="openModal('${name}')" class="p-2 hover:text-brand-light transition-colors" title="Edit">
                        <i class="fa-solid fa-pen-to-square"></i>
                    </button>
                    <button onclick="deleteRepo('${name}')" class="p-2 hover:text-red-500 transition-colors" title="Delete">
                        <i class="fa-solid fa-trash"></i>
                    </button>
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    }
}

async function updateSingleRepo(name, btn) {
    const icon = btn.querySelector('i');
    icon.classList.add('fa-spin');
    btn.disabled = true;

    try {
        const res = await fetch('/update_repos', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ targets: [name] })
        });
        const data = await res.json();
        
        if (data.success && data.updated.length > 0) {
            alert(`Successfully updated ${name}`);
        } else if (data.errors && data.errors.length > 0) {
            alert(`Error updating ${name}: ${data.errors[0]}`);
        } else {
            alert(`${name} is already up to date.`);
        }
    } catch (e) {
        alert("Update failed: " + e.message);
    } finally {
        icon.classList.remove('fa-spin');
        btn.disabled = false;
    }
}

async function saveRepo() {
    const name = document.getElementById('repo-name').value.trim();
    const type = document.getElementById('repo-type').value;
    const oldName = document.getElementById('old-name-ref').value;

    if(!name) return alert("Filename is required");

    let payload = { 
        name: name, 
        old_name: oldName,
        type: type, 
        save_path: `payloads/${name}` 
    };

    if (type === 'direct') {
        payload.url = document.getElementById('repo-url').value.trim();
        if(!payload.url) return alert("URL is required");
    } else {
        payload.repo = document.getElementById('repo-github').value.trim();
        payload.asset_pattern = document.getElementById('repo-pattern').value.trim();
        if(!payload.repo || !payload.asset_pattern) return alert("Repo and Pattern are required");
    }

    try {
        const res = await fetch('/api/repos/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        
        const data = await res.json();
        if(data.error) throw new Error(data.error);

        closeModal();
        loadRepos();
    } catch(e) {
        alert("Error saving: " + e.message);
    }
}

async function deleteRepo(name) {
    if(!confirm(`Delete configuration for ${name}?`)) return;
    await fetch('/api/repos/delete', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({name})
    });
    loadRepos();
}

document.addEventListener('DOMContentLoaded', loadRepos);
