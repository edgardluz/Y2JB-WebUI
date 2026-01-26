let currentMode = 'downgrade';
let isConsoleOpen = false;

document.addEventListener('DOMContentLoaded', loadSettings);

function setMode(mode) {
    currentMode = mode;
    document.querySelectorAll('.mode-btn').forEach(btn => {
        btn.classList.remove('bg-brand-blue', 'text-white', 'shadow-lg');
        btn.classList.add('hover:bg-white/5', 'text-gray-400');
    });
    const activeBtn = document.getElementById(`btn-${mode}`);
    activeBtn.classList.remove('hover:bg-white/5', 'text-gray-400');
    activeBtn.classList.add('bg-brand-blue', 'text-white', 'shadow-lg');
}

function toggleAdvanced() {
    const el = document.getElementById('advanced-options');
    const arrow = document.getElementById('adv-arrow');
    el.classList.toggle('hidden');
    arrow.style.transform = el.classList.contains('hidden') ? 'rotate(0deg)' : 'rotate(90deg)';
}

function toggleConsole() {
    const drawer = document.getElementById('console-drawer');
    isConsoleOpen = !isConsoleOpen;
    drawer.style.height = isConsoleOpen ? '240px' : '0px';
}

async function loadSettings() {
    try {
        const res = await fetch('/api/backpork/settings');
        const data = await res.json();
        
        document.getElementById('input_path').value = data.input_path || '';
        document.getElementById('output_path').value = data.output_path || '';
        document.getElementById('sdk_pair').value = data.sdk_pair || 4;
        document.getElementById('paid').value = data.paid || '0x3100000000000002';
        document.getElementById('ptype').value = data.ptype || 'fake';
        document.getElementById('backup').checked = data.backup !== false;
        document.getElementById('use_fakelib').checked = data.use_fakelib !== false;
    } catch(e) { console.error("Failed to load settings", e); }
}

async function runProcess() {
    const btn = document.getElementById('run-btn');
    const statusText = document.getElementById('status-text');
    const statusIcon = document.getElementById('status-icon');
    const terminal = document.getElementById('terminal-content');
    const progressBar = document.getElementById('progress-bar');
    
    if(!document.getElementById('input_path').value) {
        Toast.show("Input directory required", "error");
        return;
    }

    btn.disabled = true;
    btn.classList.add('opacity-50', 'cursor-not-allowed');
    statusText.textContent = "Processing...";
    statusIcon.className = 'w-2 h-2 rounded-full bg-yellow-500 shrink-0 animate-pulse';
    terminal.innerHTML = '';
    progressBar.style.width = '0%';
    
    if(!isConsoleOpen) toggleConsole();

    const config = {
        mode: currentMode,
        input_path: document.getElementById('input_path').value,
        output_path: document.getElementById('output_path').value,
        sdk_pair: document.getElementById('sdk_pair').value,
        paid: document.getElementById('paid').value,
        ptype: document.getElementById('ptype').value,
        backup: document.getElementById('backup').checked,
        use_fakelib: document.getElementById('use_fakelib').checked
    };

    try {
        const response = await fetch('/api/backpork/run', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(config)
        });

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        
        progressBar.style.width = '20%';

        while (true) {
            const {value, done} = await reader.read();
            if (done) break;
            
            const chunk = decoder.decode(value);
            const lines = chunk.split('\n\n');
            
            lines.forEach(line => {
                if (line.startsWith('data: ')) {
                    try {
                        const msg = JSON.parse(line.substring(6));
                        
                        if (msg.log) {
                            terminal.textContent += msg.log + "\n";
                            terminal.scrollTop = terminal.scrollHeight;
                        }
                        
                        if (msg.status === 'success') {
                            progressBar.style.width = '100%';
                            statusIcon.className = 'w-2 h-2 rounded-full bg-green-500 shrink-0';
                            statusText.textContent = "Complete";
                            Toast.show('Process Finished Successfully', 'success');
                            btn.disabled = false;
                            btn.classList.remove('opacity-50', 'cursor-not-allowed');
                        } else if (msg.status === 'error') {
                            progressBar.style.width = '100%';
                            progressBar.classList.add('bg-red-500');
                            statusIcon.className = 'w-2 h-2 rounded-full bg-red-500 shrink-0';
                            statusText.textContent = "Failed";
                            Toast.show('Process Failed', 'error');
                            btn.disabled = false;
                            btn.classList.remove('opacity-50', 'cursor-not-allowed');
                        }
                    } catch(e) {}
                }
            });
        }
    } catch (e) {
        statusText.textContent = "Connection Error";
        Toast.show("Network Error", "error");
        btn.disabled = false;
        btn.classList.remove('opacity-50', 'cursor-not-allowed');
    }
}
