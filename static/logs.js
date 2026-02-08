let autoScroll = true;
let logPollInterval;
let lastLogCount = 0;

document.addEventListener('DOMContentLoaded', () => {
    startLogPolling();
    
    const container = document.getElementById('log-container');
    container.addEventListener('scroll', () => {
        const isAtBottom = container.scrollHeight - container.scrollTop <= container.clientHeight + 50;
        if (!isAtBottom && autoScroll) {
            disableAutoScroll();
        } else if (isAtBottom && !autoScroll) {
            enableAutoScroll();
        }
    });
});

function startLogPolling() {
    fetchLogs();
    logPollInterval = setInterval(fetchLogs, 1000);
}

async function fetchLogs() {
    const statusBadge = document.getElementById('connection-status');
    
    try {
        const response = await fetch('/api/logs');
        if (!response.ok) throw new Error("API Error");
        
        const data = await response.json();
        
        statusBadge.className = "flex items-center gap-2 px-3 py-1.5 rounded-full bg-green-500/10 border border-green-500/20 text-green-400 text-xs font-mono transition-colors";
        statusBadge.innerHTML = '<div class="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div><span>Live</span>';

        renderLogs(data.logs);

    } catch (error) {
        console.error(error);
        statusBadge.className = "flex items-center gap-2 px-3 py-1.5 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-mono transition-colors";
        statusBadge.innerHTML = '<div class="w-2 h-2 rounded-full bg-red-500"></div><span>Offline</span>';
    }
}

function renderLogs(logs) {
    if (logs.length === lastLogCount) return;
    
    const container = document.getElementById('log-container');
    
    if (lastLogCount === 0 || logs.length < lastLogCount) {
        container.innerHTML = '';
    }

    
    container.innerHTML = logs.map(line => formatLogLine(line)).join('');
    
    lastLogCount = logs.length;

    if (autoScroll) {
        scrollToBottom();
    }
}

function formatLogLine(line) {
    let colorClass = "text-gray-400";
    
    if (line.includes('[ERROR]') || line.includes('Error:') || line.includes('[FAIL]')) {
        colorClass = "text-red-400 font-bold";
    } else if (line.includes('[WARNING]')) {
        colorClass = "text-yellow-400";
    } else if (line.includes('[INFO]')) {
        colorClass = "text-blue-300";
    } else if (line.includes('[STDOUT]')) {
        colorClass = "text-gray-300";
    } else if (line.includes('[AJB]')) {
        colorClass = "text-purple-400";
    } else if (line.includes('[UPLOAD]')) {
        colorClass = "text-green-400";
    }

    const safeLine = line.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    
    return `<div class="whitespace-pre-wrap break-all hover:bg-white/5 py-0.5 px-1 rounded ${colorClass}">${safeLine}</div>`;
}

function scrollToBottom() {
    const container = document.getElementById('log-container');
    container.scrollTop = container.scrollHeight;
}

function toggleAutoScroll() {
    if (autoScroll) disableAutoScroll();
    else enableAutoScroll();
}

function disableAutoScroll() {
    autoScroll = false;
    document.getElementById('btn-autoscroll').classList.remove('text-brand-light', 'border-brand-blue');
    document.getElementById('btn-autoscroll').classList.add('opacity-50');
    document.getElementById('scroll-lock-indicator').classList.remove('hidden');
}

function enableAutoScroll() {
    autoScroll = true;
    document.getElementById('btn-autoscroll').classList.add('text-brand-light', 'border-brand-blue');
    document.getElementById('btn-autoscroll').classList.remove('opacity-50');
    document.getElementById('scroll-lock-indicator').classList.add('hidden');
    scrollToBottom();
}

function clearLogs() {
    document.getElementById('log-container').innerHTML = '<div class="opacity-30 text-center py-4 text-[10px]">Console Cleared</div>';
    lastLogCount = 0;
}