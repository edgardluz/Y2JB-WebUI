document.addEventListener('DOMContentLoaded', startClock);

function startClock() {
    const clockEl = document.getElementById('live-clock');
    if (!clockEl) return;
    function update() {
        const now = new Date();
        clockEl.textContent = now.toLocaleTimeString();
    }
    update();
    setInterval(update, 1000);
}
