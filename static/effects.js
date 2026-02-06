function shakeElement(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.classList.remove('shake-animation');
    void el.offsetWidth;
    el.classList.add('shake-animation');
    el.addEventListener('animationend', () => {
        el.classList.remove('shake-animation');
    }, { once: true });
}