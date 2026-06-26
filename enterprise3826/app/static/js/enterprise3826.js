(function () {
    function setStatus(ok) {
        var dot = document.getElementById('systemStatusDot');
        var text = document.getElementById('systemStatusText');
        if (dot === null || text === null) {
            return;
        }
        if (ok) {
            dot.classList.add('online');
            text.textContent = 'Система активна';
            return;
        }
        dot.classList.remove('online');
        text.textContent = 'Проверка недоступна';
    }

    function pingHealth() {
        fetch('/api/health', { credentials: 'same-origin' })
            .then(function (r) { return r.ok; })
            .then(function (ok) { setStatus(ok); })
            .catch(function () { setStatus(false); });
    }

    document.addEventListener('DOMContentLoaded', function () {
        pingHealth();
        setInterval(pingHealth, 30000);
    });
})();
