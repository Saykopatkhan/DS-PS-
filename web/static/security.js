"use strict";
function apiFetch(input, options = {}) {
    const url = new URL(input, window.location.href);
    const method = (options.method || 'GET').toUpperCase();
    const headers = new Headers(options.headers || {});
    if (url.origin === window.location.origin && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
        headers.set('X-CSRF-Token', document.querySelector('meta[name="csrf-token"]').content);
    }
    return fetch(input, {...options, headers});
}
function logout() {
    apiFetch('/logout', {method: 'POST', credentials: 'same-origin'})
        .then(response => { if (response.ok) window.location.assign('/login'); });
}
function escapeHtml(value) {
    return String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
