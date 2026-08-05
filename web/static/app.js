/**
 * DS IPS Dashboard - Frontend JavaScript
 * SocketIO ile gerçek zamanlı alarm akışı, istatistik güncellemesi ve kontrol paneli.
 */

let socket = null;

// DS-01: Fetch WS Token before connecting
fetch('/api/ws_token', {headers: {'X-Requested-With': 'XMLHttpRequest'}, credentials: 'same-origin'})
    .then(r => {
        if (!r.ok) throw new Error('Token fetch failed');
        return r.json();
    })
    .then(tokenData => {
        socket = io({ auth: { token: tokenData.token } });

        socket.on('connect', () => {
            console.log('[DS IPS] WebSocket bağlantısı kuruldu');
        });

        socket.on('disconnect', () => {
            console.log('[DS IPS] WebSocket bağlantısı kesildi');
            const badge = document.getElementById('status-badge');
            if(badge) {
                badge.className = 'status-badge';
                badge.querySelector('.status-text').textContent = 'Bağlantı Kesildi';
            }
        });

        socket.on('new_alert', (data) => {
            addAlertToFeed(data, true);
            const el = document.getElementById('total-alerts');
            if(el) el.textContent = parseInt(el.textContent) + 1;
            
            if (typeof drawAttackLaser === "function") {
                drawAttackLaser(data.source_ip, data.destination_ip, data.severity);
            }
        });

        socket.on('stats_update', (data) => {
            updateStats(data);
        });

        socket.on('status_update', (data) => {
            updateRunningStatus(data.running);
        });

        socket.on('ban_update', (data) => {
            fetch('/api/bans', {credentials: 'same-origin'})
                .then(r => r.json())
                .then(bans => renderBanList(bans));

            const el = document.getElementById('active-bans');
            if (el) {
                if (data.action === 'added') {
                    el.textContent = parseInt(el.textContent) + 1;
                } else {
                    el.textContent = Math.max(0, parseInt(el.textContent) - 1);
                }
            }
        });

        socket.on('scan_complete', (data) => {
            const btn = document.getElementById('scan-btn');
            const list = document.getElementById('scanner-list');
            
            if(btn) {
                btn.disabled = false;
                btn.textContent = 'Taramayı Başlat';
            }
            
            if (data.success && data.records) {
                renderDeviceList(data.records);
                showNotification('Tarama tamamlandı', 'success');
                
                // Haritayı güncelle
                if (typeof updateNetworkMap === "function") {
                    updateNetworkMap(data.records);
                }
            }
        });
    })
    .catch(err => {
        console.error('Socket.io başlatılamadı:', err);
    });

// Durum değişkenleri
let isRunning = false;
const MAX_ALERTS_DISPLAY = 100;

// DOM yüklendiğinde
document.addEventListener('DOMContentLoaded', () => {
    loadInitialData();
});

// İlk verileri yükle
function loadInitialData() {
    fetch('/api/alerts', {credentials: 'same-origin'})
        .then(r => r.json())
        .then(data => {
            if (data.length > 0) {
                // Reverse to show oldest first, then add newest on top
                data.reverse().forEach(alert => addAlertToFeed(alert, false));
            }
        })
        .catch(err => console.error('Alarmlar yüklenemedi:', err));

    fetch('/api/bans', {credentials: 'same-origin'})
        .then(r => r.json())
        .then(data => renderBanList(data))
        .catch(err => console.error('Banlar yüklenemedi:', err));

    fetch('/api/stats', {credentials: 'same-origin'})
        .then(r => r.json())
        .then(data => updateStats(data))
        .catch(err => console.error('İstatistikler yüklenemedi:', err));
        
    // Harita ve cihaz listesi için ilk cihazları çek
    fetch('/api/records', {credentials: 'same-origin'})
        .then(r => r.json())
        .then(data => {
            if (typeof renderDeviceList === "function") renderDeviceList(data);
            if (typeof updateNetworkMap === "function") updateNetworkMap(data);
        })
        .catch(err => console.error('Cihazlar yüklenemedi:', err));
        
    // Cihaz listesini ve haritayı 15 saniyede bir otomatik güncelle
    setInterval(() => {
        fetch('/api/records', {credentials: 'same-origin'})
            .then(r => r.json())
            .then(data => {
                if (typeof renderDeviceList === "function") renderDeviceList(data);
                if (typeof updateNetworkMap === "function") updateNetworkMap(data);
            })
            .catch(err => console.error('Otomatik cihaz güncellemesi başarısız:', err));
    }, 15000);
}

// (WebSocket olayları yukarıda initialize edildi)

// ---- Alarm Akışı ----

function addAlertToFeed(alert, animate) {
    const list = document.getElementById('alerts-list');

    // Boş durum mesajını kaldır
    const empty = list.querySelector('.alert-empty');
    if (empty) empty.remove();

    const item = document.createElement('div');
    item.className = `alert-item severity-${alert.severity}`;
    if (animate) item.classList.add('animate-in');

    const timestamp = alert.timestamp || new Date().toLocaleTimeString('tr-TR');

    item.innerHTML = `
        <div class="alert-header">
            <span class="severity-badge ${alert.severity}">${escapeHtml(alert.severity.toUpperCase())}</span>
            <span class="alert-type">${escapeHtml(alert.alert_type)}</span>
            <span class="alert-time">${escapeHtml(timestamp)}</span>
        </div>
        <div class="alert-body">
            <p class="alert-desc">${escapeHtml(alert.description)}</p>
            <div class="alert-meta" style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <span class="meta-item">
                        <span class="meta-label">Kaynak:</span>
                        <span class="mono">${escapeHtml(alert.source_ip || 'N/A')} / ${escapeHtml(alert.source_mac || 'N/A')}</span>
                    </span>
                    <span class="meta-item">
                        <span class="meta-label">Hedef:</span>
                        <span class="mono">${escapeHtml(alert.destination_ip || 'N/A')} / ${escapeHtml(alert.destination_mac || 'N/A')}</span>
                    </span>
                </div>
                ${(alert.source_ip && alert.source_ip !== 'N/A') || (alert.source_mac && alert.source_mac !== 'N/A') ? 
                    `<button class="btn btn-sm btn-danger" style="margin-left: 10px;" onclick="quickBan('${escapeAttr(alert.source_ip === 'N/A' ? '' : alert.source_ip)}', '${escapeAttr(alert.source_mac === 'N/A' ? '' : alert.source_mac)}')">Ağdan At</button>` 
                    : ''}
            </div>
        </div>
    `;

    // Listenin başına ekle (en yeni üstte)
    list.insertBefore(item, list.firstChild);

    // Maksimum gösterim sayısını aşma
    while (list.children.length > MAX_ALERTS_DISPLAY) {
        list.removeChild(list.lastChild);
    }
}

// ---- İstatistik Güncelleme ----

function updateStats(stats) {
    document.getElementById('total-alerts').textContent = stats.total_alerts || 0;
    document.getElementById('active-bans').textContent = stats.active_bans || 0;
    document.getElementById('interface-name').textContent = stats.interface || 'N/A';

    // Mode badge
    const modeBadge = document.getElementById('mode-badge');
    modeBadge.textContent = stats.mode || 'IDS';
    modeBadge.className = 'mode-badge ' + (stats.mode === 'IPS' ? 'mode-ips' : 'mode-ids');

    // Uptime
    if (stats.uptime !== undefined) {
        const h = Math.floor(stats.uptime / 3600);
        const m = Math.floor((stats.uptime % 3600) / 60);
        const s = stats.uptime % 60;
        document.getElementById('uptime').textContent =
            `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
    }

    // ARP istatistikleri
    const arpStats = stats.arp_stats || {};
    const arpRequests = arpStats.requests || {};
    const arpReplies = arpStats.replies || {};
    const arpGratuitous = arpStats.gratuitous || {};
    document.getElementById('arp-requests').textContent =
        Object.values(arpRequests).reduce((a, b) => a + b, 0);
    document.getElementById('arp-replies').textContent =
        Object.values(arpReplies).reduce((a, b) => a + b, 0);
    document.getElementById('arp-gratuitous').textContent =
        Object.values(arpGratuitous).reduce((a, b) => a + b, 0);

    // Scan istatistikleri
    const scanStats = stats.scan_stats || {};
    document.getElementById('scan-syn').textContent = scanStats.syn_scans || 0;
    document.getElementById('scan-fin').textContent = scanStats.fin_scans || 0;
    document.getElementById('scan-xmas').textContent = scanStats.xmas_scans || 0;
    document.getElementById('scan-null').textContent = scanStats.null_scans || 0;
    document.getElementById('scan-udp').textContent = scanStats.udp_scans || 0;

    // WiFi istatistikleri
    const wifiStats = stats.wifi_stats || {};
    document.getElementById('wifi-deauth').textContent = wifiStats.deauth_senders || 0;
    document.getElementById('wifi-beacon').textContent = wifiStats.beacon_bssids || 0;
    document.getElementById('wifi-evil-twin').textContent = wifiStats.evil_twin_ssids || 0;

    // WiFi modül durumu
    const wifiStatus = document.getElementById('wifi-status');
    if (stats.wifi_enabled) {
        wifiStatus.textContent = 'Aktif';
        wifiStatus.className = 'module-status active';
    } else {
        wifiStatus.textContent = 'Pasif';
        wifiStatus.className = 'module-status';
    }

    // Çalışma durumunu güncelle
    updateRunningStatus(stats.sniffer_running);

    // Arayüz input'unu güncelle
    const ifaceInput = document.getElementById('interface-input');
    if (document.activeElement !== ifaceInput) {
        ifaceInput.value = stats.interface || 'eth0';
    }
}

// ---- Çalışma Durumu ----

function updateRunningStatus(running) {
    isRunning = running;
    const badge = document.getElementById('status-badge');
    const text = badge.querySelector('.status-text');
    const startBtn = document.getElementById('start-btn');
    const stopBtn = document.getElementById('stop-btn');

    if (running) {
        badge.className = 'status-badge running';
        text.textContent = 'Aktif';
        startBtn.disabled = true;
        stopBtn.disabled = false;
    } else {
        badge.className = 'status-badge stopped';
        text.textContent = 'Durduruldu';
        startBtn.disabled = false;
        stopBtn.disabled = true;
    }
}

// ---- Sniffer Kontrolü ----

function startSniffer() {
    const iface = document.getElementById('interface-input').value.trim();
    if (!iface) {
        showNotification('Lütfen bir ağ arayüzü girin!', 'warning');
        return;
    }

    fetch('/api/control', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
        body: JSON.stringify({ action: 'start', interface: iface })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            updateRunningStatus(true);
            showNotification('Sniffer başlatıldı!', 'success');
        }
    })
    .catch(err => showNotification('Başlatma hatası: ' + err, 'error'));
}

function stopSniffer() {
    fetch('/api/control', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
        body: JSON.stringify({ action: 'stop' })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            updateRunningStatus(false);
            showNotification('Sniffer durduruldu.', 'warning');
        }
    })
    .catch(err => showNotification('Durdurma hatası: ' + err, 'error'));
}

// ---- Ban Yönetimi ----

function addBan() {
    const ip = document.getElementById('ban-ip').value.trim();
    const mac = document.getElementById('ban-mac').value.trim();
    const reason = document.getElementById('ban-reason').value.trim() || 'Manuel ban';

    if (!ip && !mac) {
        showNotification('IP veya MAC adresi gerekli!', 'warning');
        return;
    }

    fetch('/api/ban', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
        body: JSON.stringify({ ip, mac, reason })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            document.getElementById('ban-ip').value = '';
            document.getElementById('ban-mac').value = '';
            document.getElementById('ban-reason').value = '';
            fetch('/api/bans', {credentials: 'same-origin'}).then(r => r.json()).then(bans => renderBanList(bans));
            showNotification('Engelleme eklendi!', 'success');
        }
    })
    .catch(err => showNotification('Ban hatası: ' + err, 'error'));
}

function removeBan(ip, mac) {
    fetch('/api/unban', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
        body: JSON.stringify({ ip: ip || '', mac: mac || '' })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            fetch('/api/bans', {credentials: 'same-origin'}).then(r => r.json()).then(bans => renderBanList(bans));
            showNotification('Engelleme kaldırıldı.', 'warning');
        }
    })
    .catch(err => showNotification('Unban hatası: ' + err, 'error'));
}

function renderBanList(bans) {
    const list = document.getElementById('ban-list');
    if (!bans || bans.length === 0) {
        list.innerHTML = '<div class="ban-empty">Aktif ban bulunmuyor.</div>';
        return;
    }

    list.innerHTML = bans.map(ban => `
        <div class="ban-item">
            <div class="ban-info">
                <span class="mono">${escapeHtml(ban.ip_address || '-')} / ${escapeHtml(ban.mac_address || '-')}</span>
                <span class="ban-reason">${escapeHtml(ban.reason || 'N/A')}</span>
            </div>
            <button class="btn btn-sm btn-unban" onclick="removeBan('${escapeAttr(ban.ip_address || '')}', '${escapeAttr(ban.mac_address || '')}')">
                Kaldır
            </button>
        </div>
    `).join('');
}

// ---- Alarm Akışını Temizle ----

function clearAlertFeed() {
    const list = document.getElementById('alerts-list');
    list.innerHTML = '<div class="alert-empty"><span>Alarm akışı temizlendi.</span></div>';
}

// ---- Bildirim Sistemi ----

function showNotification(message, type) {
    // Mevcut bildirimi kaldır
    const existing = document.querySelector('.notification');
    if (existing) existing.remove();

    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 70px;
        right: 20px;
        padding: 0.75rem 1.25rem;
        border-radius: 8px;
        font-size: 0.8rem;
        font-weight: 500;
        z-index: 1000;
        animation: slideIn 0.3s ease-out;
        cursor: pointer;
        max-width: 350px;
        backdrop-filter: blur(12px);
        border: 1px solid;
    `;

    if (type === 'success') {
        notification.style.background = 'rgba(0, 255, 136, 0.15)';
        notification.style.color = '#00ff88';
        notification.style.borderColor = 'rgba(0, 255, 136, 0.3)';
    } else if (type === 'warning') {
        notification.style.background = 'rgba(255, 170, 0, 0.15)';
        notification.style.color = '#ffaa00';
        notification.style.borderColor = 'rgba(255, 170, 0, 0.3)';
    } else if (type === 'error') {
        notification.style.background = 'rgba(255, 68, 68, 0.15)';
        notification.style.color = '#ff4444';
        notification.style.borderColor = 'rgba(255, 68, 68, 0.3)';
    }

    notification.onclick = () => notification.remove();
    document.body.appendChild(notification);

    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.opacity = '0';
            notification.style.transition = 'opacity 0.3s';
            setTimeout(() => notification.remove(), 300);
        }
    }, 3000);
}

// ---- Ağ Cihazları Tarama ----

function runNetworkScan() {
    const btn = document.getElementById('scan-btn');
    const list = document.getElementById('scanner-list');
    
    btn.disabled = true;
    btn.textContent = 'Taranıyor...';
    list.innerHTML = '<div class="ban-empty">Ağ taranıyor, lütfen bekleyin...</div>';
    
    fetch('/api/scan', { method: 'POST', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
        .then(r => r.json())
        .then(data => {
            if (!data.success) {
                showNotification('Tarama başlatılamadı: ' + data.error, 'error');
                btn.disabled = false;
                btn.textContent = 'Taramayı Başlat';
            } else {
                showNotification('Ağ taraması başladı', 'success');
            }
        })
        .catch(err => {
            showNotification('Tarama hatası: ' + err, 'error');
            btn.disabled = false;
            btn.textContent = 'Taramayı Başlat';
        });
}

// Socket event for scan completion is handled at the top

function renderDeviceList(records) {
    const list = document.getElementById('scanner-list');
    if (!records || records.length === 0) {
        list.innerHTML = '<div class="ban-empty">Ağda cihaz bulunamadı.</div>';
        return;
    }

    let html = '';
    let counter = 1;
    
    records.forEach(device => {
        // Kendi IP'sini (gateway) veya boş olanları atla
        if (!device.ip_address || !device.mac_address) return;
        
        let vendor = escapeHtml(device.vendor || 'Bilinmiyor');
        let hostname = escapeHtml(device.hostname || 'Bilinmiyor');
        let osType = escapeHtml(device.os_type || 'Bilinmiyor');
        let score = device.threat_score || 0;
        
        let scoreColor = '#8892b0';
        if (score > 20) scoreColor = '#ff4444';
        else if (score > 0) scoreColor = '#ffaa00';
        
        // Aktif / Pasif (15 Dakika sınırı)
        let lastSeenDate = new Date(device.last_seen.replace(' ', 'T') + 'Z');
        let isInactive = (new Date() - lastSeenDate) > 15 * 60 * 1000;
        let statusBadge = isInactive ? '<span style="color: #8892b0; font-size: 0.8rem; margin-left: 10px;">⚪ Pasif</span>' : '<span style="color: #64ffda; font-size: 0.8rem; margin-left: 10px;">🟢 Aktif</span>';
        
        html += `
        <div class="ban-item" style="border-left: 3px solid ${isInactive ? '#444' : (score > 20 ? '#ff4444' : '#00f0ff')}; flex-direction: column; align-items: flex-start; padding: 10px; opacity: ${isInactive ? '0.6' : '1'};">
            <div style="display: flex; justify-content: space-between; width: 100%; margin-bottom: 5px;">
                <span class="mono" style="font-size: 1rem; font-weight: bold; color: #e6f1ff;">${escapeHtml(device.ip_address)} ${statusBadge}</span>
                <button class="btn btn-sm btn-danger" onclick="quickBan('${escapeAttr(device.ip_address)}', '${escapeAttr(device.mac_address)}')">
                    Engelle
                </button>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 5px; width: 100%; font-size: 0.85rem; color: #a8b2d1;">
                <div><span style="color: #64ffda;">MAC:</span> ${escapeHtml(device.mac_address)}</div>
                <div><span style="color: #64ffda;">OS Tipi:</span> ${osType}</div>
                <div><span style="color: #64ffda;">Marka:</span> ${vendor}</div>
                <div><span style="color: #64ffda;">Hostname:</span> ${hostname}</div>
                <div><span style="color: #64ffda;">Son Görülme:</span> ${lastSeenDate.toLocaleString()}</div>
                <div><span style="color: #64ffda;">Tehdit Skoru:</span> <strong style="color: ${scoreColor}">${score}</strong></div>
            </div>
        </div>
        `;
        counter++;
    });
    
    list.innerHTML = html || '<div class="ban-empty">Geçerli cihaz bulunamadı.</div>';
}

function quickBan(ip, mac) {
    document.getElementById('ban-ip').value = ip;
    document.getElementById('ban-mac').value = mac;
    document.getElementById('ban-reason').value = 'Web Panel Hızlı Ban';
    addBan();
}

// ---- Yardımcı Fonksiyonlar ----

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function escapeAttr(text) {
    if (!text) return '';
    return text.replace(/'/g, "\\'").replace(/"/g, '\\"');
}

// ---- Ayarlar (Settings) Yönetimi ----
function openSettings() {
    fetch('/api/settings', {credentials: 'same-origin'})
        .then(r => r.json())
        .then(data => {
            document.getElementById('setting-discord').value = data.discord_webhook || '';
            document.getElementById('setting-telegram-token').value = data.telegram_token || '';
            document.getElementById('setting-telegram-chat').value = data.telegram_chat_id || '';
            document.getElementById('settings-modal').style.display = 'block';
        })
        .catch(err => showNotification('Ayarlar yüklenemedi: ' + err, 'error'));
}

function closeSettings() {
    document.getElementById('settings-modal').style.display = 'none';
}

function saveSettings() {
    const data = {
        discord_webhook: document.getElementById('setting-discord').value.trim(),
        telegram_token: document.getElementById('setting-telegram-token').value.trim(),
        telegram_chat_id: document.getElementById('setting-telegram-chat').value.trim()
    };
    
    fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
        credentials: 'same-origin',
        body: JSON.stringify(data)
    })
    .then(r => r.json())
    .then(res => {
        if(res.success) {
            showNotification('Ayarlar kaydedildi.', 'success');
            closeSettings();
        } else {
            showNotification('Kaydetme hatası: ' + res.error, 'error');
        }
    })
    .catch(err => showNotification('Kaydetme hatası: ' + err, 'error'));
}

// ---- Canlı Ağ Haritası (Vis.js) ----
let network = null;
let nodes = new vis.DataSet();
let edges = new vis.DataSet();

function initNetworkMap() {
    const container = document.getElementById('network-map');
    if (!container) return;

    // Varsayılan Gateway/Modem node'u
    nodes.add({ id: 'gateway', label: '🌐 Modem / Gateway\n(Ağ Geçidi)', shape: 'dot', size: 25, color: '#64ffda', font: { color: '#e6f1ff' }});
    
    const data = { nodes: nodes, edges: edges };
    const options = {
        nodes: { font: { color: '#8892b0' }, shape: 'dot', size: 20 },
        edges: { width: 2, color: { color: '#233554', highlight: '#64ffda' }, smooth: { type: 'continuous' } },
        physics: { stabilization: false, barnesHut: { gravitationalConstant: -3000, springLength: 100 } },
        interaction: { hover: true, tooltipDelay: 100 }
    };
    
    network = new vis.Network(container, data, options);
    
    // Tıklanabilir Harita (Interactive Map) Menüsü
    network.on("click", function (params) {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0]; // IP adresi
            const nodeData = nodes.get(nodeId);
            const contextMenu = document.getElementById('map-context-menu');
            
            // Eğer modem ise menü gösterme
            if (nodeId.endsWith('.1') && nodeData.label.includes('Modem')) return;
            
            const header = document.getElementById('context-header');
            header.innerHTML = `Hedef: ${escapeHtml(nodeId)}<br><span style="color:#ffaa00; font-size: 0.8rem;">${escapeHtml(nodeData.title.split('\\n')[0])}</span>`;
            
            const btn = document.getElementById('btn-context-ban');
            btn.onclick = function() {
                const macMatch = nodeData.title.match(/MAC: ([a-f0-9:]+)/i);
                const mac = macMatch ? macMatch[1] : '';
                quickBan(nodeId, mac);
                contextMenu.style.display = 'none';
            };
            
            // Fare pozisyonuna göre menüyü konumlandır
            const mapRect = container.getBoundingClientRect();
            const pointer = params.pointer.DOM;
            contextMenu.style.left = (mapRect.left + pointer.x + window.scrollX + 10) + 'px';
            contextMenu.style.top = (mapRect.top + pointer.y + window.scrollY - 10) + 'px';
            contextMenu.style.display = 'block';
        } else {
            document.getElementById('map-context-menu').style.display = 'none';
        }
    });
}

function updateNetworkMap(records) {
    if (!network) return;
    
    records.forEach(device => {
        if (!device.ip_address || device.ip_address === 'N/A') return;
        
        const ip = device.ip_address;
        const vendor = device.vendor || 'Bilinmiyor';
        const os = device.os_type || 'Bilinmiyor';
        
        // Aktif / Pasif (15 Dakika)
        let lastSeenDate = new Date(device.last_seen.replace(' ', 'T') + 'Z');
        let isInactive = (new Date() - lastSeenDate) > 15 * 60 * 1000;

        // Node rengini tehlikeye göre belirle
        let color = '#8892b0';
        if (isInactive) color = '#444444'; // Pasif cihaz gri
        else if (device.threat_score > 20) color = '#ff4444'; // Kırmızı (Tehlike)
        else if (device.threat_score > 0) color = '#ffaa00'; // Sarı (Şüpheli)
        else color = '#64ffda'; // Yeşil (Güvenli)
        
        let iconCode = '💻';
        if (isInactive) iconCode = '💤';
        else if (os.toLowerCase().includes('apple') || os.toLowerCase().includes('iphone')) iconCode = '📱';
        else if (os.toLowerCase().includes('android')) iconCode = '📱';
        else if (vendor.toLowerCase().includes('router')) iconCode = '🌐';
        
        if (!nodes.get(ip)) {
            nodes.add({
                id: ip,
                label: `${iconCode} ${ip}`,
                title: `MAC: ${device.mac_address}\nMarka: ${vendor}\nOS: ${os}`,
                shape: 'dot',
                size: 20,
                color: color,
                font: { color: '#e6f1ff' }
            });
            // Gateway'e bağla
            edges.add({ id: `edge_${ip}`, from: ip, to: 'gateway', color: '#233554' });
        } else {
            // Rengi güncelle
            nodes.update({ id: ip, color: color });
        }
    });
}

function drawAttackLaser(src_ip, dst_ip, severity) {
    if (!network || !src_ip || src_ip === 'N/A') return;
    
    const target = (dst_ip && dst_ip !== 'N/A') ? dst_ip : 'gateway'; // Hedef yoksa modeme saldırmış say
    
    // Node yoksa geçici oluştur
    if (!nodes.get(src_ip)) {
        nodes.add({ id: src_ip, label: src_ip, shape: 'dot', color: '#ff4444' });
    }
    if (!nodes.get(target)) {
        nodes.add({ id: target, label: target, shape: 'dot', color: '#8892b0' });
    }
    
    // Lazer rengi
    const laserColor = severity === 'critical' ? '#ff0000' : (severity === 'high' ? '#ff4444' : '#ffaa00');
    const edgeId = `laser_${src_ip}_${target}_${Date.now()}`;
    
    // Saldırganın üstüne ünlem ekle
    const attackerNode = nodes.get(src_ip);
    if (attackerNode && !attackerNode.label.includes('⚠️')) {
        nodes.update({ id: src_ip, label: '⚠️ ' + attackerNode.label });
    }
    
    // Saldırı oku çiz
    edges.add({
        id: edgeId,
        from: src_ip,
        to: target,
        color: { color: laserColor, highlight: laserColor },
        width: 4,
        arrows: 'to',
        dashes: [5, 5]
    });
    
    // Lazer animasyonu (Kısa süre sonra sil)
    setTimeout(() => {
        if (edges.get(edgeId)) {
            edges.remove(edgeId);
        }
    }, 1500); // 1.5 saniye ekranda kalır
}

// Sayfa yüklenince haritayı başlat
document.addEventListener('DOMContentLoaded', () => {
    // delay for vis network load
    setTimeout(initNetworkMap, 500);
});
