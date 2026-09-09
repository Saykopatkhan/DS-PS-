import re

with open('/home/kali/İndirilenler/ds_ips_project/web/static/style.css', 'r', encoding='utf-8') as f:
    css = f.read()

# 1. Stats Row Fix
css = re.sub(
    r'\.stats-row\s*\{\s*display:\s*grid;\s*grid-template-columns:\s*repeat\(4,\s*1fr\);\s*gap:\s*1rem;\s*\}',
    '.stats-row {\n    display: grid;\n    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));\n    gap: 1rem;\n}',
    css
)
css = re.sub(r'@media\s*\(\s*max-width:\s*900px\s*\)\s*\{\s*\.stats-row\s*\{\s*grid-template-columns:\s*repeat\(2,\s*1fr\);\s*\}\s*', '@media (max-width: 900px) {\n    ', css)
css = re.sub(r'@media\s*\(\s*max-width:\s*600px\s*\)\s*\{\s*\.stats-row\s*\{\s*grid-template-columns:\s*1fr;\s*\}\s*', '@media (max-width: 600px) {\n    ', css)

# New CSS to append
new_css = """
/* ============================================
   NEW STYLES (Added per user request)
   ============================================ */

/* ---- SOC Panels ---- */
.soc-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-bottom: 1rem;
}
.soc-panel {
    background: var(--bg-card);
    backdrop-filter: blur(20px);
    border: 1px solid var(--border-light);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    display: flex;
    flex-direction: column;
    overflow: hidden;
}
.soc-panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem 1.5rem;
    background: rgba(0, 0, 0, 0.2);
    border-bottom: 1px solid var(--border-light);
}
.soc-panel-body {
    padding: 1.5rem;
    flex: 1;
    position: relative;
    display: flex;
    flex-direction: column;
}
.soc-tabs {
    display: flex;
    gap: 0.5rem;
}
.soc-tab {
    background: transparent;
    border: none;
    color: var(--text-muted);
    font-size: 0.8rem;
    font-weight: 600;
    padding: 0.4rem 0.8rem;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    transition: all 0.3s ease;
}
.soc-tab:hover {
    color: var(--text-primary);
}
.soc-tab.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
}

/* ---- Cyber Radar ---- */
.radar-container {
    position: relative;
    width: 100%;
    aspect-ratio: 1;
    max-height: 350px;
    margin: 0 auto;
    border-radius: 50%;
    overflow: hidden;
    background: radial-gradient(circle, rgba(0,255,136,0.1) 0%, rgba(10,15,29,0.8) 70%);
    border: 1px solid rgba(0, 255, 136, 0.2);
}
.radar-canvas {
    width: 100%;
    height: 100%;
}
.radar-overlay {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    font-family: var(--font-mono);
    color: rgba(0, 255, 136, 0.6);
    font-size: 0.75rem;
    pointer-events: none;
    text-align: center;
}
.radar-overlay::before {
    content: '';
    position: absolute;
    top: -175px; left: -175px;
    width: 350px; height: 350px;
    border-radius: 50%;
    border-top: 2px solid rgba(0, 255, 136, 0.8);
    animation: radarSweep 4s linear infinite;
}
.radar-legend {
    position: absolute;
    bottom: 10px;
    right: 10px;
    background: rgba(0,0,0,0.6);
    padding: 0.5rem;
    border-radius: 8px;
    font-size: 0.65rem;
    color: var(--text-muted);
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
}

/* ---- Geographic Threat Map (Leaflet) ---- */
.geo-map-container {
    width: 100%;
    height: 350px;
    border-radius: 12px;
    overflow: hidden;
}
.leaflet-container {
    background: #0a0f1d !important;
}
.leaflet-tile-pane {
    filter: brightness(0.6) invert(1) contrast(3) hue-rotate(200deg) saturate(0.3) brightness(0.7);
}
.leaflet-control-zoom a {
    background: rgba(10,15,29,0.8) !important;
    color: #ffd700 !important;
    border-color: rgba(255,215,0,0.2) !important;
}
.leaflet-popup-content-wrapper {
    background: rgba(10,15,29,0.95) !important;
    color: #f0f4f8 !important;
    border: 1px solid rgba(255,215,0,0.2);
    border-radius: 12px !important;
}
.leaflet-popup-tip {
    background: rgba(10,15,29,0.95) !important;
}

/* ---- Network Map (Vis.js) ---- */
.network-map-container {
    background: var(--bg-card);
    backdrop-filter: blur(20px);
    border: 1px solid var(--border-light);
    border-radius: var(--radius);
    padding: 1rem;
    position: relative;
}
#network-map {
    width: 100%;
    height: 400px;
    border-radius: 12px;
    background: rgba(0,0,0,0.2);
}
.map-controls {
    position: absolute;
    top: 1.5rem;
    right: 1.5rem;
    display: flex;
    gap: 0.5rem;
}
.map-context-menu {
    position: absolute;
    background: rgba(15, 25, 45, 0.95);
    backdrop-filter: blur(10px);
    border: 1px solid var(--border-light);
    border-radius: 8px;
    padding: 0.5rem 0;
    box-shadow: var(--shadow);
    z-index: 1000;
}
.map-context-menu .menu-item {
    padding: 0.5rem 1rem;
    font-size: 0.8rem;
    color: var(--text-primary);
    cursor: pointer;
    transition: background 0.2s;
}
.map-context-menu .menu-item:hover {
    background: rgba(255, 215, 0, 0.15);
}

/* ---- DPI/SNI Widget ---- */
.dpi-panel {
    background: var(--bg-card);
    backdrop-filter: blur(20px);
    border: 1px solid var(--border-light);
    border-radius: var(--radius);
    padding: 1.5rem;
    margin-bottom: 1rem;
}
.dpi-feed {
    max-height: 300px;
    overflow-y: auto;
    font-family: var(--font-mono);
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
}
.dpi-entry {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.75rem 1rem;
    background: rgba(10, 15, 29, 0.5);
    border-radius: 8px;
    border: 1px solid rgba(255,255,255,0.02);
}
.dpi-entry.new {
    animation: dpiGlow 1s ease-out;
}
.protocol-badge {
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    font-size: 0.65rem;
    font-weight: 700;
}
.protocol-badge.tls {
    background: rgba(0,212,255,0.15);
    color: #00d4ff;
}
.protocol-badge.dns {
    background: rgba(0,255,136,0.15);
    color: #00ff88;
}
.protocol-badge.http {
    background: rgba(255,184,0,0.15);
    color: #ffb800;
}
.category-tag {
    font-size: 0.65rem;
    color: var(--text-muted);
    background: rgba(255,255,255,0.05);
    padding: 0.2rem 0.4rem;
    border-radius: 4px;
}
@keyframes dpiGlow {
    from { background: rgba(0,255,136,0.15); }
    to { background: rgba(10, 15, 29, 0.5); }
}

/* ---- Anti-MITM Healing Card ---- */
.healing-card {
    position: relative;
    overflow: hidden;
}
.healing-indicator {
    font-size: 2rem;
    color: #ff2a2a;
}
.healing-indicator.active {
    animation: heartbeat 1.5s ease-in-out infinite;
    color: #00ff88;
    text-shadow: 0 0 15px rgba(0,255,136,0.6);
}
@keyframes heartbeat {
    0%, 100% { transform: scale(1); }
    50% { transform: scale(1.15); }
}

/* ---- Sound Controls ---- */
.sound-control {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-left: 1rem;
}
.sound-btn {
    background: transparent;
    border: none;
    color: var(--text-primary);
    cursor: pointer;
    font-size: 1.1rem;
}
.sound-btn.muted {
    opacity: 0.4;
}
.volume-slider {
    width: 60px;
    height: 4px;
    -webkit-appearance: none;
    background: rgba(255,255,255,0.2);
    border-radius: 2px;
    outline: none;
}
.volume-slider::-webkit-slider-thumb {
    -webkit-appearance: none;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: var(--accent);
    cursor: pointer;
}

/* ---- Risk Center ---- */
.risk-center {
    position: relative;
    width: 200px;
    height: 200px;
    margin: 0 auto;
    display: flex;
    align-items: center;
    justify-content: center;
}
.risk-gauge {
    position: absolute;
    width: 100%;
    height: 100%;
}
.risk-score {
    font-family: var(--font-mono);
    font-size: 2.5rem;
    font-weight: 700;
    color: var(--danger);
    text-shadow: 0 0 15px rgba(255,42,42,0.5);
    z-index: 1;
}

/* ---- PCAP Recording Indicator ---- */
.pcap-indicator {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    background: rgba(0,0,0,0.3);
    padding: 0.4rem 0.8rem;
    border-radius: 20px;
    border: 1px solid rgba(255,255,255,0.05);
}
.pcap-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
}
.pcap-dot.recording {
    background: #ff2a2a;
    animation: pulse 1.5s infinite;
    box-shadow: 0 0 8px rgba(255,42,42,0.6);
}
.pcap-dot.ready {
    background: #5c728a;
}
.pcap-indicator span {
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--text-primary);
}

/* ---- General Traffic Table ---- */
.traffic-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 1rem;
}
.traffic-table th {
    text-align: left;
    padding: 0.75rem;
    font-size: 0.75rem;
    text-transform: uppercase;
    color: var(--text-muted);
    border-bottom: 1px solid var(--border-light);
}
.traffic-table td {
    padding: 0.75rem;
    font-size: 0.85rem;
    color: var(--text-primary);
    border-bottom: 1px solid rgba(255,255,255,0.02);
}
.traffic-table tr:hover {
    background: rgba(255, 215, 0, 0.05);
}
.device-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.2rem 0.6rem;
    background: rgba(255,255,255,0.05);
    border-radius: 12px;
    font-size: 0.75rem;
}
.threat-score {
    font-family: var(--font-mono);
    font-weight: 700;
}
.threat-score.safe { color: #00ff88; }
.threat-score.warning { color: #ffb800; }
.threat-score.danger { color: #ff2a2a; }

/* ---- Modals ---- */
.modal-overlay {
    position: fixed;
    top: 0; left: 0;
    width: 100%; height: 100%;
    background: rgba(0, 0, 0, 0.7);
    backdrop-filter: blur(5px);
    z-index: 1000;
    display: flex;
    align-items: center;
    justify-content: center;
    opacity: 0;
    pointer-events: none;
    transition: opacity 0.3s ease;
}
.modal-overlay.active {
    opacity: 1;
    pointer-events: auto;
}
.modal-content {
    background: var(--bg-card);
    border: 1px solid var(--border-light);
    border-radius: var(--radius);
    width: 90%;
    max-width: 500px;
    box-shadow: var(--shadow-lg);
    transform: translateY(20px);
    transition: transform 0.3s ease;
}
.modal-overlay.active .modal-content {
    transform: translateY(0);
}
.modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1.25rem 1.5rem;
    border-bottom: 1px solid var(--border-light);
}
.modal-header h3 {
    font-size: 1.1rem;
    color: var(--text-primary);
}
.modal-close {
    background: none;
    border: none;
    color: var(--text-muted);
    font-size: 1.2rem;
    cursor: pointer;
}
.modal-close:hover {
    color: var(--text-primary);
}
.modal-body {
    padding: 1.5rem;
}
.modal-footer {
    padding: 1.25rem 1.5rem;
    border-top: 1px solid var(--border-light);
    display: flex;
    justify-content: flex-end;
    gap: 1rem;
}

/* ---- Traffic Modal (Wider) ---- */
.traffic-modal {
    max-width: 800px;
}
.traffic-log-table {
    width: 100%;
    border-collapse: collapse;
}
.traffic-log-entry td {
    padding: 0.6rem;
    font-size: 0.8rem;
    border-bottom: 1px solid rgba(255,255,255,0.05);
}
.traffic-log-entry.highlight {
    animation: dpiGlow 1s ease-out;
}

/* ---- Alert Filter Buttons ---- */
.alert-filters {
    display: flex;
    gap: 0.5rem;
}
.filter-btn {
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.1);
    color: var(--text-secondary);
    padding: 0.3rem 0.8rem;
    border-radius: 12px;
    font-size: 0.75rem;
    cursor: pointer;
    transition: all 0.2s ease;
}
.filter-btn:hover {
    background: rgba(255,255,255,0.1);
    color: var(--text-primary);
}
.filter-btn.active {
    background: var(--accent);
    color: var(--bg-primary);
    border-color: var(--accent);
}

/* ---- Additional Animations ---- */
@keyframes radarSweep {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
}
@keyframes scanLine {
    0% { top: 0; }
    100% { top: 100%; }
}
@keyframes glowPulse {
    0%, 100% { box-shadow: 0 0 5px var(--accent-dim); }
    50% { box-shadow: 0 0 20px var(--accent-glow); }
}

/* ---- Header Buttons ---- */
.header-btn {
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.1);
    color: var(--text-primary);
    padding: 0.5rem 1rem;
    border-radius: 8px;
    font-size: 0.85rem;
    cursor: pointer;
    transition: all 0.3s ease;
}
.header-btn:hover {
    border-color: var(--accent);
    box-shadow: 0 0 10px var(--accent-dim);
}
.header-btn.premium {
    background: linear-gradient(135deg, rgba(218,165,32,0.2) 0%, rgba(255,215,0,0.05) 100%);
    border: 1px solid rgba(255,215,0,0.3);
    color: var(--accent);
}
.header-btn.premium:hover {
    box-shadow: 0 0 15px var(--accent-glow);
    background: linear-gradient(135deg, rgba(218,165,32,0.3) 0%, rgba(255,215,0,0.1) 100%);
}
"""

with open('/home/kali/İndirilenler/ds_ips_project/web/static/style.css', 'w', encoding='utf-8') as f:
    f.write(css + new_css)
