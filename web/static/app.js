/**
 * DS IPS Dashboard - Frontend JavaScript
 * SocketIO ile gerçek zamanlı alarm akışı, istatistik güncellemesi ve kontrol paneli.
 */

let socket = null;
const HIDS_TYPES = {
  sqli: ["SQL_INJECTION"],
  rce: ["RCE_COMMAND_INJ"],
  lfi: ["LFI_DIR_TRAVERSAL"],
  ssh: ["SSH_BRUTE_FORCE"],
  scanner: ["SCANNER_USER_AGENT", "WEB DIR-BRUTEFORCE"],
  xss: ["XSS_REFLECTED"],
  ddos: ["HTTP_DDOS", "WEB L7 DOS / FLOOD"],
};
const alertCanvas = document.getElementById("alertChart");
const alertChart =
  alertCanvas && typeof Chart !== "undefined"
    ? new Chart(alertCanvas, {
        type: "doughnut",
        data: {
          labels: ["Kritik", "Yüksek", "Orta", "Düşük/Bilgi"],
          datasets: [
            {
              data: [0, 0, 0, 0],
              backgroundColor: ["#eb7b86", "#e9b970", "#8293ff", "#72829e"],
              borderWidth: 0,
              hoverOffset: 3,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: "86%",
          animation: false,
          plugins: {
            legend: { display: false },
            tooltip: { backgroundColor: "#202b42", padding: 12 },
          },
        },
      })
    : null;

// DS-01: Fetch WS Token before connecting
apiFetch("/api/ws_token", {
  headers: { "X-Requested-With": "XMLHttpRequest" },
  credentials: "same-origin",
})
  .then((r) => {
    if (!r.ok) throw new Error("Token fetch failed");
    return r.json();
  })
  .then((tokenData) => {
    socket = io({ auth: { token: tokenData.token } });

    socket.on("connect", () => {
      console.log("[DS IPS] WebSocket bağlantısı kuruldu");
      socket.emit("request_stats");
      fetchRecordsForTrafficList();
    });

    socket.on("disconnect", () => {
      console.log("[DS IPS] WebSocket bağlantısı kesildi");
      const radarState = document.getElementById("radar-state");
      if (radarState) radarState.textContent = "Canlı bağlantı kesildi";
      const badge = document.getElementById("status-badge");
      if (badge) {
        badge.className = "status-badge";
        badge.querySelector(".status-text").textContent = "Bağlantı Kesildi";
      }
    });

    socket.on("new_alert", (data) => {
      addAlertToFeed(data, true);
      const el = document.getElementById("total-alerts");
      if (el) el.textContent = parseInt(el.textContent) + 1;

      if (typeof drawAttackLaser === "function") {
        drawAttackLaser(data.source_ip, data.destination_ip, data.severity);
      }

      // Radar blip ekle
      const radarLabel = data.source_ip || data.alert_type || "Tehdit";
      addRadarBlip(radarLabel, data.severity);

      // Coğrafi harita pin ekle
      addGeoPin(data.source_ip, data.severity, data.alert_type);

      // HIDS Modül Kart Sayacı Güncelleme
      const alertType = (data.type || data.alert_type || "").toUpperCase();
      const category = Object.keys(HIDS_TYPES).find((key) =>
        HIDS_TYPES[key].includes(alertType),
      );
      if (category) {
        const counter = document.getElementById("hids-" + category);
        if (counter)
          counter.textContent = (Number(counter.textContent) || 0) + 1;
        const total = document.getElementById("hids-alerts");
        if (total) total.textContent = (Number(total.textContent) || 0) + 1;
      }

      // ipset engel sayacını güncelle (ban olursa)
      if (alertType.includes("BAN") || alertType.includes("BLOCK")) {
        const ipsetEl = document.getElementById("ipset-blocks");
        if (ipsetEl) ipsetEl.innerText = parseInt(ipsetEl.innerText || 0) + 1;
        const ipsetTotalEl = document.getElementById("ipset-total");
        if (ipsetTotalEl)
          ipsetTotalEl.innerText = parseInt(ipsetTotalEl.innerText || 0) + 1;
      }

      if (data.severity === "critical" || data.severity === "high")
        playAlertSound(data.severity);

      // Anti-MITM Healing Update
      if (data.alert_type && data.alert_type.includes("HEALING")) {
        const healingCount = document.getElementById("healing-count");
        if (healingCount)
          healingCount.innerText = parseInt(healingCount.innerText || 0) + 1;
        const healingInd = document.getElementById("healing-indicator");
        if (healingInd) {
          healingInd.style.filter = "grayscale(0%)";
          healingInd.classList.add("active");
          setTimeout(() => {
            healingInd.style.filter = "grayscale(100%)";
            healingInd.classList.remove("active");
          }, 2000);
        }
      }
    });

    socket.on("new_dns_log", (data) => {
      if (typeof appendTrafficLog === "function") {
        appendTrafficLog(data);
      }
    });

    socket.on("stats_update", (data) => {
      updateStats(data);

      // ipset ve ban sayacı güncelleme (Faz 1)
      if (data.active_bans !== undefined) {
        const ipsetActiveEl = document.getElementById("ipset-active");
        if (ipsetActiveEl) ipsetActiveEl.innerText = data.active_bans;
        const ipsetBlocksEl = document.getElementById("ipset-blocks");
        if (ipsetBlocksEl) ipsetBlocksEl.innerText = data.active_bans;
      }
    });

    socket.on("status_update", (data) => {
      updateRunningStatus(data.running);
    });

    socket.on("ban_update", (data) => {
      apiFetch("/api/bans", { credentials: "same-origin" })
        .then((r) => r.json())
        .then((bans) => renderBanList(bans));

      const el = document.getElementById("active-bans");
      if (el) {
        if (data.action === "added") {
          el.textContent = parseInt(el.textContent || 0) + 1;
        } else {
          el.textContent = Math.max(0, parseInt(el.textContent || 0) - 1);
        }
      }
    });

    socket.on("scan_complete", (data) => {
      const btn = document.getElementById("scan-btn");
      const list = document.getElementById("scanner-list");

      if (btn) {
        btn.disabled = false;
        btn.textContent = "Taramayı Başlat";
      }

      if (data.success && data.records) {
        renderDeviceList(data.records);
        showNotification("Tarama tamamlandı", "success");

        // Haritayı güncelle
        if (typeof updateNetworkMap === "function") {
          updateNetworkMap(data.records);
        }
      }
    });
  })
  .catch((err) => {
    console.error("Socket.io başlatılamadı:", err);
  });

// Durum değişkenleri
let isRunning = false;
const MAX_ALERTS_DISPLAY = 100;
let currentAlertFilter = "all"; // all, critical, warning

// Ses Kontrolü
let audioCtx = null;
let soundEnabled = false;

function initAudio() {
  if (!audioCtx) {
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  }
}

function toggleSound() {
  initAudio();
  soundEnabled = !soundEnabled;
  const btn = document.getElementById("sound-toggle-btn");
  if (soundEnabled) {
    btn.textContent = "Ses açık";
    btn.setAttribute("aria-pressed", "true");
    btn.classList.remove("muted");
    if (audioCtx.state === "suspended") audioCtx.resume();
    showNotification("Sesli bildirimler açıldı", "success");
  } else {
    btn.textContent = "Ses kapalı";
    btn.setAttribute("aria-pressed", "false");
    btn.classList.add("muted");
    showNotification("Sesli bildirimler kapatıldı", "warning");
  }
}

function playAlertSound(severity) {
  if (!soundEnabled || !audioCtx) return;
  const value = parseFloat(document.getElementById("volume-slider").value);
  const vol = Number.isFinite(value) ? value : 0.5;
  const osc = audioCtx.createOscillator();
  const gainNode = audioCtx.createGain();

  osc.connect(gainNode);
  gainNode.connect(audioCtx.destination);

  if (severity === "critical") {
    osc.type = "sawtooth";
    osc.frequency.setValueAtTime(440, audioCtx.currentTime); // A4
    osc.frequency.linearRampToValueAtTime(880, audioCtx.currentTime + 0.1);
    gainNode.gain.setValueAtTime(vol, audioCtx.currentTime);
    gainNode.gain.exponentialRampToValueAtTime(
      0.01,
      audioCtx.currentTime + 0.5,
    );
    osc.start();
    osc.stop(audioCtx.currentTime + 0.5);
  } else {
    osc.type = "sine";
    osc.frequency.setValueAtTime(600, audioCtx.currentTime);
    gainNode.gain.setValueAtTime(vol * 0.5, audioCtx.currentTime);
    gainNode.gain.exponentialRampToValueAtTime(
      0.01,
      audioCtx.currentTime + 0.3,
    );
    osc.start();
    osc.stop(audioCtx.currentTime + 0.3);
  }
}

// =============================================
// Canvas Radar Animasyonu
// =============================================
let radarAngle = 0;
let radarCanvas = null;
let radarCtx = null;
let radarBlips = []; // {x, y, label, severity, age}
let radarFrame = null;
let radarVisible = true;
let radarLastFrame = null;
let radarExpiryTimer = null;
const radarMotion = matchMedia("(prefers-reduced-motion: reduce)");
function refreshRadar() {
  if (radarFrame !== null) cancelAnimationFrame(radarFrame);
  radarFrame = null;
  radarLastFrame = null;
  drawRadar(performance.now());
}
radarMotion.addEventListener("change", refreshRadar);
document.addEventListener("visibilitychange", refreshRadar);

function initCanvasRadar() {
  radarCanvas = document.getElementById("radar-canvas");
  if (!radarCanvas) return;
  const parent = radarCanvas.parentElement;
  radarCanvas.width = parent.clientWidth;
  radarCanvas.height = parent.clientHeight;
  radarCtx = radarCanvas.getContext("2d");
  new ResizeObserver(() => {
    if (!parent.clientWidth || !parent.clientHeight) return;
    radarCanvas.width = parent.clientWidth;
    radarCanvas.height = parent.clientHeight;
    refreshRadar();
  }).observe(parent);
  new IntersectionObserver((entries) => {
    radarVisible = entries[0].isIntersecting;
    refreshRadar();
  }).observe(parent);
  refreshRadar();
}

function drawRadar(timestamp = performance.now()) {
  radarFrame = null;
  if (!radarCtx || !radarCanvas) return;
  const W = radarCanvas.width;
  const H = radarCanvas.height;
  const cx = W / 2;
  const cy = H / 2;
  const R = Math.max(1, Math.min(W, H) / 2 - 24);

  radarCtx.clearRect(0, 0, W, H);

  // Arka plan
  radarCtx.fillStyle = "#0d1523";
  radarCtx.fillRect(0, 0, W, H);

  // Izgara daireleri
  [1, 0.66, 0.33].forEach((f) => {
    radarCtx.beginPath();
    radarCtx.arc(cx, cy, R * f, 0, Math.PI * 2);
    radarCtx.strokeStyle = "rgba(130,147,255,0.18)";
    radarCtx.lineWidth = 1;
    radarCtx.stroke();
  });

  // Çapraz çizgiler
  [
    [0, Math.PI / 2],
    [Math.PI / 4, (3 * Math.PI) / 4],
  ].forEach(([a1, a2]) => {
    radarCtx.beginPath();
    radarCtx.moveTo(cx + Math.cos(a1) * R, cy + Math.sin(a1) * R);
    radarCtx.lineTo(
      cx + Math.cos(a1 + Math.PI) * R,
      cy + Math.sin(a1 + Math.PI) * R,
    );
    radarCtx.strokeStyle = "rgba(130,147,255,0.1)";
    radarCtx.stroke();
    radarCtx.beginPath();
    radarCtx.moveTo(cx + Math.cos(a2) * R, cy + Math.sin(a2) * R);
    radarCtx.lineTo(
      cx + Math.cos(a2 + Math.PI) * R,
      cy + Math.sin(a2 + Math.PI) * R,
    );
    radarCtx.stroke();
  });

  // Sweep gradient
  radarCtx.save();
  radarCtx.translate(cx, cy);
  radarCtx.rotate(radarAngle);
  // Sweep koni - Manuel çizim
  for (let a = 0; a <= Math.PI * 0.55; a += 0.015) {
    radarCtx.beginPath();
    radarCtx.moveTo(0, 0);
    radarCtx.arc(0, 0, R, -a, -a + 0.02);
    const alpha = (1 - a / (Math.PI * 0.55)) * (isRunning ? 0.24 : 0.05);
    radarCtx.fillStyle = `rgba(130,147,255,${alpha})`;
    radarCtx.fill();
  }
  radarCtx.restore();

  // Sweep çizgisi
  radarCtx.beginPath();
  radarCtx.moveTo(cx, cy);
  radarCtx.lineTo(cx + Math.cos(radarAngle) * R, cy + Math.sin(radarAngle) * R);
  radarCtx.strokeStyle = "rgba(130,147,255,0.9)";
  radarCtx.lineWidth = 1;
  radarCtx.stroke();

  // Merkez nokta
  radarCtx.beginPath();
  radarCtx.arc(cx, cy, 3, 0, Math.PI * 2);
  radarCtx.fillStyle = "#8293ff";
  radarCtx.fill();

  // Blip'leri çiz
  radarBlips = radarBlips.filter((b) => Date.now() - b.created < 4000);
  radarBlips.forEach((b) => {
    const x = cx + b.x * R;
    const y = cy + b.y * R;
    const alpha = radarMotion.matches
      ? 1
      : Math.max(0, 1 - (Date.now() - b.created) / 4000);
    let color = `rgba(255,180,0,${alpha})`; // warning (sarı)
    let glowR = 12;
    if (b.severity === "critical") {
      color = `rgba(255,50,50,${alpha})`; // critical (kırmızı)
      glowR = 20;
    } else if (b.severity === "low") {
      color = `rgba(0,200,255,${alpha})`; // low / info (mavi)
      glowR = 8;
    }

    // Glow
    const grd = radarCtx.createRadialGradient(x, y, 0, x, y, glowR);
    grd.addColorStop(0, color);
    grd.addColorStop(1, "transparent");
    radarCtx.beginPath();
    radarCtx.arc(x, y, glowR, 0, Math.PI * 2);
    radarCtx.fillStyle = grd;
    radarCtx.fill();

    // Nokta
    radarCtx.beginPath();
    radarCtx.arc(x, y, 4, 0, Math.PI * 2);
    radarCtx.fillStyle = color;
    radarCtx.fill();

    // Etiket
    radarCtx.fillStyle = color;
    radarCtx.font = "9px monospace";
    radarCtx.fillText(b.label, Math.min(x + 7, W - 125), Math.max(12, y - 4));
  });

  const moving =
    isRunning && !radarMotion.matches && !document.hidden && radarVisible;
  if (moving) {
    if (radarLastFrame !== null)
      radarAngle =
        (radarAngle + Math.min(100, timestamp - radarLastFrame) * 0.00072) %
        (Math.PI * 2);
    radarLastFrame = timestamp;
  } else radarLastFrame = null;
  if (
    !radarMotion.matches &&
    !document.hidden &&
    radarVisible &&
    (moving || radarBlips.length)
  )
    radarFrame = requestAnimationFrame(drawRadar);
}

function addRadarBlip(label, severity) {
  const text = String(label || "Olay").substring(0, 20);
  const previous = radarBlips.find(
    (blip) => blip.label === text && Date.now() - blip.created < 4000,
  );
  const priority = {
    critical: 4,
    high: 3,
    medium: 2,
    warning: 2,
    low: 1,
    info: 0,
  };
  if (
    previous &&
    (priority[previous.severity] || 0) > (priority[severity] || 0)
  )
    severity = previous.severity;
  // Stable relative coordinates survive tab changes and canvas resizing.
  let hash = 0;
  for (const character of text)
    hash = (hash * 31 + character.charCodeAt(0)) >>> 0;
  const angle = ((hash % 360) * Math.PI) / 180;
  const radius = 0.25 + ((hash >>> 8) % 60) / 100;
  radarBlips = radarBlips.filter(
    (blip) => blip.label !== text && Date.now() - blip.created < 4000,
  );
  if (radarBlips.length >= 100) radarBlips.shift();
  radarBlips.push({
    x: Math.cos(angle) * radius,
    y: Math.sin(angle) * radius,
    label: text,
    severity,
    created: Date.now(),
  });
  if (radarFrame === null) refreshRadar();
  clearTimeout(radarExpiryTimer);
  radarExpiryTimer = setTimeout(refreshRadar, 4100);
}

// GeoIP harita pin ekle
const geoMarkers = {};
function addGeoPin(ip, severity, alertType) {
  if (
    !ip ||
    ip === "N/A" ||
    ip.startsWith("192.168") ||
    ip.startsWith("10.") ||
    ip.startsWith("172.") ||
    ip === "127.0.0.1"
  )
    return;
  if (geoMarkers[ip]) return; // Zaten pin var

  const color = severity === "critical" ? "#ff2a2a" : "#e9b970";

  apiFetch(`/api/geoip/${encodeURIComponent(ip)}`, {
    credentials: "same-origin",
  })
    .then((r) => r.json())
    .then((data) => {
      if (!geoMapInitialized || !geoMap) return;
      const lat = data.lat || 0;
      const lon = data.lon || 0;
      if (lat === 0 && lon === 0) return;

      const icon = L.divIcon({
        className: "custom-geo-marker",
        html: `<div style="background-color: ${color}; width: 12px; height: 12px; border-radius: 50%; box-shadow: 0 0 10px ${color}; border: 2px solid #0a192f;"></div>`,
        iconSize: [16, 16],
      });
      const marker = L.marker([lat, lon], { icon })
        .addTo(geoMap)
        .bindPopup(
          `<b style="color:${color}">${escapeHtml(alertType)}</b><br>${escapeHtml(ip)}<br>${escapeHtml(data.city || "")}, ${escapeHtml(data.country || "")}<br>${escapeHtml(data.isp || "")}`,
        );
      geoMarkers[ip] = marker;
    })
    .catch(() => {});
}

// =============================================
// Harita Sekmeleri
// =============================================
let geoMapInitialized = false;
let geoMap = null;

function switchMapTab(tab) {
  const tabRadar = document.getElementById("tab-radar");
  const tabGeo = document.getElementById("tab-geo");
  const radarView = document.getElementById("radar-view");
  const geoView = document.getElementById("geo-view");

  if (!radarView || !geoView) return;

  if (tab === "radar") {
    radarView.style.display = "block";
    geoView.style.display = "none";
    if (tabRadar) tabRadar.classList.add("active");
    if (tabGeo) tabGeo.classList.remove("active");
    // Radar canvas boyutunu yeniden ayarla
    setTimeout(() => {
      if (radarCanvas) {
        radarCanvas.width = radarCanvas.parentElement.clientWidth;
        radarCanvas.height = radarCanvas.parentElement.clientHeight;
        refreshRadar();
      }
    }, 50);
  } else {
    radarView.style.display = "none";
    geoView.style.display = "block";
    if (tabRadar) tabRadar.classList.remove("active");
    if (tabGeo) tabGeo.classList.add("active");

    // Leaflet haritayı GÖRÜNÜR hale geldikten sonra başlat
    setTimeout(() => {
      if (!geoMapInitialized) {
        if (typeof L === "undefined") {
          console.error("[DS IPS] Leaflet yüklenmedi!");
          const gv = document.getElementById("geo-view");
          if (gv)
            gv.innerHTML =
              '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#eb7b86;font-family:monospace;font-size:14px;">❌ Leaflet.js yüklenemedi - Sunucuyu yeniden başlatın</div>';
          return;
        }
        try {
          // Leaflet ikon yollarını düzelt
          L.Icon.Default.mergeOptions({
            iconUrl: "/static/images/marker-icon.png",
            iconRetinaUrl: "/static/images/marker-icon-2x.png",
            shadowUrl: "/static/images/marker-shadow.png",
          });
          geoMap = L.map("leaflet-map", {
            zoomControl: true,
            attributionControl: true,
            scrollWheelZoom: false,
            zoomAnimation: !radarMotion.matches,
            fadeAnimation: !radarMotion.matches,
          }).setView([30, 15], 2);
          apiFetch("/static/js/world.geojson")
            .then((response) => {
              if (!response.ok) throw new Error("Harita verisi alınamadı");
              return response.json();
            })
            .then((world) =>
              L.geoJSON(world, {
                interactive: false,
                style: {
                  color: "#46567b",
                  weight: 0.7,
                  fillColor: "#253453",
                  fillOpacity: 0.85,
                },
              }).addTo(geoMap),
            )
            .catch(() =>
              showNotification(
                "Ülke sınırları yüklenemedi. Sayfayı yenileyin.",
                "error",
              ),
            );
          geoMap.attributionControl.setPrefix(false);
          geoMap.attributionControl.addAttribution(
            'Ülke sınırları: <a href="https://www.naturalearthdata.com/">Natural Earth</a>',
          );
          geoMapInitialized = true;
          console.log("[DS IPS] Coğrafi harita başlatıldı ✓");
        } catch (e) {
          console.error("[DS IPS] Harita başlatma hatası:", e);
        }
      } else if (geoMap) {
        geoMap.invalidateSize();
      }
    }, 300);
  }
}

// DOM yüklendiğinde
document.addEventListener("DOMContentLoaded", () => {
  // Canvas radar başlat
  initCanvasRadar();
  initNetworkMap();
  loadInitialData();

  // CPU/RAM stats polling - her 4 saniyede bir
  setInterval(() => {
    apiFetch("/api/stats", { credentials: "same-origin" })
      .then((r) => r.json())
      .then((data) => updateStats(data))
      .catch(() => {});
  }, 4000);
});

// İlk verileri yükle
function loadInitialData() {
  fetchIncidentOverview();
  apiFetch("/api/alerts", { credentials: "same-origin" })
    .then((r) => r.json())
    .then((data) => {
      if (data.length > 0) {
        // Reverse to show oldest first, then add newest on top
        data.reverse().forEach((alert) => addAlertToFeed(alert, false));
      }
    })
    .catch((err) => console.error("Alarmlar yüklenemedi:", err));

  apiFetch("/api/bans", { credentials: "same-origin" })
    .then((r) => r.json())
    .then((data) => renderBanList(data))
    .catch((err) => console.error("Banlar yüklenemedi:", err));

  apiFetch("/api/stats", { credentials: "same-origin" })
    .then((r) => r.json())
    .then((data) => updateStats(data))
    .catch((err) => console.error("İstatistikler yüklenemedi:", err));

  fetchRecordsForTrafficList();
  setInterval(() => {
    fetchIncidentOverview();
    fetchRecordsForTrafficList();
  }, 5000);
}

let incidentRequestPending = false;

async function fetchIncidentOverview() {
  const tbody = document.getElementById("incident-table-body");
  const status = document.getElementById("response-policy-status");
  if (!tbody || !status || incidentRequestPending) return;
  incidentRequestPending = true;
  try {
    const [incidents, policy] = await Promise.all(
      ["/api/incidents?limit=20", "/api/response-policy"].map(async (url) => {
        const response = await apiFetch(url, { credentials: "same-origin" });
        if (!response.ok) throw new Error("Olay verisi alınamadı");
        return response.json();
      }),
    );
    if (!Array.isArray(incidents)) throw new Error("Geçersiz olay verisi");
    status.textContent = `Otomatik müdahale: ${policy.enabled ? "açık" : "kapalı (değerlendirme)"} · Mod: ${String(policy.mode || "—").toUpperCase()} · Deneme modu: ${policy.dry_run ? "açık" : "kapalı"}`;
    const decisions = {
      observe: "İzle",
      review: "İncele",
      block: "Engelleme hazırlanıyor",
      pending: "Sonuç doğrulanmalı",
      blocked: "Geçici engel uygulandı",
      failed: "Müdahale uygulanamadı",
    };
    const reasons = {
      insufficient_evidence:
        "Yeterli bağımsız kanıt veya doğrulanmış kaynak yok",
      automatic_response_disabled: "Otomatik müdahale kapalı",
      passive_mode: "Pasif izleme veya deneme modu",
      monitoring_stopped: "İzleme durdurulmuş",
      protected_address: "Korunan adres",
      ipv6_response_unsupported: "IPv6 için otomatik müdahale desteklenmiyor",
      already_blocked: "Adres zaten engelli",
      corroborated_verified_source:
        "Doğrulanmış kaynak ve birden fazla kanıt türü",
      firewall_not_applied: "Güvenlik duvarı engeli uygulamadı",
      firewall_error: "Güvenlik duvarı işlemi başarısız",
    };
    const families = {
      unattributed: "Kaynağı doğrulanmamış",
      authentication: "Kimlik doğrulama",
      honeypot: "Tuzak servisi",
      traffic_rate: "Trafik hızı",
      reconnaissance: "Tarama",
      web_payload: "Uygulama içeriği",
      threat_intelligence: "Tehdit istihbaratı",
      dns_anomaly: "DNS anomali",
      behavior: "Davranış",
      observation: "Gözlem",
    };
    tbody.innerHTML = incidents.length
      ? incidents
          .slice(0, 20)
          .map((incident) => {
            const score = Number(incident.score);
            const seen = new Date(Number(incident.last_seen) * 1000);
            const signals = Object.keys(incident.signals || {})
              .map((family) => families[family] || family)
              .join(", ");
            return `<tr>
            <td><strong class="mono">${escapeHtml(incident.source_ip)}</strong><div class="device-detail">${Number.isFinite(seen.getTime()) ? escapeHtml(seen.toLocaleString("tr-TR")) : "—"}</div><div class="device-detail">${incident.active ? "Değerlendirme sürüyor" : "Değerlendirme penceresi kapandı"}</div></td>
            <td>${Number.isFinite(score) ? Math.max(0, Math.min(100, score)) : 0} / 100<div class="device-detail">${escapeHtml(signals || "Gözlem")}</div></td>
            <td>${escapeHtml(decisions[incident.decision] || incident.decision)}<div class="device-detail">${escapeHtml(reasons[incident.reason] || incident.reason)}</div></td>
          </tr>`;
          })
          .join("")
      : '<tr><td colspan="3" class="table-empty">Henüz ilişkilendirilmiş olay yok.</td></tr>';
  } catch (error) {
    status.textContent =
      "Müdahale politikası alınamadı. Yenileyerek tekrar deneyin.";
    tbody.innerHTML =
      '<tr><td colspan="3" class="table-empty">Olay verisi yüklenemedi.</td></tr>';
  } finally {
    incidentRequestPending = false;
  }
}

// (WebSocket olayları yukarıda initialize edildi)

// ---- Alarm Akışı ----

function matchesAlertFilter(severity) {
  return (
    currentAlertFilter === "all" ||
    (currentAlertFilter === "critical"
      ? severity === "critical"
      : ["high", "medium", "warning"].includes(severity))
  );
}

function filterAlerts(type) {
  currentAlertFilter = type;
  document.querySelectorAll(".filter-btn").forEach((button, index) => {
    const selected = ["all", "critical", "warning"][index] === type;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-pressed", String(selected));
  });
  document.querySelectorAll(".alert-item").forEach((item) => {
    item.hidden = !matchesAlertFilter(item.dataset.severity);
  });
  updateAlertEmptyState();
}

function updateAlertEmptyState() {
  const list = document.getElementById("alerts-list");
  const items = [...list.querySelectorAll(".alert-item")];
  list.querySelector(".filter-empty")?.remove();
  if (items.length && items.every((item) => item.hidden)) {
    const empty = document.createElement("div");
    empty.className = "alert-empty filter-empty";
    empty.textContent = "Bu filtreyle eşleşen güvenlik olayı yok.";
    list.append(empty);
  }
}

function addAlertToFeed(alert, animate) {
  const list = document.getElementById("alerts-list");

  // Boş durum mesajını kaldır
  const empty = list.querySelector(".alert-empty");
  if (empty) empty.remove();

  const item = document.createElement("div");
  const severity = [
    "critical",
    "high",
    "medium",
    "warning",
    "low",
    "info",
  ].includes(alert.severity)
    ? alert.severity
    : "info";
  const safeSeverity = severity;
  item.dataset.severity = severity;
  item.className = `alert-item severity-${safeSeverity}`;
  if (animate) item.classList.add("animate-in");

  item.hidden = !matchesAlertFilter(severity);

  const timestamp = alert.timestamp || new Date().toLocaleTimeString("tr-TR");

  item.innerHTML = `
        <div class="alert-header">
            <span class="severity-badge ${safeSeverity}">${escapeHtml((alert.severity || "").toUpperCase())}</span>
            <span class="alert-type">${escapeHtml(alert.alert_type)}</span>
            <span class="alert-time">${escapeHtml(timestamp)}</span>
        </div>
        <div class="alert-body">
            <p class="alert-desc">${escapeHtml(alert.description)}</p>
            <div class="alert-meta" style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <span class="meta-item">
                        <span class="meta-label">Kaynak:</span>
                        <span class="mono">${escapeHtml(alert.source_ip || "N/A")} / ${escapeHtml(alert.source_mac || "N/A")}</span>
                    </span>
                    <span class="meta-item">
                        <span class="meta-label">Hedef:</span>
                        <span class="mono">${escapeHtml(alert.destination_ip || "N/A")} / ${escapeHtml(alert.destination_mac || "N/A")}</span>
                    </span>
                </div>
                ${
                  (alert.source_ip && alert.source_ip !== "N/A") ||
                  (alert.source_mac && alert.source_mac !== "N/A")
                    ? `<button class="btn btn-sm btn-danger" style="margin-left: 10px;" onclick="quickBan('${escapeAttr(alert.source_ip === "N/A" ? "" : alert.source_ip)}', '${escapeAttr(alert.source_mac === "N/A" ? "" : alert.source_mac)}')">Ağdan At</button>`
                    : ""
                }
            </div>
        </div>
    `;

  if (alert.pcap_file) {
    const link = document.createElement("a");
    link.className = "btn btn-sm btn-primary pcap-btn";
    link.href = "/api/pcaps/" + encodeURIComponent(alert.pcap_file);
    link.download = alert.pcap_file;
    link.textContent = "📥 PCAP İndir (Kanıt)";
    item.appendChild(link);
  }

  // Listenin başına ekle (en yeni üstte)
  list.insertBefore(item, list.firstChild);
  if (animate && !item.hidden)
    window.DSUI?.animate(item, {
      opacity: [0.4, 1],
      y: [-6, 0],
      duration: 240,
    });

  // Maksimum gösterim sayısını aşma
  const items = list.querySelectorAll(".alert-item");
  if (items.length > MAX_ALERTS_DISPLAY) items[items.length - 1].remove();
  updateAlertEmptyState();
}

// ---- İstatistik Güncelleme ----

function updateStats(stats) {
  const el = (id) => document.getElementById(id);
  const setText = (id, val) => {
    const e = el(id);
    if (e) e.textContent = val;
  };

  setText(
    "last-updated",
    "Son veri · " + new Date().toLocaleTimeString("tr-TR"),
  );
  setText("total-alerts", stats.total_alerts || 0);
  setText("ipset-active", stats.active_bans || 0);
  setText("ipset-blocks", stats.active_bans || 0);
  setText("tg-commands", "—");
  const counts = Array.isArray(stats.alert_counts) ? stats.alert_counts : [];
  if (alertChart) {
    const values = [0, 0, 0, 0];
    counts.forEach((item) => {
      const severity = (item.severity || "").toLowerCase();
      const index =
        severity === "critical"
          ? 0
          : ["high", "warning"].includes(severity)
            ? 1
            : severity === "medium"
              ? 2
              : 3;
      values[index] += Number(item.count) || 0;
    });
    alertChart.data.datasets[0].data = values;
    alertChart.update("none");
    alertCanvas.setAttribute(
      "aria-label",
      "Alarm dağılımı: " +
        values
          .map((value, index) => alertChart.data.labels[index] + ": " + value)
          .join(", "),
    );
  }
  let hidsTotal = 0;
  for (const [key, types] of Object.entries(HIDS_TYPES)) {
    const count = counts
      .filter((item) => types.includes((item.alert_type || "").toUpperCase()))
      .reduce((sum, item) => sum + item.count, 0);
    setText("hids-" + key, count);
    hidsTotal += count;
  }
  setText("hids-alerts", hidsTotal);
  setText("active-bans", stats.active_bans || 0);
  setText("interface-name", stats.interface || "N/A");
  const cpuVal = stats.cpu_usage || 0;
  const ramVal = stats.ram_usage || 0;
  setText("cpu-usage", cpuVal.toFixed(1) + "%");
  setText("ram-usage", ramVal.toFixed(1) + "%");
  // Yeni gauge elementleri
  const cpuGauge = document.getElementById("cpu-gauge");
  const ramGauge = document.getElementById("ram-gauge");
  const cpuBar = document.getElementById("cpu-bar");
  const ramBar = document.getElementById("ram-bar");
  if (cpuGauge) {
    cpuGauge.textContent = cpuVal.toFixed(1) + "%";
    cpuGauge.style.color =
      cpuVal > 80 ? "#eb7b86" : cpuVal > 50 ? "#e9b970" : "#8293ff";
  }
  if (ramGauge) {
    ramGauge.textContent = ramVal.toFixed(1) + "%";
    ramGauge.style.color =
      ramVal > 80 ? "#eb7b86" : ramVal > 50 ? "#e9b970" : "#00ccff";
  }
  if (cpuBar) cpuBar.style.width = Math.min(100, cpuVal) + "%";
  if (ramBar) ramBar.style.width = Math.min(100, ramVal) + "%";

  // Mode badge
  const modeBadge = el("mode-badge");
  if (modeBadge) {
    modeBadge.textContent = stats.mode || "IDS";
    modeBadge.className =
      "mode-badge " + (stats.mode === "IPS" ? "mode-ips" : "mode-ids");
  }

  // Uptime
  if (stats.uptime !== undefined) {
    const h = Math.floor(stats.uptime / 3600);
    const m = Math.floor((stats.uptime % 3600) / 60);
    const s = stats.uptime % 60;
    setText(
      "uptime",
      `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`,
    );
  }

  // ARP istatistikleri
  const arpStats = stats.arp_stats || {};
  const arpRequests = arpStats.requests || {};
  const arpReplies = arpStats.replies || {};
  const arpGratuitous = arpStats.gratuitous || {};

  const reqCount = Object.values(arpRequests).reduce((a, b) => a + b, 0);
  const repCount = Object.values(arpReplies).reduce((a, b) => a + b, 0);
  const gratCount = Object.values(arpGratuitous).reduce((a, b) => a + b, 0);
  const totalArpNow = reqCount + repCount + gratCount;

  setText("arp-requests", reqCount);
  setText("arp-replies", repCount);
  setText("arp-gratuitous", gratCount);

  const captures = Object.values(stats.capture || {});
  const packetCount = captures.length
    ? Math.max(...captures.map((item) => Number(item.packets) || 0))
    : totalArpNow;
  if (
    window.lastPacketCount !== undefined &&
    packetCount > window.lastPacketCount
  )
    addRadarBlip("Paket gözlemi", "low");
  window.lastPacketCount = packetCount;

  // Scan istatistikleri
  const scanStats = stats.scan_stats || {};
  setText("scan-syn", scanStats.syn_scans || 0);
  setText("scan-fin", scanStats.fin_scans || 0);
  setText("scan-xmas", scanStats.xmas_scans || 0);
  setText("scan-null", scanStats.null_scans || 0);
  setText("scan-udp", scanStats.udp_scans || 0);

  // WiFi istatistikleri
  const wifiStats = stats.wifi_stats || {};
  setText("wifi-deauth", wifiStats.deauth_senders || 0);
  setText("wifi-beacon", wifiStats.beacon_bssids || 0);
  setText("wifi-evil-twin", wifiStats.evil_twin_ssids || 0);

  // WiFi modül durumu
  const wifiStatus = el("wifi-status");
  if (wifiStatus) {
    if (stats.wifi_enabled) {
      wifiStatus.textContent = "Aktif";
      wifiStatus.className = "module-status active";
    } else {
      wifiStatus.textContent = "Pasif";
      wifiStatus.className = "module-status";
    }
  }

  // Çalışma durumunu güncelle
  updateRunningStatus(stats.sniffer_running);
  const captureState = document.getElementById("radar-state");
  if (captureState && stats.capture) {
    const backends = Object.values(stats.capture);
    const active = backends.filter((item) => item.running).length;
    const lastSeen = Math.max(
      0,
      ...backends.map((item) => Number(item.last_packet_at) || 0),
    );
    captureState.textContent = !stats.monitoring_requested
      ? "Yakalama durduruldu"
      : !active
        ? "Yakalama çalışmıyor — yeniden başlatın"
        : `${active < backends.length ? "Kısmi yakalama" : "Yakalama etkin"} · ${lastSeen ? "Son paket " + new Date(lastSeen * 1000).toLocaleTimeString("tr-TR") : "Henüz paket yok"}`;
    captureState.title = backends
      .map((item) => item.error)
      .filter(Boolean)
      .join("; ");
    if (radarMotion.matches) captureState.textContent += " · Hareket azaltıldı";
    if (stats.monitoring_requested)
      document.getElementById("stop-btn").disabled = false;
  }

  // Telegram kart istatistikleri
  setText("tg-sent", stats.telegram_sent || 0);
  const tgStatus = document.getElementById("tg-status");
  if (tgStatus) {
    if (stats.telegram_connected) {
      tgStatus.textContent = "Bağlı";
      tgStatus.style.color = "#8293ff";
    } else {
      tgStatus.textContent = "Yapılandırılmadı";
      tgStatus.style.color = "#e9b970";
    }
  }

  // Risk Skoru Güncelleme
  const riskScoreEl = document.getElementById("main-risk-score");
  if (riskScoreEl && stats.alert_counts) {
    let score = 0;
    stats.alert_counts.forEach((item) => {
      const sev = (item.severity || "").toLowerCase();
      if (sev === "critical") score += item.count * 10;
      else if (sev === "high" || sev === "warning") score += item.count * 5;
      else if (sev === "medium") score += item.count * 2;
      else score += item.count * 1;
    });

    score = Math.min(score, 999);
    riskScoreEl.textContent = score;
    const color =
      score > 100
        ? "var(--danger)"
        : score > 50
          ? "var(--warning)"
          : "var(--text-primary)";
    riskScoreEl.style.color = color;
    const riskTrendEl = document.getElementById("risk-trend");
    if (riskTrendEl) {
      riskTrendEl.textContent =
        score > 100
          ? "Yüksek olay yoğunluğu"
          : score > 50
            ? "Artan olay yoğunluğu"
            : score > 0
              ? "Düşük olay yoğunluğu"
              : "Kayıtlı alarm yok";
      riskTrendEl.style.color = color;
    }
  }

  // Arayüz input'unu güncelle
  const ifaceInput = el("interface-input");
  if (ifaceInput && document.activeElement !== ifaceInput) {
    ifaceInput.value = stats.interface || "eth0";
  }
}

// ---- Çalışma Durumu ----

function updateRunningStatus(running) {
  const changed = isRunning !== Boolean(running);
  isRunning = Boolean(running);
  if (changed || (isRunning && radarFrame === null)) refreshRadar();
  const radarState = document.getElementById("radar-state");
  if (radarState)
    radarState.textContent = running ? "Yakalama etkin" : "Yakalama durduruldu";
  const badge = document.getElementById("status-badge");
  const text = badge.querySelector(".status-text");
  const startBtn = document.getElementById("start-btn");
  const stopBtn = document.getElementById("stop-btn");

  if (running) {
    badge.className = "status-badge running";
    text.textContent = "Aktif";
    startBtn.disabled = true;
    stopBtn.disabled = false;
  } else {
    badge.className = "status-badge stopped";
    text.textContent = "Durduruldu";
    startBtn.disabled = false;
    stopBtn.disabled = true;
  }
}

// ---- Sniffer Kontrolü ----

function startSniffer() {
  const iface = document.getElementById("interface-input").value.trim();
  if (!iface) {
    showNotification("Lütfen bir ağ arayüzü girin!", "warning");
    return;
  }

  apiFetch("/api/control", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "XMLHttpRequest",
    },
    credentials: "same-origin",
    body: JSON.stringify({ action: "start", interface: iface }),
  })
    .then((r) => r.json())
    .then((data) => {
      if (data.success) {
        updateRunningStatus(true);
        showNotification("Paket yakalama başlatıldı.", "success");
      } else {
        showNotification(data.error || "Yakalama başlatılamadı.", "error");
      }
    })
    .catch((err) => showNotification("Başlatma hatası: " + err, "error"));
}

function stopSniffer() {
  apiFetch("/api/control", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "XMLHttpRequest",
    },
    credentials: "same-origin",
    body: JSON.stringify({ action: "stop" }),
  })
    .then((r) => r.json())
    .then((data) => {
      if (data.success) {
        updateRunningStatus(false);
        showNotification("Paket yakalama durduruldu.", "warning");
      } else {
        showNotification(data.error || "Yakalama durdurulamadı.", "error");
      }
    })
    .catch((err) => showNotification("Durdurma hatası: " + err, "error"));
}

// ---- Ban Yönetimi ----

function addBan() {
  const ip = document.getElementById("ban-ip").value.trim();
  const mac = document.getElementById("ban-mac").value.trim();
  const reason =
    document.getElementById("ban-reason").value.trim() || "Manuel ban";

  if (!ip && !mac) {
    showNotification("IP veya MAC adresi gerekli!", "warning");
    return;
  }

  apiFetch("/api/ban", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "XMLHttpRequest",
    },
    credentials: "same-origin",
    body: JSON.stringify({ ip, mac, reason }),
  })
    .then((r) => r.json())
    .then((data) => {
      if (data.success) {
        document.getElementById("ban-ip").value = "";
        document.getElementById("ban-mac").value = "";
        document.getElementById("ban-reason").value = "";
        showNotification("Engelleme eklendi!", "success");
      } else {
        showNotification(data.error || "Engelleme uygulanamadı.", "error");
      }
      if (data.success || Object.keys(data.applied || {}).length > 0) {
        apiFetch("/api/bans", { credentials: "same-origin" })
          .then((r) => r.json())
          .then((bans) => renderBanList(bans));
      }
    })
    .catch((err) => showNotification("Ban hatası: " + err, "error"));
}

function removeBan(ip, mac) {
  apiFetch("/api/unban", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "XMLHttpRequest",
    },
    credentials: "same-origin",
    body: JSON.stringify({ ip: ip || "", mac: mac || "" }),
  })
    .then((r) => r.json())
    .then((data) => {
      if (data.success) {
        apiFetch("/api/bans", { credentials: "same-origin" })
          .then((r) => r.json())
          .then((bans) => renderBanList(bans));
        showNotification("Engelleme kaldırıldı.", "warning");
      }
    })
    .catch((err) => showNotification("Unban hatası: " + err, "error"));
}

function renderBanList(bans) {
  const list = document.getElementById("ban-list");
  if (!bans || bans.length === 0) {
    list.innerHTML = '<div class="ban-empty">Aktif ban bulunmuyor.</div>';
    return;
  }

  list.innerHTML = bans
    .map(
      (ban) => `
        <div class="ban-item">
            <div class="ban-info">
                <span class="mono">${escapeHtml(ban.ip_address || "-")} / ${escapeHtml(ban.mac_address || "-")}</span>
                <span class="ban-reason">${escapeHtml(ban.reason || "N/A")}</span>
            </div>
            <button class="btn btn-sm btn-unban" onclick="removeBan('${escapeAttr(ban.ip_address || "")}', '${escapeAttr(ban.mac_address || "")}')">
                Kaldır
            </button>
        </div>
    `,
    )
    .join("");
}

// ---- Alarm Akışını Temizle ----

function clearAlertFeed() {
  const list = document.getElementById("alerts-list");
  list.innerHTML =
    '<div class="alert-empty"><span>Alarm akışı temizlendi.</span></div>';
}

// ---- Bildirim Sistemi ----

function showNotification(message, type) {
  window.DSUI?.toast(message, type);
}

// ---- Ağ Cihazları Tarama ----

function runNetworkScan() {
  const btn = document.getElementById("scan-btn");
  const list = document.getElementById("scanner-list");

  btn.disabled = true;
  btn.textContent = "Taranıyor...";
  list.innerHTML =
    '<div class="ban-empty">Ağ taranıyor, lütfen bekleyin...</div>';

  apiFetch("/api/scan", {
    method: "POST",
    headers: { "X-Requested-With": "XMLHttpRequest" },
    credentials: "same-origin",
  })
    .then((r) => r.json())
    .then((data) => {
      if (!data.success) {
        showNotification("Tarama başlatılamadı: " + data.error, "error");
        btn.disabled = false;
        btn.textContent = "Taramayı Başlat";
      } else {
        showNotification("Ağ taraması başladı", "success");
      }
    })
    .catch((err) => {
      showNotification("Tarama hatası: " + err, "error");
      btn.disabled = false;
      btn.textContent = "Taramayı Başlat";
    });
}

// Socket event for scan completion is handled at the top

function renderDeviceList(records) {
  const list = document.getElementById("scanner-list");
  const devices = (records || []).filter(
    (device) => device.ip_address && device.mac_address,
  );
  list.innerHTML =
    devices
      .map((device) => {
        const lastSeen = new Date(parseDeviceTime(device.last_seen));
        const recent =
          Number.isFinite(lastSeen.getTime()) &&
          Date.now() - lastSeen.getTime() < 15 * 60 * 1000;
        let details = device.details || {};
        if (typeof details === "string") {
          try {
            details = JSON.parse(details);
          } catch {
            details = {};
          }
        }
        const hostname =
          details?.hostname ||
          details?.dhcp_hostname ||
          device.hostname ||
          "Tanımsız";
        const score = Number(device.threat_score) || 0;
        return `<article class="discovered-device">
      <div class="discovered-heading"><div><strong class="mono">${escapeHtml(device.ip_address)}</strong><span class="device-presence ${recent ? "recent" : ""}">${recent ? "Yakın zamanda görüldü" : "Pasif"}</span></div>
        <span class="device-score ${score > 20 ? "elevated" : ""}">Olay skoru · ${score}</span></div>
      <dl class="device-properties">
        <div><dt>MAC adresi</dt><dd class="mono">${escapeHtml(device.mac_address)}</dd></div>
        <div><dt>Cihaz adı</dt><dd>${escapeHtml(hostname)}</dd></div>
        <div><dt>Üretici</dt><dd>${escapeHtml(device.vendor || "Bilinmiyor")}</dd></div>
        <div><dt>İşletim sistemi</dt><dd>${escapeHtml(device.os_type || "Bilinmiyor")}</dd></div>
        <div><dt>Son görülme</dt><dd>${Number.isFinite(lastSeen.getTime()) ? escapeHtml(lastSeen.toLocaleString("tr-TR")) : "—"}</dd></div>
      </dl>
      <div class="device-actions">
        <button class="btn btn-sm btn-danger" onclick="quickBan('${escapeAttr(device.ip_address)}', '${escapeAttr(device.mac_address)}')">Engelle</button>
        <button class="btn btn-sm" onclick="activeDefenseAction('${escapeAttr(device.ip_address)}', 'tarpit', this)">Tarpit</button>
        <button class="btn btn-sm" onclick="activeDefenseAction('${escapeAttr(device.ip_address)}', 'tcp_reset', this)">TCP sıfırla</button>
        <button class="btn btn-sm" onclick="activeDefenseAction('${escapeAttr(device.ip_address)}', 'quarantine', this)">Karantina</button>
        <button class="btn btn-sm" onclick="activeDefenseAction('${escapeAttr(device.ip_address)}', 'rate_limit', this)">Hızı sınırla · 1 Kbps</button>
      </div></article>`;
      })
      .join("") || '<div class="ban-empty">Ağda cihaz bulunamadı.</div>';
}

function activeDefenseAction(ip, action, btnElement) {
  if (!ip) return;
  const actionLabels = {
    tarpit: "TCP Tarpit Kaynak Tuzağı",
    untarpit: "TCP Tarpit İptal Edildi",
    tcp_reset: "TCP RST Oturum Düşürme",
    quarantine: "Karantina Portalı Yönlendirmesi",
    unquarantine: "Karantina İptal Edildi",
    rate_limit: "Bant Genişliğini 1 Kbps Seviyesine Boğma",
    unrate_limit: "Bant Genişliği Limiti İptal Edildi",
  };

  let isRevert = false;
  if (btnElement && btnElement.classList.contains("active-rule")) {
    isRevert = true;
    if (action === "tarpit") action = "untarpit";
    if (action === "quarantine") action = "unquarantine";
    if (action === "rate_limit") action = "unrate_limit";
  }

  const label = actionLabels[action] || action;

  apiFetch("/api/active_defense", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "XMLHttpRequest",
    },
    credentials: "same-origin",
    body: JSON.stringify({ ip: ip, action: action }),
  })
    .then((r) => r.json())
    .then((data) => {
      if (data.success) {
        showNotification("✅ " + (data.msg || label + " uygulandı"), "success");
        if (btnElement) {
          if (isRevert) {
            btnElement.classList.remove("active-rule");
            btnElement.style.border = "";
            btnElement.style.boxShadow = "";
          } else {
            btnElement.classList.add("active-rule");
            btnElement.style.border = "2px solid #8293ff";
            btnElement.style.boxShadow = "0 0 10px #8293ff";
          }
        }
      } else {
        showNotification(
          "❌ Hata: " + (data.error || "İşlem başarısız"),
          "error",
        );
      }
    })
    .catch((err) => {
      showNotification("❌ Sunucu Bağlantı Hatası", "error");
    });
}

// =============================================
// Ağ Geçidi Modu (Gateway Mode) UI
// =============================================
function toggleGatewayMode() {
  apiFetch("/api/gateway_mode/toggle", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "XMLHttpRequest",
    },
    credentials: "same-origin",
  })
    .then((r) => r.json())
    .then((data) => {
      if (data.success) {
        const btn = document.getElementById("gateway-mode-btn");
        if (data.active) {
          if (btn) {
            btn.classList.add("active");
            btn.style.background = "var(--accent-soft)";
            btn.style.color = "#fff";
          }
          showNotification("✅ " + data.msg, "success");
          // Cihaz talimatlarını göster
          if (data.instructions) {
            let instrText = "📱 Cihazlarınızda Ağ Geçidini ayarlayın:\n\n";
            instrText += "🍎 iPhone: " + data.instructions.iphone + "\n";
            instrText += "🤖 Android: " + data.instructions.android + "\n";
            instrText += "🪟 Windows: " + data.instructions.windows + "\n";
            instrText += "🍏 macOS: " + data.instructions.mac;
            setTimeout(() => alert(instrText), 500);
          }
        } else {
          if (btn) {
            btn.classList.remove("active");
            btn.style.background = "";
            btn.style.color = "";
          }
          showNotification("⚠️ " + data.msg, "warning");
        }
      } else {
        showNotification(
          "❌ " + (data.error || "Gateway modu hatası"),
          "error",
        );
      }
    })
    .catch((err) => showNotification("❌ Sunucuya bağlanılamadı", "error"));
}

function checkGatewayStatus() {
  apiFetch("/api/gateway_mode", { credentials: "same-origin" })
    .then((r) => r.json())
    .then((data) => {
      const btn = document.getElementById("gateway-mode-btn");
      if (btn && data.active) {
        btn.classList.add("active");
        btn.style.background = "var(--accent-soft)";
        btn.style.color = "#fff";
      }
    })
    .catch(() => {});
}

// Sayfa yüklendiğinde gateway durumunu kontrol et
document.addEventListener("DOMContentLoaded", () => {
  setTimeout(checkGatewayStatus, 2000);
});

function quickBan(ip, mac) {
  document.getElementById("ban-ip").value = ip;
  document.getElementById("ban-mac").value = mac;
  document.getElementById("ban-reason").value = "Web Panel Hızlı Ban";
  addBan();
}

// ---- Yardımcı Fonksiyonlar ----

function escapeHtml(text) {
  if (text === null || text === undefined) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeAttr(text) {
  return escapeHtml(
    String(text ?? "")
      .replace(/\\/g, "\\\\")
      .replace(/'/g, "\\'")
      .replace(/\n/g, "\\n")
      .replace(/\r/g, "\\r"),
  );
}

function showAlert(title, message, type) {
  showNotification((title ? `[${title}] ` : "") + message, type || "info");
}

// ---- Ayarlar (Settings) Yönetimi ----
function openSettings() {
  apiFetch("/api/settings", { credentials: "same-origin" })
    .then((r) => r.json())
    .then((data) => {
      document.getElementById("setting-discord").value =
        data.discord_webhook || "";
      document.getElementById("setting-telegram-token").value =
        data.telegram_token || "";
      document.getElementById("setting-telegram-chat").value =
        data.telegram_chat_id || "";
      document.getElementById("settings-modal").style.display = "block";
    })
    .catch((err) => showNotification("Ayarlar yüklenemedi: " + err, "error"));
}

function closeSettings() {
  document.getElementById("settings-modal").style.display = "none";
}

function saveSettings() {
  const data = {
    discord_webhook: document.getElementById("setting-discord").value.trim(),
    telegram_token: document
      .getElementById("setting-telegram-token")
      .value.trim(),
    telegram_chat_id: document
      .getElementById("setting-telegram-chat")
      .value.trim(),
  };

  apiFetch("/api/settings", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "XMLHttpRequest",
    },
    credentials: "same-origin",
    body: JSON.stringify(data),
  })
    .then((r) => r.json())
    .then((res) => {
      if (res.success) {
        showNotification("Ayarlar kaydedildi.", "success");
        closeSettings();
      } else {
        showNotification("Kaydetme hatası: " + res.error, "error");
      }
    })
    .catch((err) => showNotification("Kaydetme hatası: " + err, "error"));
}

// ---- Canlı Ağ Haritası (Vis.js) ----
let network = null;
let nodes = new vis.DataSet();
let edges = new vis.DataSet();
const networkSlots = new Map();
const laserTimers = new Map();
let networkUserView = false;
let pendingNetworkRecords = [];

function parseDeviceTime(value) {
  const stamp = String(value || "").replace(" ", "T");
  return Date.parse(stamp + (/(Z|[+-]\d{2}:?\d{2})$/i.test(stamp) ? "" : "Z"));
}

function devicePosition(slot) {
  let ring = 1;
  while (slot >= 8 * ring) {
    slot -= 8 * ring;
    ring++;
  }
  const angle = (slot / (8 * ring)) * Math.PI * 2;
  return { x: Math.cos(angle) * ring * 310, y: Math.sin(angle) * ring * 310 };
}

function fitNetworkMap() {
  if (!network) return;
  networkUserView = false;
  network.fit({ animation: false });
}

function initNetworkMap() {
  if (network) return;
  const container = document.getElementById("network-map");
  if (!container) return;

  // Varsayılan Gateway/Modem node'u
  nodes.add({
    id: "gateway",
    label: "İzlenen ağ",
    x: 0,
    y: 0,
    fixed: true,
    shape: "box",
    color: { background: "#172238", border: "#91a3ef" },
    font: { color: "#e6f1ff", size: 16 },
  });

  const data = { nodes: nodes, edges: edges };
  const options = {
    nodes: {
      font: { color: "#96a6c2", size: 14 },
      shape: "box",
      color: { background: "#172238", border: "#2d3d59" },
      borderWidth: 2,
      widthConstraint: { minimum: 170, maximum: 170 },
      heightConstraint: { minimum: 54 },
      margin: 10,
      fixed: true,
      shadow: false,
    },
    edges: {
      width: 2,
      color: { color: "#2d3d59", highlight: "#91a3ef" },
      smooth: false,
      dashes: true,
    },
    physics: { enabled: false },
    interaction: { hover: true, tooltipDelay: 100, dragNodes: false },
  };

  network = new vis.Network(container, data, options);
  network.on("dragStart", () => {
    networkUserView = true;
  });
  network.on("zoom", () => {
    networkUserView = true;
  });
  new ResizeObserver(() => {
    if (container.clientWidth && container.clientHeight) {
      network.redraw();
      if (!networkUserView) fitNetworkMap();
    }
  }).observe(container);
  updateNetworkMap(pendingNetworkRecords);

  // Tıklanabilir Harita (Interactive Map) Menüsü
  network.on("click", function (params) {
    if (params.nodes.length > 0) {
      const nodeId = params.nodes[0]; // IP adresi
      const nodeData = nodes.get(nodeId);
      const contextMenu = document.getElementById("map-context-menu");

      // Eğer modem ise menü gösterme
      if (nodeId === "gateway") return;

      const header = document.getElementById("context-header");
      header.innerHTML = `Hedef: ${escapeHtml(nodeId)}<br><span style="color:#e9b970; font-size: 0.8rem;">${escapeHtml((nodeData.title || "").split("\n")[0])}</span>`;

      // Eğer butonlar yoksa önce context menu HTML içine eklediğimizden emin olmalıyız (Şu an var, ama biz dinamik veya index.html üzerinden ekledik)
      let btnContainer = document.getElementById("context-buttons-container");
      if (!btnContainer) {
        // index.html'deki mevcut context menüyü bozmamak için eski butonları bulup güncelleyelim.
        const banBtn = document.getElementById("btn-context-ban");

        // Gözetle butonunu ban butonunun önüne ekle (sadece 1 kere)
        if (!document.getElementById("btn-context-monitor")) {
          const monitorBtn = document.createElement("button");
          monitorBtn.id = "btn-context-monitor";
          monitorBtn.className = "btn btn-sm btn-primary";
          monitorBtn.style = "width: 100%; margin-bottom: 5px;";
          monitorBtn.innerHTML = '<i class="fas fa-eye"></i> Canlı Gözetle';
          banBtn.parentNode.insertBefore(monitorBtn, banBtn);
        }
      }

      const btnMonitor = document.getElementById("btn-context-monitor");
      btnMonitor.onclick = function () {
        openTrafficModal(nodeId);
        contextMenu.style.display = "none";
      };

      const btn = document.getElementById("btn-context-ban");
      btn.onclick = function () {
        const macMatch = nodeData.title.match(/MAC: ([a-f0-9:]+)/i);
        const mac = macMatch ? macMatch[1] : "";
        quickBan(nodeId, mac);
        contextMenu.style.display = "none";
      };

      // Fare pozisyonuna göre menüyü konumlandır
      const mapRect = container.getBoundingClientRect();
      const pointer = params.pointer.DOM;
      contextMenu.style.left =
        Math.min(
          mapRect.left + pointer.x + window.scrollX + 10,
          document.documentElement.clientWidth - 260,
        ) + "px";
      contextMenu.style.top =
        mapRect.top + pointer.y + window.scrollY - 10 + "px";
      contextMenu.style.display = "block";
    } else {
      document.getElementById("map-context-menu").style.display = "none";
    }
  });
}

function updateNetworkMap(records) {
  pendingNetworkRecords = Array.isArray(records) ? records : [];
  if (!network) return;
  const current = new Map();
  for (const device of pendingNetworkRecords) {
    const ip = device.ip_address;
    const seen = parseDeviceTime(device.last_seen);
    if (
      !ip ||
      ip === "N/A" ||
      !Number.isFinite(seen) ||
      Date.now() - seen >= 10 * 60 * 1000
    )
      continue;
    if (!current.has(ip) || seen > parseDeviceTime(current.get(ip).last_seen))
      current.set(ip, device);
  }
  let membershipChanged = false;
  for (const id of nodes.getIds()) {
    if (id === "gateway" || current.has(id)) continue;
    nodes.remove(id);
    networkSlots.delete(id);
    for (const edge of edges.get())
      if (edge.from === id || edge.to === id) {
        edges.remove(edge.id);
        clearTimeout(laserTimers.get(edge.id));
        laserTimers.delete(edge.id);
      }
    membershipChanged = true;
  }
  const occupied = new Set(networkSlots.values());
  for (const [ip, device] of [...current].sort(([a], [b]) =>
    a.localeCompare(b, undefined, { numeric: true }),
  )) {
    if (!networkSlots.has(ip)) {
      let slot = 0;
      while (occupied.has(slot)) slot++;
      occupied.add(slot);
      networkSlots.set(ip, slot);
      membershipChanged = true;
    }
    const os = String(device.os_type || "Bilinmiyor");
    const vendor = String(device.vendor || "Bilinmiyor");
    const caption = String(
      device.hostname && device.hostname !== "Bilinmiyor"
        ? device.hostname
        : os,
    ).slice(0, 22);
    const position = devicePosition(networkSlots.get(ip));
    nodes.update({
      id: ip,
      ...position,
      fixed: true,
      label: `${ip}\n${caption}`,
      title: `MAC: ${escapeHtml(device.mac_address)}\nMarka: ${escapeHtml(vendor)}\nOS: ${escapeHtml(os)}`,
      color: {
        background: "#172238",
        border:
          device.threat_score > 20
            ? "#eb7b86"
            : device.threat_score > 0
              ? "#e9b970"
              : "#91a3ef",
      },
      font: { color: "#e6f1ff", size: 13 },
    });
    if (!edges.get(`edge_${ip}`))
      edges.add({
        id: `edge_${ip}`,
        from: "gateway",
        to: ip,
        title: "Gözlem ilişkisi; fiziksel bağlantı doğrulanmadı",
        color: "#2d3d59",
      });
  }
  if (membershipChanged && !networkUserView) fitNetworkMap();
}

function drawAttackLaser(src_ip, dst_ip, severity) {
  // Never invent devices or a destination for an unattributed event.
  if (!network || !nodes.get(src_ip) || !nodes.get(dst_ip) || src_ip === dst_ip)
    return;
  const id = `laser_${src_ip}_${dst_ip}`;
  if (!laserTimers.has(id) && laserTimers.size >= 100) return;
  clearTimeout(laserTimers.get(id));
  edges.update({
    id,
    from: src_ip,
    to: dst_ip,
    color: severity === "critical" ? "#eb7b86" : "#e9b970",
    width: 3,
    arrows: "to",
    dashes: true,
  });
  laserTimers.set(
    id,
    setTimeout(() => {
      edges.remove(id);
      laserTimers.delete(id);
    }, 1500),
  );
}

// ---- TRAFFIC MONITOR (DS-IPS V2) ----
let currentTrafficIp = null;
const MAX_TRAFFIC_LOGS = 50;

function openTrafficModal(ip) {
  window.currentMonitorIp = ip;
  document.getElementById("traffic-ip").textContent = ip;
  document.getElementById("traffic-modal").style.display = "block";

  // Geçmişi API'den çek
  apiFetch(
    `/api/dns_logs/${encodeURIComponent(ip)}?limit=${MAX_TRAFFIC_LOGS}`,
    { credentials: "same-origin" },
  )
    .then((r) => r.json())
    .then((data) => {
      if (data.length > 0) {
        document.getElementById("traffic-table-body").innerHTML = "";
        data.reverse().forEach((log) => appendTrafficLog(log, true));
      } else {
        document.getElementById("traffic-table-body").innerHTML =
          '<tr><td colspan="3" style="text-align:center; color:#96a6c2; padding:20px;">Geçmiş trafik verisi bulunamadı.</td></tr>';
      }
    })
    .catch((err) => {
      console.error("DNS Log hatası:", err);
    });
}

function closeTrafficModal() {
  document.getElementById("traffic-modal").style.display = "none";
  window.currentMonitorIp = null;
}

// Trafik tablosuna satır ekleme
function appendTrafficLog(data, isHistory = false) {
  if (data.source_ip !== window.currentMonitorIp) return;

  const tbody = document.getElementById("traffic-table-body");

  // "Bulunamadı" yazısını kaldır
  if (tbody.innerHTML.includes("bulunamadı")) {
    tbody.innerHTML = "";
  }

  const tr = document.createElement("tr");
  tr.style.backgroundColor = "rgba(100, 255, 218, 0.05)"; // Yeni satır parlaması

  tr.innerHTML = `
        <td style="padding:10px; color:#96a6c2;">${escapeHtml((data.timestamp || "").split(" ")[1] || data.timestamp || "")}</td>
        <td style="padding:10px; color:#e6f1ff; font-weight:bold;">${escapeHtml(data.domain)}</td>
        <td style="padding:10px;"><span class="severity-badge medium" style="background:#2d3d59; border-color:#91a3ef; color:#91a3ef;">${escapeHtml(data.record_type)}</span></td>
    `;

  // En başa ekle (yukarıdan aşağı aksın)
  tbody.insertBefore(tr, tbody.firstChild);

  // Parlama efektini söndür
  setTimeout(() => {
    tr.style.backgroundColor = "transparent";
  }, 1000);

  // Maksimum satır sınırını koru
  while (tbody.children.length > MAX_TRAFFIC_LOGS) {
    tbody.removeChild(tbody.lastChild);
  }
}

// Genel panelde aktif cihazları sabitle
let deviceRequestPending = null;
let deviceSightings = new Map();
function fetchRecordsForTrafficList() {
  if (deviceRequestPending) return deviceRequestPending;
  const tbody = document.getElementById("general-traffic-body");
  if (!tbody) return Promise.resolve();
  deviceRequestPending = apiFetch("/api/devices", {
    credentials: "same-origin",
  })
    .then((response) => {
      if (!response.ok) throw new Error("Cihaz verisi alınamadı");
      return response.json();
    })
    .then((data) => {
      if (!Array.isArray(data)) throw new Error("Geçersiz cihaz verisi");
      updateNetworkMap(data);
      renderDeviceList(data);
      const devices = data.filter((device) => {
        if (!device.ip_address || device.ip_address === "N/A") return false;
        const lastSeen = parseDeviceTime(device.last_seen);
        return (
          Number.isFinite(lastSeen) && Date.now() - lastSeen < 10 * 60 * 1000
        );
      });
      let shown = 0;
      const sightings = new Map();
      for (const device of devices) {
        const seen = parseDeviceTime(device.last_seen);
        sightings.set(device.ip_address, seen);
        if (
          isRunning &&
          seen > (deviceSightings.get(device.ip_address) || 0) &&
          shown < 8
        ) {
          addRadarBlip(device.ip_address, "low");
          shown++;
        }
      }
      deviceSightings = sightings;
      tbody.innerHTML =
        devices
          .map(
            (device) => `
                <tr><td><div class="device-ip"><span class="device-state"></span>${escapeHtml(device.ip_address)}</div>
                <div class="device-detail">${escapeHtml(device.hostname || device.vendor || "Tanımsız cihaz")}</div>
                <div class="device-detail mono">${escapeHtml(device.mac_address || "—")}</div></td>
                <td class="align-right"><button class="btn btn-sm" onclick="openTrafficModal('${escapeAttr(device.ip_address)}')">Gözetle</button></td></tr>
            `,
          )
          .join("") ||
        '<tr><td colspan="2" class="table-empty">Son 10 dakikada görülen cihaz yok.</td></tr>';
    })
    .catch(() => {
      tbody.innerHTML =
        '<tr><td colspan="2" class="table-empty">Cihazlar yüklenemedi. Yenile düğmesiyle tekrar deneyin.</td></tr>';
    })
    .finally(() => {
      deviceRequestPending = null;
    });
  return deviceRequestPending;
}

// =============================================
// Active Defense UI Logic
// =============================================
function fetchActiveDefenseRules() {
  apiFetch("/api/active_defense/list", { credentials: "same-origin" })
    .then((r) => r.json())
    .then((data) => {
      const list = document.getElementById("active-defense-list");
      if (!list) return;
      if (data.success) {
        if (data.rules && data.rules.length > 0) {
          list.innerHTML = data.rules
            .map(
              (r) => `
                        <div class="defense-item">
                            <div>
                                <strong class="mono">${escapeHtml(r.module)}</strong>
                                <div style="font-size: 0.85rem; color: #e2e8f0; margin-top: 4px;">
                                    Hedef IP: ${r.target_ip ? escapeHtml(r.target_ip) : "Genel"} | MAC: ${r.target_mac ? escapeHtml(r.target_mac) : "-"}
                                </div>
                                ${r.parameters && Object.keys(r.parameters).length > 0 ? `<div style="font-size: 0.75rem; color: #96a6c2; margin-top: 2px;">Parametreler: ${escapeHtml(JSON.stringify(r.parameters))}</div>` : ""}
                                <div style="font-size: 0.7rem; color: #64748b; margin-top: 4px;">Zaman: ${escapeHtml(r.created_at || r.timestamp)}</div>
                            </div>
                        </div>
                    `,
            )
            .join("");
        } else {
          list.innerHTML =
            '<div class="ban-empty">Aktif savunma kuralı yok.</div>';
        }
      }
    })
    .catch((err) => console.error("Active defense fetch error:", err));
}

function cleanupActiveDefense() {
  if (
    !confirm(
      "Tüm aktif savunma kurallarını iptal etmek ve veritabanını temizlemek istediğinize emin misiniz?",
    )
  )
    return;
  apiFetch("/api/active_defense/cleanup", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "XMLHttpRequest",
    },
    credentials: "same-origin",
  })
    .then((r) => r.json())
    .then((data) => {
      if (data.success) {
        fetchActiveDefenseRules();
        renderBanList(); // Update standard ban list as well
        showAlert(
          "Başarılı",
          "Tüm aktif savunma kuralları temizlendi.",
          "success",
        );
      } else {
        showAlert("Hata", data.error || "Temizleme başarısız", "error");
      }
    })
    .catch((err) => showAlert("Hata", "Sunucuya bağlanılamadı.", "error"));
}

function openDNSBlocklist() {
  apiFetch("/api/dns_sinkhole/blocklist", { credentials: "same-origin" })
    .then((r) => r.json())
    .then((data) => {
      if (data.success) {
        document.getElementById("dns-blocklist-textarea").value =
          data.domains.join("\n");
        document.getElementById("dns-blocklist-modal").style.display = "block";
      } else {
        showAlert("Hata", data.error || "Blocklist alınamadı", "error");
      }
    })
    .catch((err) => showAlert("Hata", "Sunucuya bağlanılamadı.", "error"));
}

function saveDNSBlocklist() {
  const text = document.getElementById("dns-blocklist-textarea").value;
  const domains = text
    .split("\n")
    .map((d) => d.trim())
    .filter((d) => d.length > 0);

  apiFetch("/api/dns_sinkhole/blocklist", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domains: domains }),
    credentials: "same-origin",
  })
    .then((r) => r.json())
    .then((data) => {
      if (data.success) {
        document.getElementById("dns-blocklist-modal").style.display = "none";
        showAlert("Başarılı", "DNS Blocklist güncellendi.", "success");
      } else {
        showAlert("Hata", data.error || "Kaydedilemedi", "error");
      }
    })
    .catch((err) => showAlert("Hata", "Sunucuya bağlanılamadı.", "error"));
}

function toggleDHCP() {
  apiFetch("/api/gateway_mode/dhcp", {
    method: "POST",
    credentials: "same-origin",
  })
    .then((response) => response.json())
    .then((data) => {
      showNotification(
        data.success ? data.msg : data.error || "DHCP işlemi başarısız",
        data.success ? "success" : "error",
      );
      const button = document.getElementById("dhcp-mode-btn");
      if (button) button.classList.toggle("active", Boolean(data.dhcp_active));
    })
    .catch(() => showNotification("Sunucuya bağlanılamadı", "error"));
}
