"use strict";
const PORT_DB = {
  7: "Echo (Test Servisi)",
  9: "Discard (Test Servisi)",
  13: "Daytime",
  20: "FTP-Data",
  21: "FTP (Şifresiz Dosya Transferi)",
  22: "SSH (Uzaktan Güvenli Erişim)",
  23: "Telnet (Şifresiz Uzaktan Erişim)",
  25: "SMTP (E-posta Gönderimi)",
  26: "RSFTP",
  37: "Time Protocol",
  53: "DNS (Alan Adı Çözümleme)",
  80: "HTTP (Web - Şifresiz)",
  110: "POP3 (E-posta Alma)",
  111: "RPCbind",
  135: "RPC (Uzak Yordam Çağrısı)",
  139: "NetBIOS (Ağ Dosya Paylaşımı)",
  143: "IMAP (E-posta Eşitleme)",
  443: "HTTPS (Güvenli Web)",
  445: "SMB (Dosya Paylaşımı / WannaCry Riski)",
  513: "rlogin (Uzaktan Giriş)",
  514: "RSH / Syslog",
  515: "LPD (Yazıcı)",
  543: "Kerberos Login",
  544: "Kerberos Shell",
  548: "AFP (Apple Dosya Paylaşımı)",
  554: "RTSP (Medya Akış)",
  993: "IMAPS (Güvenli IMAP)",
  995: "POP3S (Güvenli POP3)",
  1025: "NFS / IIS",
  1026: "Windows RPC",
  1027: "Windows RPC",
  1028: "Windows RPC",
  1029: "Windows RPC",
  1433: "MSSQL (Veritabanı)",
  1521: "Oracle DB",
  1900: "SSDP/UPnP (Cihaz Keşfi)",
  2049: "NFS (Ağ Dosya Sistemi)",
  2121: "FTP Proxy",
  3128: "Squid HTTP Proxy",
  3306: "MySQL/MariaDB (Veritabanı)",
  3389: "RDP (Uzak Masaüstü)",
  5190: "AIM/ICQ",
  5353: "mDNS (Multicast DNS)",
  5432: "PostgreSQL (Veritabanı)",
  5666: "NRPE (Nagios)",
  5800: "VNC HTTP",
  5900: "VNC (Ekran Paylaşımı)",
  6001: "X11",
  8008: "HTTP Alternatif",
  8080: "HTTP Proxy/Alternatif",
  49152: "Dinamik/Özel Port (Windows RPC)",
  49153: "Dinamik/Özel Port",
  49154: "Dinamik/Özel Port",
  49155: "Dinamik/Özel Port",
  49156: "Dinamik/Özel Port",
  49157: "Dinamik/Özel Port",
};

let devicePortData = Object.create(null);
let refreshing = false;

function showPortModal(ip, ports) {
  document.getElementById("port-modal-title").textContent =
    ip + " · Port analizi (" + ports.length + ")";
  document.getElementById("port-modal-body").innerHTML =
    ports
      .map((port) => {
        const value = String(port).trim();
        const description = PORT_DB[value] || "Dinamik / özel iletişim portu";
        return (
          '<div class="port-item"><span class="port-num">Port ' +
          escapeHtml(value) +
          '</span><span class="port-desc">' +
          escapeHtml(description) +
          "</span></div>"
        );
      })
      .join("") || '<p class="field-help">Port bilgisi bulunamadı.</p>';
  document.getElementById("port-modal").classList.add("active");
}

function closePortModal() {
  document.getElementById("port-modal").classList.remove("active");
}

async function readData(url) {
  const response = await apiFetch(url);
  if (!response.ok)
    throw new Error("Veri yüklenemedi (" + response.status + ")");
  return response.json();
}

async function refreshData() {
  if (refreshing) return;
  refreshing = true;
  const button = document.getElementById("refresh-btn");
  const status = document.getElementById("analysis-status");
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  status.textContent = "Veriler güncelleniyor…";
  const results = await Promise.allSettled([
    readData("/api/ueba_profiles").then((profiles) => {
      const body = document.getElementById("ueba-body");
      devicePortData = Object.create(null);
      body.innerHTML =
        Object.entries(profiles || {})
          .map(([ip, profile]) => {
            const ports = Array.isArray(profile.learned_ports)
              ? profile.learned_ports
              : [];
            devicePortData[ip] = ports;
            let badges = ports
              .slice(0, 15)
              .map(
                (port) =>
                  '<button type="button" class="port-badge" data-ip="' +
                  escapeHtml(ip) +
                  '" data-port="' +
                  escapeHtml(port) +
                  '">' +
                  escapeHtml(port) +
                  "</button>",
              )
              .join("");
            if (ports.length > 15)
              badges +=
                '<button class="port-badge" data-ip="' +
                escapeHtml(ip) +
                '" data-port="ALL">+' +
                (ports.length - 15) +
                " port</button>";
            const connections = Number(profile.total_connections) || 0;
            const state =
              connections <= 50
                ? '<span class="learning-status">Öğreniyor · ' +
                  connections +
                  "/50</span>"
                : '<span class="profiled-status">Profil oluşturuldu</span>';
            return (
              '<tr><td><strong class="mono">' +
              escapeHtml(ip) +
              '</strong><button class="btn-scan" data-scanip="' +
              escapeHtml(ip) +
              '">Tara</button></td><td>' +
              (badges || '<span class="subtle">Henüz bağlantı yok</span>') +
              "</td><td>" +
              state +
              "</td></tr>"
            );
          })
          .join("") ||
        '<tr><td colspan="3" class="table-empty">Henüz davranış profili yok. Öğrenilen cihazlar burada listelenir.</td></tr>';
    }),
    readData("/api/vuln_scans").then((alerts) => {
      document.getElementById("vuln-body").innerHTML =
        alerts
          .map(
            (alert) =>
              '<tr><td class="mono">' +
              escapeHtml(alert.timestamp || "—") +
              '</td><td class="mono">' +
              escapeHtml(alert.source_ip || "—") +
              '</td><td class="vuln-desc ' +
              (alert.severity === "info" ? "finding-info" : "finding-warning") +
              '">' +
              escapeHtml(alert.description || "—") +
              "</td></tr>",
          )
          .join("") ||
        '<tr><td colspan="3" class="table-empty">Henüz tarama raporu yok. Tamamlanan taramaların bulguları burada görünür.</td></tr>';
    }),
  ]);
  results.forEach((result, index) => {
    if (result.status === "rejected")
      document.getElementById(
        index === 0 ? "ueba-body" : "vuln-body",
      ).innerHTML =
        '<tr><td colspan="3" class="table-empty">Veriler alınamadı. Yenile düğmesiyle tekrar deneyin.</td></tr>';
  });
  status.textContent = results.some((result) => result.status === "rejected")
    ? "Bazı veriler güncellenemedi"
    : "Son güncelleme · " + new Date().toLocaleTimeString("tr-TR");
  button.disabled = false;
  button.removeAttribute("aria-busy");
  refreshing = false;
}

async function triggerScan(ip, button) {
  if (button) button.disabled = true;
  try {
    const response = await apiFetch("/api/scan_ip", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ ip }),
    });
    const data = await response.json();
    if (!response.ok || !data.success)
      throw new Error(data.error || "Tarama başlatılamadı");
    window.DSUI?.toast(
      ip +
        " için tarama başlatıldı. Bulgular tamamlandığında rapora yansıyacak.",
      "success",
    );
    setTimeout(refreshData, 5000);
  } catch (error) {
    window.DSUI?.toast(error.message, "error");
  } finally {
    if (button?.isConnected) button.disabled = false;
  }
}

document.addEventListener("click", (event) => {
  const badge = event.target.closest(".port-badge");
  if (badge) {
    const { ip, port } = badge.dataset;
    showPortModal(ip, port === "ALL" ? devicePortData[ip] || [] : [port]);
  }
  const scan = event.target.closest(".btn-scan");
  if (scan) triggerScan(scan.dataset.scanip, scan);
});
refreshData();
setInterval(() => {
  if (!document.hidden) refreshData();
}, 10000);
