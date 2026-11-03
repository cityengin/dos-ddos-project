(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);

  // Configuration for 10 rolling charts (60 points each, 1 per second)
  const HISTORY_LEN = 60;
  const METRICS = [
    { key: "pps", id: "chart-pps", valId: "val-pps", statsId: "stats-pps", color: "#4f46e5", unit: "pkts/s", decimals: 0 },
    { key: "syn", id: "chart-syn", valId: "val-syn", statsId: "stats-syn", color: "#7c3aed", unit: "syn/s", decimals: 0 },
    { key: "ack", id: "chart-ack", valId: "val-ack", statsId: "stats-ack", color: "#059669", unit: "ack/s", decimals: 0 },
    { key: "udp", id: "chart-udp", valId: "val-udp", statsId: "stats-udp", color: "#0284c7", unit: "udp/s", decimals: 0 },
    { key: "h_src", id: "chart-hsrc", valId: "val-hsrc", statsId: "stats-hsrc", color: "#d97706", unit: "bits", decimals: 2 },
    { key: "h_dport", id: "chart-hdport", valId: "val-hdport", statsId: "stats-hdport", color: "#ea580c", unit: "bits", decimals: 2 },
    { key: "n_src", id: "chart-nsrc", valId: "val-nsrc", statsId: "stats-nsrc", color: "#e11d48", unit: "IPs", decimals: 0 },
    { key: "syn_ratio", id: "chart-synratio", valId: "val-synratio", statsId: "stats-synratio", color: "#c026d3", unit: "ratio", decimals: 2 },
    { key: "ack_syn_ratio", id: "chart-acksynratio", valId: "val-acksynratio", statsId: "stats-acksynratio", color: "#0d9488", unit: "ratio", decimals: 2 },
    { key: "rate_per_src", id: "chart-ratepersrc", valId: "val-ratepersrc", statsId: "stats-ratepersrc", color: "#f43f5e", unit: "pkts/s/src", decimals: 1 },
  ];

  // Initialize history queues with zeros
  const history = {};
  METRICS.forEach((m) => {
    history[m.key] = new Array(HISTORY_LEN).fill(0);
  });

  // ---------- WebSocket Connection ----------
  let ws = null;

  function connect() {
    const loc = window.location;
    const proto = loc.protocol === "https:" ? "wss:" : "ws:";
    const url = `${proto}//${loc.host}`;
    ws = new WebSocket(url);

    ws.onopen = () => {
      setPill("pill-ws", true, "Connected");
    };

    ws.onclose = () => {
      setPill("pill-ws", false, "Disconnected");
      setPill("pill-detector", false, "Offline");
      setTimeout(connect, 2000);
    };

    ws.onerror = () => {
      setPill("pill-ws", false, "Error");
    };

    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        handleMessage(msg);
      } catch (e) {
        console.error("Failed to parse message:", e);
      }
    };
  }

  function setPill(id, isOnline, text) {
    const el = $(id);
    if (!el) return;
    el.className = "status-pill " + (isOnline ? "online" : "offline");
    if (text) {
      const txtEl = el.querySelector(".status-text");
      if (txtEl) txtEl.textContent = text;
    }
  }

  // ---------- Message Dispatcher ----------
  function handleMessage(msg) {
    switch (msg.type) {
      case "snapshot":
        setPill("pill-detector", !!msg.detectorOnline, msg.detectorOnline ? "Detector Online" : "Detector Standby");
        if (msg.health) {
          onHealthReceived(msg.health);
        }
        if (msg.events && Array.isArray(msg.events)) {
          const list = $("log-list");
          list.innerHTML = "";
          msg.events.forEach((evt) => appendEventLog(evt, false));
        }
        if (msg.history && Array.isArray(msg.history) && msg.history.length > 0) {
          msg.history.forEach((data) => {
            onMetricReceived(data);
          });
        }
        break;

      case "detector":
        setPill("pill-detector", !!msg.up, msg.up ? "Detector Online" : "Detector Offline");
        break;

      case "metric":
        onMetricReceived(msg.data);
        break;

      case "event":
        appendEventLog(msg.data, true);
        break;

      case "health":
        onHealthReceived(msg);
        break;

      case "sim_status":
        updateSimUI(msg);
        break;

      case "clear_logs":
        $("log-list").innerHTML = "";
        break;
    }
  }

  // ---------- Metric Handler & UI Updates ----------
  function onMetricReceived(d) {
    setPill("pill-detector", true, "Detector Active");

    // 1. Update rolling history
    METRICS.forEach((m) => {
      let val = d[m.key];
      if (val === undefined || val === null) {
        if (m.key === "syn_ratio") val = (d.syn || 0) / Math.max(d.pps || 0, 1.0);
        else if (m.key === "ack_syn_ratio") val = (d.ack || 0) / Math.max(d.syn || 0, 1.0);
        else if (m.key === "rate_per_src") val = (d.pps || 0) / Math.max(d.n_src || 0, 1);
        else val = 0;
      }
      history[m.key].push(Number(val));
      if (history[m.key].length > HISTORY_LEN) history[m.key].shift();

      // Update text values
      const valEl = $(m.valId);
      if (valEl) {
        const displayVal = m.decimals > 0 ? Number(val).toFixed(m.decimals) : Math.round(Number(val));
        valEl.innerHTML = `${displayVal} <span class="unit">${m.unit}</span>`;
      }

      // Update min/max footer
      const statsEl = $(m.statsId);
      if (statsEl) {
        const arr = history[m.key];
        const maxVal = Math.max(...arr);
        const avgVal = arr.reduce((a, b) => a + b, 0) / arr.length;
        if (m.decimals > 0) {
          statsEl.textContent = `max: ${maxVal.toFixed(m.decimals)} · avg: ${avgVal.toFixed(m.decimals)}`;
        } else {
          statsEl.textContent = `max: ${Math.round(maxVal)} · avg: ${Math.round(avgVal)}`;
        }
      }
    });

    // 2. Update Verdict Banner
    updateVerdictBanner(d);

    // 3. Update Attacker IPs Table
    updateAttackerTable(d);

    // 4. Render Canvas Charts
    renderAllCharts();
  }

  // ---------- Update Classification Banner ----------
  function updateVerdictBanner(d) {
    const banner = $("main-verdict-banner");
    const primaryText = $("verdict-primary-text");
    const attackTypeTag = $("verdict-attack-type");
    const descText = $("verdict-desc-text");
    const icon = $("verdict-icon");

    const ruleVal = $("rule-val");
    const mlVal = $("ml-val");
    const mlConf = $("ml-conf");
    const nsrcVal = $("nsrc-val");
    const entropySub = $("entropy-sub");

    const isTriggered = !!d.triggered;
    const verdict = isTriggered ? (d.verdict || "DoS") : "BENIGN";
    const ddos = verdict === "DDoS";

    let attackType = d.attackType;
    if (!attackType) {
      if (d.syn_flood) attackType = "SYN Flood (L4)";
      else if (d.udp_flood) attackType = "UDP Flood (L4)";
      else if ((d.ack || 0) > 0 || (d.syn || 0) > 0) attackType = "HTTP Flood (L7)";
      else if (isTriggered) attackType = "Volumetric / ICMP Flood (L3)";
    }

    if (!isTriggered) {
      banner.className = "verdict-banner safe";
      primaryText.textContent = "BENIGN";
      attackTypeTag.textContent = "An toàn · Không có tấn công";
      descText.textContent = "Lưu lượng mạng trong giới hạn an toàn. Không phát hiện bất thường.";
      icon.innerHTML = `<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
        <polyline points="22 4 12 14.01 9 11.01"/>
      </svg>`;
      ruleVal.textContent = "BENIGN";
      ruleVal.style.color = "#15803d";
      const srcTitle = $("source-table-title");
      if (srcTitle) {
        srcTitle.textContent = "Nguồn Lưu lượng IP Hoạt động (Top Active Sources)";
        srcTitle.style.color = "";
      }
    } else {
      banner.className = "verdict-banner " + (ddos ? "crit" : "warn");
      primaryText.textContent = verdict;
      attackTypeTag.textContent = attackType || "Threat Detected";
      descText.textContent = ddos
        ? `Tấn công Từ chối Dịch vụ Phân tán (DDoS) từ ${d.n_src} địa chỉ nguồn khác nhau!`
        : `Tấn công Từ chối Dịch vụ (DoS) tập trung từ 1 địa chỉ nguồn!`;
      icon.innerHTML = `<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
        <line x1="12" y1="9" x2="12" y2="13"/>
        <line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg>`;
      ruleVal.textContent = verdict + (attackType ? ` [${attackType.split(' ')[0]}]` : "");
      ruleVal.style.color = ddos ? "#b91c1c" : "#b45309";
      const srcTitle = $("source-table-title");
      if (srcTitle) {
        srcTitle.textContent = "Địa chỉ IP Tấn công (Top Attacker IPs)";
        srcTitle.style.color = "#dc2626";
      }
    }

    // Machine Learning Prediction
    if (d.ml_verdict) {
      const mlLvl = d.ml_verdict === "DDoS" ? "#b91c1c" : (d.ml_verdict === "DoS" ? "#b45309" : "#15803d");
      if (d.ml_verdict !== "BENIGN" && attackType) {
        const shortType = attackType.replace(/\s*\(L\d\)/, "");
        mlVal.innerHTML = `${d.ml_verdict} <span class="vbox-type">(${shortType})</span>`;
      } else {
        mlVal.textContent = d.ml_verdict;
      }
      mlVal.style.color = mlLvl;
      mlConf.textContent = d.ml_conf != null ? `Confidence: ${Math.round(d.ml_conf * 100)}%` : "Active";
    } else {
      mlVal.textContent = "Standby (No model)";
      mlVal.style.color = "#64748b";
      mlConf.textContent = "Run train_window.py to activate";
    }

    // Source count & Entropy
    nsrcVal.textContent = d.n_src || 0;
    entropySub.textContent = `H(src): ${(d.h_src || 0).toFixed(2)} | H(dst): ${(d.h_dport || 0).toFixed(2)}`;

    // Dynamic Rule Thresholds
    const ruleSub = $("rule-sub");
    if (ruleSub && d.thr_pps !== undefined) {
      ruleSub.textContent = `Ngưỡng: pps ≥ ${d.thr_pps} | syn ≥ ${d.thr_syn}`;
    }

    // eBPF/XDP Mitigation display
    const blockedVal = $("blocked-val");
    const blockedSub = $("blocked-sub");
    if (blockedVal) {
      const bPps = d.blocked_pps || 0;
      const bSrc = d.blocked_src || 0;
      blockedVal.innerHTML = `${bPps.toLocaleString()} <span class="unit">drop/s</span>`;
      blockedVal.style.color = bPps > 0 ? "#dc2626" : "#64748b";
      if (blockedSub) {
        blockedSub.textContent = bPps > 0 ? `Active: ${bSrc} sources blocked` : "Detect-Only Mode";
      }
    }
  }

  // ---------- Update Attacker IPs Table ----------
  function updateAttackerTable(d) {
    const tbody = $("attacker-table-body");
    const countBadge = $("active-ip-count");
    const spoofBanner = $("spoof-banner");
    const spoofBannerText = $("spoof-banner-text");

    const totalPps = Math.max(d.pps || 0, 1);
    const topSources = d.top_sources || [];
    const nSrc = d.n_src || 0;

    countBadge.textContent = `${nSrc} IPs Active`;

    // Show spoof warning banner if dispersion is high (> 10 sources)
    if (nSrc > 10) {
      spoofBanner.style.display = "flex";
      spoofBannerText.textContent = `Cảnh báo IP Spoofing / Phân tán cao: Có ${nSrc.toLocaleString()} địa chỉ IP nguồn ngẫu nhiên trong cửa sổ hiện tại. Dưới đây là Top nguồn lưu lượng lớn nhất.`;
    } else {
      spoofBanner.style.display = "none";
    }

    if (topSources.length === 0) {
      tbody.innerHTML = `
        <tr class="empty-row">
          <td colspan="5">
            <div class="empty-state">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" stroke-width="1.5">
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="8" x2="12" y2="12"/>
                <line x1="12" y1="16" x2="12.01" y2="16"/>
              </svg>
              <p>Hiện không có lưu lượng mạng đáng chú ý. Hệ thống an toàn.</p>
            </div>
          </td>
        </tr>`;
      return;
    }

    let rowsHtml = "";
    topSources.forEach((src, idx) => {
      const pps = src.pps || 0;
      const count = src.count || 0;
      const percent = Math.min(100, Math.round((pps / totalPps) * 100));

      const isSuspect = d.triggered && pps >= 20;
      const badgeHtml = isSuspect
        ? `<span class="ip-badge">${d.verdict === "DDoS" ? "DDoS Source" : "Attacker"}</span>`
        : `<span class="badge badge-subtle">Active</span>`;

      rowsHtml += `
        <tr>
          <td class="mono" style="color: #64748b; font-weight: 600;">#${idx + 1}</td>
          <td>
            <div class="ip-cell">
              <span class="ip-text">${src.ip}</span>
              ${badgeHtml}
            </div>
          </td>
          <td class="mono font-semibold" style="color: ${isSuspect ? '#dc2626' : '#1e293b'};">${pps.toLocaleString()} <span style="font-size: 0.72rem; color: #94a3b8;">pps</span></td>
          <td class="mono" style="color: #64748b;">${count.toLocaleString()}</td>
          <td>
            <div class="bar-wrap">
              <div class="bar-track">
                <div class="bar-fill" style="width: ${percent}%; background: ${isSuspect ? '#ef4444' : '#3b82f6'};"></div>
              </div>
              <span class="mono" style="font-size: 0.75rem; color: #64748b; min-width: 32px;">${percent}%</span>
            </div>
          </td>
        </tr>`;
    });

    tbody.innerHTML = rowsHtml;
  }

  // ---------- Security Event Log ----------
  function appendEventLog(evt, prepend = true) {
    const list = $("log-list");
    if (!list) return;

    const item = document.createElement("div");
    item.className = `log-item ${evt.level || "info"}`;
    item.innerHTML = `
      <div class="log-time">${evt.time || new Date().toLocaleTimeString()}</div>
      <div class="log-body">
        <div class="log-title">${escapeHtml(evt.title || "Event")}</div>
        <div class="log-detail">${escapeHtml(evt.detail || "")}</div>
      </div>
    `;

    if (prepend && list.firstChild) {
      list.insertBefore(item, list.firstChild);
    } else {
      list.appendChild(item);
    }

    // Limit log elements in DOM to 100
    while (list.children.length > 100) {
      list.removeChild(list.lastChild);
    }
  }

  $("btn-clear-logs").addEventListener("click", () => {
    $("log-list").innerHTML = "";
    if (ws && ws.readyState === 1) {
      ws.send(JSON.stringify({ action: "clear_logs" }));
    }
  });

  // ---------- Victim Service Health ----------
  function onHealthReceived(msg) {
    const badge = $("health-status");
    const msEl = $("health-ms");
    if (!badge || !msEl) return;

    if (msg.ok) {
      badge.className = "health-badge up";
      badge.textContent = `UP (${msg.status})`;
      msEl.textContent = msg.ms != null ? `${msg.ms} ms` : "OK";
    } else {
      badge.className = "health-badge down";
      badge.textContent = msg.status === "ERR" ? "DOWN (Offline)" : `ERR (${msg.status})`;
      msEl.textContent = msg.ms ? `${msg.ms} ms` : "No reply";
    }
  }

  // ---------- High-Performance HTML5 Canvas Charts ----------
  function renderAllCharts() {
    METRICS.forEach((m) => {
      renderSparkline(m.id, history[m.key], m.color, m.decimals);
    });
  }

  function renderSparkline(canvasId, data, color, decimals) {
    const canvas = $(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    // Handle high-DPI retina display
    const dpr = window.devicePixelRatio || 1;
    const width = canvas.parentElement.clientWidth || 220;
    const height = canvas.parentElement.clientHeight || 52;

    if (canvas.width !== width * dpr || canvas.height !== height * dpr) {
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      canvas.style.width = width + "px";
      canvas.style.height = height + "px";
    }

    ctx.save();
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, width, height);

    const padLeft = 6;
    const padRight = 6;
    const padTop = 4;
    const padBottom = 6;
    const plotW = width - padLeft - padRight;
    const plotH = height - padTop - padBottom;

    const maxVal = Math.max(...data, 1);
    const minVal = 0;
    const range = maxVal - minVal || 1;

    // 1. Draw subtle horizontal grid lines (3 lines)
    ctx.strokeStyle = "#f1f5f9";
    ctx.lineWidth = 0.5;
    for (let i = 0; i <= 2; i++) {
      const y = padTop + (plotH / 2) * i;
      ctx.beginPath();
      ctx.moveTo(padLeft, y);
      ctx.lineTo(width - padRight, y);
      ctx.stroke();
    }

    // 2. Map coordinates
    const points = data.map((val, idx) => {
      const x = padLeft + (idx / (HISTORY_LEN - 1)) * plotW;
      const y = padTop + plotH - ((val - minVal) / range) * plotH;
      return { x, y };
    });

    if (points.length < 2) {
      ctx.restore();
      return;
    }

    // 3. Draw gradient filled area
    const grad = ctx.createLinearGradient(0, padTop, 0, padTop + plotH);
    grad.addColorStop(0, hexToRgba(color, 0.12));
    grad.addColorStop(1, hexToRgba(color, 0.0));

    ctx.beginPath();
    ctx.moveTo(points[0].x, padTop + plotH);
    ctx.lineTo(points[0].x, points[0].y);

    for (let i = 0; i < points.length - 1; i++) {
      const xc = (points[i].x + points[i + 1].x) / 2;
      const yc = (points[i].y + points[i + 1].y) / 2;
      ctx.quadraticCurveTo(points[i].x, points[i].y, xc, yc);
    }
    ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);
    ctx.lineTo(points[points.length - 1].x, padTop + plotH);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // 4. Draw smooth stroke curve (thin & sharp)
    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 0; i < points.length - 1; i++) {
      const xc = (points[i].x + points[i + 1].x) / 2;
      const yc = (points[i].y + points[i + 1].y) / 2;
      ctx.quadraticCurveTo(points[i].x, points[i].y, xc, yc);
    }
    ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.0;
    ctx.stroke();

    // 5. Draw pulse point at latest value
    const lastPoint = points[points.length - 1];
    ctx.beginPath();
    ctx.arc(lastPoint.x, lastPoint.y, 1.8, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
    ctx.beginPath();
    ctx.arc(lastPoint.x, lastPoint.y, 3.2, 0, Math.PI * 2);
    ctx.strokeStyle = hexToRgba(color, 0.35);
    ctx.lineWidth = 0.8;
    ctx.stroke();

    ctx.restore();
  }

  // Helper
  function hexToRgba(hex, alpha) {
    hex = hex.replace("#", "");
    const r = parseInt(hex.substring(0, 2), 16);
    const g = parseInt(hex.substring(2, 4), 16);
    const b = parseInt(hex.substring(4, 6), 16);
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Handle window resize for canvas responsiveness
  window.addEventListener("resize", () => {
    renderAllCharts();
  });

  // ---------- Benign User Simulator Controller ----------
  function updateSimUI(data) {
    if (!data) return;
    const btn = $("btn-sim-toggle");
    const txt = $("sim-text");
    if (!btn || !txt) return;

    if (data.running) {
      btn.className = "sim-pill active";
      const uCount = data.activeUsers || data.targetUsers || 20;
      txt.textContent = `Users: ~${uCount}`;
      btn.title = `Đang mô phỏng ${uCount} người dùng ngẫu nhiên (ra vào tự nhiên). Nhấp để Tắt.`;
    } else {
      btn.className = "sim-pill";
      txt.textContent = "Users: OFF";
      btn.title = "Mô phỏng người dùng đang Tắt. Nhấp để Bật.";
    }
  }

  const btnSim = $("btn-sim-toggle");
  if (btnSim) {
    btnSim.addEventListener("click", () => {
      btnSim.style.opacity = "0.6";
      fetch("/api/sim/toggle", { method: "POST" })
        .then((r) => r.json())
        .then((res) => {
          btnSim.style.opacity = "1";
          if (res && res.running !== undefined) {
            updateSimUI({ running: res.running });
          }
        })
        .catch(() => {
          btnSim.style.opacity = "1";
        });
    });
  }

  // Initial fetch for simulator status
  fetch("/api/sim/status")
    .then((r) => r.json())
    .then(updateSimUI)
    .catch(() => {});

  // Start connection
  connect();
})();
