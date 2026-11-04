(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);

  let activeScenario = null;
  let timerInterval = null;
  let startTime = null;

  // Load saved inputs from localStorage
  const inputTarget = $("input-target");
  const inputPort = $("input-port");
  const inputReflector = $("input-reflector");
  const inputPps = $("input-pps");

  if (localStorage.getItem("pbl3_target_ip")) {
    inputTarget.value = localStorage.getItem("pbl3_target_ip");
  }
  if (localStorage.getItem("pbl3_target_port")) {
    inputPort.value = localStorage.getItem("pbl3_target_port");
  }
  if (localStorage.getItem("pbl3_reflector_ip")) {
    inputReflector.value = localStorage.getItem("pbl3_reflector_ip");
  }

  function saveInputs() {
    localStorage.setItem("pbl3_target_ip", inputTarget.value.trim());
    localStorage.setItem("pbl3_target_port", inputPort.value.trim());
    localStorage.setItem("pbl3_reflector_ip", inputReflector.value.trim());
  }

  // 1. WebSocket Client
  let ws = null;
  function connectWs() {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(`${proto}//${location.host}`);

    ws.onopen = () => {
      console.log("[WS] Connected to generator server");
    };

    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        handleWsMessage(msg);
      } catch (e) {}
    };

    ws.onclose = () => {
      console.log("[WS] Disconnected, reconnecting in 2s...");
      setTimeout(connectWs, 2000);
    };
  }

  function handleWsMessage(msg) {
    if (msg.type === "init") {
      if (msg.data.logs) {
        $("console-box").innerHTML = "";
        msg.data.logs.forEach(appendLog);
      }
      applyStatus(msg.data.scenario);
    } else if (msg.type === "status") {
      applyStatus(msg.data.scenario);
    } else if (msg.type === "log") {
      appendLog(msg.data);
    }
  }

  // 2. Pre-flight Target Check
  $("btn-check-target").addEventListener("click", async () => {
    saveInputs();
    const target = inputTarget.value.trim();
    const port = inputPort.value.trim() || 80;

    if (!target) {
      alert("Vui lòng nhập IP máy nạn nhân (Victim IP)");
      return;
    }

    const btn = $("btn-check-target");
    btn.disabled = true;
    btn.querySelector("span").textContent = "Đang kiểm tra...";

    const banner = $("check-result-banner");
    const badgePing = $("badge-ping");
    const badgeHttp = $("badge-http");
    const msg = $("check-result-msg");
    const targetPill = $("target-pill");
    const targetPillText = $("target-pill-text");

    banner.style.display = "flex";
    badgePing.className = "res-badge";
    badgePing.textContent = "Ping: ...";
    badgeHttp.className = "res-badge";
    badgeHttp.textContent = "HTTP: ...";
    msg.textContent = "Đang gửi gói tin thăm dò...";

    try {
      const res = await fetch("/api/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, port }),
      });
      const data = await res.json();

      btn.disabled = false;
      btn.querySelector("span").textContent = "Kiểm tra Kết nối";

      if (!data.ok && data.error) {
        msg.textContent = `Lỗi: ${data.error}`;
        return;
      }

      // Ping badge
      if (data.ping && data.ping.ok) {
        badgePing.className = "res-badge success";
        badgePing.textContent = `Ping: ${data.ping.ms} ms`;
      } else {
        badgePing.className = "res-badge danger";
        badgePing.textContent = "Ping: Lỗi";
      }

      // HTTP badge
      if (data.http && data.http.ok) {
        badgeHttp.className = "res-badge success";
        badgeHttp.textContent = `HTTP ${data.http.code} (${data.http.ms} ms)`;
      } else {
        badgeHttp.className = "res-badge danger";
        badgeHttp.textContent = data.http.error ? `HTTP: ${data.http.error}` : "HTTP: Lỗi";
      }

      // Diagnosis
      if (data.ping.ok && data.http.ok) {
        msg.textContent = `🟢 SẴN SÀNG: Mục tiêu ${target}:${port} phản hồi tốt. Đã có thể bắt đầu các kịch bản thử nghiệm bên dưới.`;
        targetPill.className = "status-pill online";
        targetPillText.textContent = `Target: ${target} (UP 200)`;
      } else if (data.ping.ok && !data.http.ok) {
        msg.textContent = `🟡 CẢNH BÁO: Mạng nội bộ thông (Ping OK), nhưng Web Server trên cổng ${port} không phản hồi. Kiểm tra lại Nginx trên Victim.`;
        targetPill.className = "status-pill offline";
        targetPillText.textContent = `Target: ${target} (Web Down)`;
      } else {
        msg.textContent = `🔴 KHÔNG TỒN TẠI: Không thể ping tới ${target}. Kiểm tra xem 2 máy đã kết nối chung Wi-Fi chưa hoặc kiểm tra lại địa chỉ IP.`;
        targetPill.className = "status-pill offline";
        targetPillText.textContent = `Target: ${target} (Unreachable)`;
      }
    } catch (e) {
      btn.disabled = false;
      btn.querySelector("span").textContent = "Kiểm tra Kết nối";
      msg.textContent = `Lỗi kết nối máy chủ: ${e.message}`;
    }
  });

  // 3. Scenario Trigger Buttons
  document.querySelectorAll(".btn-scenario").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const scen = btn.getAttribute("data-scenario");
      if (activeScenario && activeScenario.name === scen) {
        // Clicking running scenario stops it
        stopAttack();
        return;
      }
      startAttack(scen);
    });
  });

  async function startAttack(scenario) {
    saveInputs();
    const target = inputTarget.value.trim();
    const port = parseInt(inputPort.value.trim() || 80, 10);
    const reflector = inputReflector.value.trim() || "172.30.0.30";
    const pps = parseInt(inputPps.value.trim() || 200, 10);

    if (!target) {
      alert("Vui lòng nhập IP máy nạn nhân trước khi kích hoạt.");
      inputTarget.focus();
      return;
    }

    try {
      const res = await fetch("/api/attack/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario, target, port, reflector, pps }),
      });
      const data = await res.json();
      if (!data.ok) {
        alert("Lỗi: " + (data.error || "Không thể khởi chạy kịch bản"));
      }
    } catch (e) {
      alert("Lỗi kết nối tới máy chủ điều khiển: " + e.message);
    }
  }

  // 4. Stop Attack Button
  $("btn-stop-all").addEventListener("click", stopAttack);

  async function stopAttack() {
    try {
      await fetch("/api/attack/stop", { method: "POST" });
    } catch (e) {
      console.error(e);
    }
  }

  // 5. Apply Status Update
  function applyStatus(scen) {
    activeScenario = scen;
    const attackPill = $("attack-pill");
    const attackPillText = $("attack-pill-text");
    const timerBox = $("running-timer");

    // Reset all scenario cards
    document.querySelectorAll(".scenario-card").forEach((card) => {
      card.classList.remove("active");
      const b = card.querySelector(".btn-scenario");
      if (b) {
        const name = b.getAttribute("data-scenario");
        b.innerHTML = `<span class="btn-icon">▶</span><span>Kích hoạt Kịch bản ${name}</span>`;
      }
    });

    if (scen) {
      attackPill.className = "status-pill active";
      attackPillText.textContent = `ĐANG PHÁT: ${scen.name} (${scen.pps} pps)`;

      const card = $(`card-scen-${scen.name}`);
      if (card) {
        card.classList.add("active");
        const b = card.querySelector(".btn-scenario");
        if (b) {
          b.innerHTML = `<span class="btn-icon">⏹</span><span>Đang phát tải &middot; Nhấn để DỪNG</span>`;
        }
      }

      // Start timer
      timerBox.style.display = "flex";
      startTime = scen.startTime || Date.now();
      if (!timerInterval) {
        timerInterval = setInterval(updateTimer, 1000);
      }
      updateTimer();
    } else {
      attackPill.className = "status-pill idle";
      attackPillText.textContent = "Trạng thái: IDLE";
      timerBox.style.display = "none";
      if (timerInterval) {
        clearInterval(timerInterval);
        timerInterval = null;
      }
    }
  }

  function updateTimer() {
    if (!startTime) return;
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    const m = String(Math.floor(elapsed / 60)).padStart(2, "0");
    const s = String(elapsed % 60).padStart(2, "0");
    $("timer-text").textContent = `${m}:${s}`;
  }

  // 6. Logging
  function appendLog(item) {
    const box = $("console-box");
    const div = document.createElement("div");
    div.className = `log-line ${item.level || "info"}`;
    div.innerHTML = `<span class="log-time">[${item.time}]</span> ${escapeHtml(item.msg)}`;
    box.appendChild(div);
    box.scrollTop = box.scrollHeight;
  }

  $("btn-clear-log").addEventListener("click", () => {
    $("console-box").innerHTML = "";
  });

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  // Init
  connectWs();
})();
