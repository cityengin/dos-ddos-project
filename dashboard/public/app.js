(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const ATTACKERS = ["attacker1", "attacker2", "attacker3"];
  const REDUCE = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const SVGNS = "http://www.w3.org/2000/svg";

  let running = null, mitigation = false;

  // ---------- websocket ----------
  let ws;
  function connect() {
    ws = new WebSocket(`ws://${location.host}`);
    ws.onopen = () => setPill("pill-ws", true);
    ws.onclose = () => { setPill("pill-ws", false); setPill("pill-detector", false); setTimeout(connect, 1500); };
    ws.onmessage = (e) => { try { handle(JSON.parse(e.data)); } catch { /* */ } };
  }
  const send = (obj) => { if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj)); };
  const setPill = (id, ok) => { $(id).className = "pill " + (ok ? "ok" : "bad"); };

  // ---------- dispatch ----------
  function handle(m) {
    switch (m.type) {
      case "snapshot":
        setPill("pill-docker", m.dockerOk); applyMitigation(!!m.mitigation);
        onState(m.running ? m : { running: null });
        break;
      case "docker": setPill("pill-docker", m.up); break;
      case "detector": setPill("pill-detector", m.up); break;
      case "metric": onMetric(m.data); break;
      case "state": onState(m); break;
      case "defense": applyMitigation(m.mitigation); break;
      case "health": onHealth(m); break;
      case "bench": onBench(m); break;
      case "log": addLog(m); break;
    }
  }

  // ---------- metrics + verdict + victim ----------
  function onMetric(d) {
    setPill("pill-detector", true);
    $("m-pps").textContent = d.pps;
    $("m-syn").textContent = d.syn;
    $("m-ack").textContent = d.ack;
    $("m-nsrc").textContent = d.n_src;
    $("m-hsrc").textContent = (d.h_src || 0).toFixed(2);
    $("m-thr").textContent = `${Math.round(d.thr_pps)}/${Math.round(d.thr_syn)}`;

    const v = $("verdict"), lab = $("verdict-label"), sub = $("verdict-sub");
    if (!d.triggered) {
      v.className = "verdict safe";
      lab.textContent = "SAFE";
      sub.textContent = "no attack detected";
      setVictim("idle");
    } else {
      const ddos = d.verdict === "DDoS";
      v.className = "verdict " + (ddos ? "ddos" : "dos");
      lab.textContent = d.verdict + (d.syn_flood ? "  [SYN flood]" : "");
      sub.textContent = `n_src=${d.n_src} · H(src)=${(d.h_src || 0).toFixed(2)} · ${d.pps} pps`;
      setVictim(ddos ? "crit" : "warn");
    }
    pushChart(d);
  }

  function setVictim(level) {
    const n = $("node-victim"), halo = n.querySelector(".vhalo"), st = $("victim-state");
    n.classList.remove("warn", "crit");
    if (level === "warn") { n.classList.add("warn"); st.textContent = "under attack"; halo.classList.add("pulse"); }
    else if (level === "crit") { n.classList.add("crit"); st.textContent = "overloaded"; halo.classList.add("pulse"); }
    else { st.textContent = mitigation ? "protected" : "idle"; halo.classList.remove("pulse"); }
  }

  // ---------- attack state / topology ----------
  function onState(m) {
    running = m.running;
    ATTACKERS.forEach((a) => setLinkActive(a, false));
    document.querySelectorAll(".btn-attack").forEach((b) => b.classList.remove("running"));
    if (m.running) {
      (m.attackers || []).forEach((a) => setLinkActive(a, true, m.attackType, mitigation && m.attackType === "http"));
      const btn = document.querySelector(`.btn-attack[data-scenario="${m.running}"]`);
      if (btn) btn.classList.add("running");
      $("btn-stop").disabled = false;
    } else {
      $("btn-stop").disabled = true;
      setVictim("idle");
    }
  }

  function applyMitigation(on) {
    mitigation = on;
    $("sw-mitigation").setAttribute("aria-checked", on ? "true" : "false");
    $("node-victim").classList.toggle("protected", on);
    ATTACKERS.forEach((a) => {
      const L = linkEls[a];
      if (L.classList.contains("active")) L.classList.toggle("throttled", on && L.classList.contains("http"));
    });
  }

  function onHealth(m) {
    const ok = $("h-ok"), ms = $("h-ms");
    ok.textContent = m.ok ? "200" : "down";
    ok.className = "tile-v small " + (m.ok ? "good" : "bad");
    ms.textContent = (m.ms != null ? m.ms : "-") + "ms";
  }

  function onBench(m) {
    const btn = $("btn-bench");
    if (m.status === "running") { btn.classList.add("running"); btn.textContent = "Benchmarking…"; return; }
    btn.classList.remove("running"); btn.textContent = "Run benchmark (before/after)";
    $("bench-hint").hidden = true;
    $("bench-result").hidden = false;
    $("bench-before").textContent = m.before;
    $("bench-after").textContent = m.after;
    const max = Math.max(m.before, 1);
    $("bar-before").style.height = (100 * m.before / max) + "%";
    $("bar-after").style.height = (100 * m.after / max) + "%";
    $("bench-note").textContent = `~${m.blocked}% of attack requests blocked by rate-limit.`;
  }

  function addLog(m) {
    const ul = $("log"), li = document.createElement("li");
    li.className = m.level || "info";
    const t = document.createElement("time"); t.textContent = m.time || "";
    li.appendChild(t); li.appendChild(document.createTextNode(m.msg));
    ul.insertBefore(li, ul.firstChild);
    while (ul.children.length > 60) ul.removeChild(ul.lastChild);
  }

  // ---------- network packets (rAF particle flow) ----------
  const pktGroup = $("packets");
  const linkEls = {
    attacker1: $("link-attacker1"), attacker2: $("link-attacker2"), attacker3: $("link-attacker3"),
  };
  const pktState = {};

  function setLinkActive(name, active, type, throttled) {
    const link = linkEls[name], node = $("node-" + name);
    link.classList.toggle("active", active);
    link.classList.toggle("http", active && type === "http");
    link.classList.toggle("throttled", !!throttled);
    node.classList.toggle("active", active);
    if (active && !REDUCE) ensurePackets(name, type); else clearPackets(name);
  }
  function ensurePackets(name, type) {
    clearPackets(name);
    const dots = [];
    for (let i = 0; i < 4; i++) {
      const c = document.createElementNS(SVGNS, "circle");
      c.setAttribute("r", "3.2"); c.setAttribute("class", "packet");
      c.style.fill = type === "http" ? "#fde68a" : "#fecaca";
      pktGroup.appendChild(c);
      dots.push({ el: c, phase: i / 4 });
    }
    pktState[name] = { dots, link: linkEls[name] };
  }
  function clearPackets(name) {
    const st = pktState[name]; if (!st) return;
    st.dots.forEach((d) => d.el.remove()); delete pktState[name];
  }
  let lastT = 0;
  function animate(ts) {
    const dt = Math.min((ts - lastT) / 1000 || 0, 0.1); lastT = ts;
    const factor = mitigation ? 0.3 : 1;
    for (const name in pktState) {
      const st = pktState[name], L = st.link;
      const x1 = +L.getAttribute("x1"), y1 = +L.getAttribute("y1");
      const x2 = +L.getAttribute("x2"), y2 = +L.getAttribute("y2");
      st.dots.forEach((d) => {
        d.phase = (d.phase + dt * 0.55 * factor) % 1;
        d.el.setAttribute("cx", x1 + (x2 - x1) * d.phase);
        d.el.setAttribute("cy", y1 + (y2 - y1) * d.phase);
        d.el.style.opacity = mitigation ? 0.3 : 0.95;
      });
    }
    requestAnimationFrame(animate);
  }
  if (!REDUCE) requestAnimationFrame(animate);

  // ---------- chart ----------
  const canvas = $("chart"), ctx = canvas.getContext("2d");
  const HIST = 60, data = { pps: [], syn: [], ack: [] };
  function pushChart(d) {
    data.pps.push(d.pps); data.syn.push(d.syn); data.ack.push(d.ack);
    for (const k in data) if (data[k].length > HIST) data[k].shift();
    drawChart();
  }
  function drawChart() {
    const dpr = devicePixelRatio || 1, w = canvas.clientWidth, h = canvas.clientHeight;
    if (canvas.width !== Math.round(w * dpr)) { canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr); }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    const max = Math.max(50, ...data.pps, ...data.syn, ...data.ack);
    ctx.strokeStyle = "rgba(255,255,255,.06)"; ctx.lineWidth = 1;
    for (let i = 0; i <= 3; i++) { const y = Math.round(h * i / 3) + 0.5; ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); }
    const line = (arr, color) => {
      if (!arr.length) return;
      ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.beginPath();
      arr.forEach((v, i) => { const x = w * i / (HIST - 1), y = h - (v / max) * (h - 8) - 4; i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
      ctx.stroke();
    };
    line(data.pps, "#3b82f6"); line(data.syn, "#ef4444"); line(data.ack, "#22c55e");
  }
  addEventListener("resize", drawChart);

  // ---------- controls ----------
  document.querySelectorAll(".btn-attack").forEach((b) =>
    b.addEventListener("click", () => send({ action: "attack", scenario: b.dataset.scenario })));
  $("btn-stop").addEventListener("click", () => send({ action: "stop" }));
  $("sw-mitigation").addEventListener("click", () => send({ action: "mitigation", on: !mitigation }));
  $("btn-bench").addEventListener("click", () => send({ action: "benchmark" }));

  // ---------- init ----------
  document.querySelector(".dring").classList.add("pulse");
  drawChart();
  connect();
})();
