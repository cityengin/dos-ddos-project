// Bare-metal Realtime Victim Defense Console backend.
// Designed for single-machine or multi-machine (WiFi/LAN) deployments.
"use strict";

const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const readline = require("readline");
const { spawn } = require("child_process");
const { WebSocketServer } = require("ws");

// Parse CLI args (e.g. node server.js --iface wlan0 --victim 192.168.1.50 --port 3000)
const args = process.argv.slice(2);
function getArg(flag, fallback) {
  const idx = args.indexOf(flag);
  if (idx >= 0 && idx + 1 < args.length) return args[idx + 1];
  return fallback;
}
const hasFlag = (flag) => args.includes(flag);

const PORT = parseInt(getArg("--port", process.env.PORT || "3000"), 10);
const HOST = getArg("--host", process.env.HOST || "0.0.0.0");
const IFACE = getArg("--iface", process.env.IFACE || "");
const VICTIM = getArg("--victim", process.env.VICTIM || "");
const PPS_THR = getArg("--pps", process.env.PPS || "40");
const SYN_THR = getArg("--syn", process.env.SYN || "25");
const ENGINE = getArg("--engine", process.env.ENGINE || "scapy");
const NO_SPAWN = hasFlag("--no-spawn") || process.env.NO_SPAWN === "1";

const ROOT_DIR = path.join(__dirname, "..");
const DETECTOR_SCRIPT = path.join(ROOT_DIR, "detection", "detector.py");
const ML_MODEL = path.join(ROOT_DIR, "detection", "window_model.joblib");

let detectorProc = null;
let detectorOnline = false;
let lastVerdict = "BENIGN";
let lastAttackType = null;
let wss = null;
const eventLog = []; // in-memory event log (last 100 events)

function addEvent(level, title, detail, verdict = "BENIGN", attackType = null) {
  const evt = {
    id: Date.now() + "_" + Math.random().toString(36).substr(2, 5),
    time: new Date().toLocaleTimeString(),
    timestamp: Date.now(),
    level, // 'safe', 'warn', 'crit', 'info'
    title,
    detail,
    verdict,
    attackType,
  };
  eventLog.unshift(evt);
  if (eventLog.length > 100) eventLog.pop();
  broadcast({ type: "event", data: evt });
}

// Initial system event
addEvent("info", "Console Initialized", `Monitoring server active on ${HOST}:${PORT}. Ready for traffic analysis.`);

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// REST API for external metric ingestion (if piped or pushed from external script)
app.post("/api/metric", (req, res) => {
  if (req.body && typeof req.body === "object") {
    handleDetectorMetric(req.body);
    res.json({ ok: true });
  } else {
    res.status(400).json({ error: "Invalid metric format" });
  }
});

app.get("/api/status", (req, res) => {
  res.json({
    detectorOnline,
    iface: IFACE || "default",
    victim: VICTIM || "all",
    eventCount: eventLog.length,
  });
});

const server = http.createServer(app);
wss = new WebSocketServer({ server });

function broadcast(obj) {
  if (typeof wss === "undefined" || !wss || !wss.clients) return;
  const msg = JSON.stringify(obj);
  wss.clients.forEach((client) => {
    if (client.readyState === 1) client.send(msg);
  });
}

// Process incoming metric from detector
function handleDetectorMetric(d) {
  detectorOnline = true;

  // Determine current verdict and type
  const isTriggered = !!d.triggered;
  const currentVerdict = isTriggered ? (d.verdict || "DoS") : "BENIGN";
  let attackType = null;
  if (isTriggered) {
    if (d.syn_flood) attackType = "SYN Flood (L4)";
    else if (d.udp_flood) attackType = "UDP Flood (L4)";
    else if ((d.ack || 0) > 0 || (d.syn || 0) > 0) attackType = "HTTP Flood (L7)";
    else attackType = "Volumetric / ICMP Flood (L3)";
  }

  // Detect state transitions to emit security log events
  if (currentVerdict !== lastVerdict || attackType !== lastAttackType) {
    if (isTriggered) {
      const level = currentVerdict === "DDoS" ? "crit" : "warn";
      const srcText = d.n_src ? `${d.n_src} source(s)` : "unknown sources";
      const topSrc = d.top_sources && d.top_sources.length > 0 ? d.top_sources[0].ip : "multiple";
      addEvent(
        level,
        `Threat Detected: ${currentVerdict} - ${attackType}`,
        `Rate: ${d.pps || 0} pps, ${srcText}. Primary sender: ${topSrc} (Entropy H(src)=${(d.h_src || 0).toFixed(2)})`,
        currentVerdict,
        attackType
      );
    } else if (lastVerdict !== "BENIGN") {
      addEvent("safe", "Threat Mitigated / Traffic Normalized", "Traffic rate has fallen below trigger threshold. System is BENIGN.", "BENIGN", null);
    }
    lastVerdict = currentVerdict;
    lastAttackType = attackType;
  }

  // Broadcast metric data
  broadcast({
    type: "metric",
    data: {
      ...d,
      attackType,
    },
  });
}

// Line buffer parser for detector stdout / stdin
function createLineParser(onLine) {
  let buf = "";
  return function (chunk) {
    buf += chunk.toString();
    let idx;
    while ((idx = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (line) onLine(line);
    }
  };
}

function processDetectorJsonLine(line) {
  try {
    const data = JSON.parse(line);
    handleDetectorMetric(data);
  } catch (err) {
    // Non-JSON output (e.g. startup banner / log)
    if (line.includes("[*]") || line.includes("[!]")) {
      addEvent("info", "Detector Notice", line);
    }
  }
}

// 1. Support piped STDIN: e.g. "sudo python3 detector.py --stream | node server.js"
if (!process.stdin.isTTY) {
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  rl.on("line", (line) => {
    if (line.trim()) processDetectorJsonLine(line.trim());
  });
  console.log("[dashboard] Reading detector stream from STDIN.");
}

// 2. Bare-metal automatic spawn of detector.py
function findPythonCommand() {
  if (process.env.PYTHON) return process.env.PYTHON;
  const venvPy = path.join(ROOT_DIR, ".venv", "bin", "python3");
  if (fs.existsSync(venvPy)) return venvPy;
  return process.platform === "win32" ? "python" : "python3";
}

function startDetector() {
  if (NO_SPAWN || !process.stdin.isTTY) return;
  if (detectorProc) return;

  const pythonCmd = findPythonCommand();
  const detArgs = [DETECTOR_SCRIPT, "--stream"];
  if (IFACE) detArgs.push("--iface", IFACE);
  if (VICTIM) detArgs.push("--victim", VICTIM);
  if (PPS_THR) detArgs.push("--pps", String(PPS_THR));
  if (SYN_THR) detArgs.push("--syn", String(SYN_THR));
  if (ENGINE) detArgs.push("--engine", ENGINE);

  // Check if ML model is trained and available
  if (fs.existsSync(ML_MODEL)) {
    detArgs.push("--ml", ML_MODEL);
    console.log(`[dashboard] ML model detected at ${ML_MODEL}, enabling --ml.`);
  }

  console.log(`[dashboard] Spawning detector: ${pythonCmd} ${detArgs.join(" ")}`);
  try {
    detectorProc = spawn(pythonCmd, detArgs, {
      cwd: ROOT_DIR,
      windowsHide: true,
    });

    const parser = createLineParser(processDetectorJsonLine);
    detectorProc.stdout.on("data", parser);

    detectorProc.stderr.on("data", (d) => {
      const errStr = d.toString().trim();
      if (errStr) {
        console.error(`[detector-err] ${errStr}`);
        addEvent("warn", "Detector Warning", errStr);
      }
    });

    detectorProc.on("error", (err) => {
      console.error(`[dashboard] Failed to spawn detector (${pythonCmd}):`, err.message);
      addEvent("warn", "Detector Spawn Error", `Cannot run ${pythonCmd}: ${err.message}. If running bare-metal with sudo, run detector in terminal and pipe: 'sudo python3 detection/detector.py --stream | node server.js'.`);
      detectorProc = null;
      detectorOnline = false;
      broadcast({ type: "detector", up: false });
    });

    detectorProc.on("exit", (code, sig) => {
      console.log(`[dashboard] Detector process exited with code ${code}, sig ${sig}`);
      detectorProc = null;
      detectorOnline = false;
      broadcast({ type: "detector", up: false });
      if (code !== 0) {
        console.log(`[dashboard] Tip: If detector needs sudo/scapy on host, run in terminal: 'sudo python3 detection/detector.py --stream | node dashboard/server.js' or 'node server.js --no-spawn'.`);
      }
    });

    detectorOnline = true;
    broadcast({ type: "detector", up: true });
    addEvent("info", "Detector Attached", `Sniffing on interface ${IFACE || "default"}, target ${VICTIM || "all"}`);
  } catch (err) {
    console.error("[dashboard] Exception spawning detector:", err.message);
  }
}

// 3. Victim Service Health Probe (checks local Nginx/Web Server availability)
const PROBE_TARGET = VICTIM || "127.0.0.1";
setInterval(() => {
  const startTime = Date.now();
  const req = http.get(`http://${PROBE_TARGET}:80/`, { timeout: 2000 }, (res) => {
    const latency = Date.now() - startTime;
    const ok = res.statusCode >= 200 && res.statusCode < 400;
    broadcast({
      type: "health",
      ok,
      status: String(res.statusCode),
      ms: latency,
      target: `http://${PROBE_TARGET}:80/`,
    });
    res.resume(); // consume response to free memory
  });

  req.on("error", (err) => {
    broadcast({
      type: "health",
      ok: false,
      status: "ERR",
      ms: null,
      error: err.code || err.message,
      target: `http://${PROBE_TARGET}:80/`,
    });
  });

  req.on("timeout", () => {
    req.destroy();
    broadcast({
      type: "health",
      ok: false,
      status: "TIMEOUT",
      ms: 2000,
      target: `http://${PROBE_TARGET}:80/`,
    });
  });
}, 2500);

// WebSocket connection handling
wss.on("connection", (ws) => {
  // Send current state and recent events to new client
  ws.send(
    JSON.stringify({
      type: "snapshot",
      detectorOnline,
      iface: IFACE || "default",
      victim: VICTIM || "all",
      lastVerdict,
      lastAttackType,
      events: eventLog.slice(0, 50),
    })
  );

  ws.on("message", (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      if (msg.action === "clear_logs") {
        eventLog.length = 0;
        broadcast({ type: "clear_logs" });
      }
    } catch {
      /* ignore */
    }
  });
});

server.listen(PORT, HOST, () => {
  console.log(`[dashboard] Victim Defense Console running at http://${HOST === "0.0.0.0" ? "localhost" : HOST}:${PORT}`);
  startDetector();
});

// Graceful cleanup
function cleanup() {
  if (detectorProc) {
    try {
      detectorProc.kill("SIGTERM");
    } catch {
      /* */
    }
  }
}
process.on("SIGINT", () => {
  cleanup();
  process.exit(0);
});
process.on("SIGTERM", () => {
  cleanup();
  process.exit(0);
});
