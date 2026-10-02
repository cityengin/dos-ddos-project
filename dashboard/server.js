// Local-only realtime dashboard backend for the DoS/DDoS lab.
// SECURITY: binds 127.0.0.1 only; the browser sends ENUMERATED actions, never raw
// shell input. Every docker command is a fixed argument array run with execFile/spawn
// (no shell string interpolation) -> no command injection.
"use strict";

const express = require("express");
const http = require("http");
const path = require("path");
const { spawn, execFile } = require("child_process");
const { WebSocketServer } = require("ws");

const HOST = "127.0.0.1";
const PORT = 3000;
const VICTIM = "172.30.0.10";
const ATTACKERS = ["attacker1", "attacker2", "attacker3"];
const NGINX_CONF = path.join(__dirname, "..", "mitigation", "nginx", "default.conf");

// Fixed scenario definitions. The client only sends the KEY ("A"/"B"/"C").
const SCENARIOS = {
  A: { label: "DoS - 1 source SYN", type: "syn", spoof: false, srcs: ["attacker1"] },
  B: { label: "DDoS - 3 source SYN + spoof", type: "syn", spoof: true, srcs: ATTACKERS },
  C: { label: "DDoS - 3 source HTTP (L7)", type: "http", spoof: false, srcs: ATTACKERS },
  D: { label: "Slowloris - 3 source low-and-slow", type: "slowloris", spoof: false, srcs: ATTACKERS },
};

let running = null;        // active scenario id or null
let mitigation = false;    // nginx rate-limit on/off
let detectorProc = null;   // child process streaming detector JSON
let dockerOk = false;

// ---- docker helpers (execFile = no shell) ----
function docker(args, timeout = 15000) {
  return new Promise((resolve) => {
    execFile("docker", args, { timeout, windowsHide: true }, (err, stdout, stderr) =>
      resolve({ err, stdout: stdout || "", stderr: stderr || "" }));
  });
}

function broadcast(obj) {
  const s = JSON.stringify(obj);
  wss.clients.forEach((c) => { if (c.readyState === 1) c.send(s); });
}

function logEvent(msg, level = "info") {
  broadcast({ type: "log", level, msg, time: new Date().toLocaleTimeString() });
}

// ---- detector realtime stream ----
async function startDetector() {
  const info = await docker(["info", "--format", "{{.ServerVersion}}"], 8000);
  dockerOk = !info.err;
  broadcast({ type: "docker", up: dockerOk });
  if (!dockerOk) {
    logEvent("Docker not reachable - start Docker Desktop, then 'docker compose up -d'.", "error");
    setTimeout(startDetector, 5000); // retry
    return;
  }
  await docker(["exec", "detector", "pkill", "-f", "detector.py"]).catch(() => {});
  detectorProc = spawn("docker",
    ["exec", "detector", "python3", "-u", "/app/detector.py",
      "--iface", "eth0", "--pps", "40", "--syn", "25", "--victim", VICTIM, "--stream"],
    { windowsHide: true });

  let buf = "";
  detectorProc.stdout.on("data", (d) => {
    buf += d.toString();
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (!line) continue;
      try { broadcast({ type: "metric", data: JSON.parse(line) }); } catch { /* ignore */ }
    }
  });
  detectorProc.on("exit", () => {
    detectorProc = null;
    broadcast({ type: "detector", up: false });
    setTimeout(startDetector, 4000); // auto-restart
  });
  broadcast({ type: "detector", up: true });
  logEvent("Detector stream connected.", "ok");
}

// ---- attack control ----
async function startAttack(id) {
  const s = SCENARIOS[id];
  if (!s) return;
  await stopAttack(true);
  for (const a of s.srcs) {
    let cmd;
    if (s.type === "syn") {
      cmd = ["exec", "-d", a, "python3", "/app/syn_flood.py", VICTIM, "-p", "80"];
      if (s.spoof) cmd.push("--spoof");
    } else if (s.type === "http") {
      cmd = ["exec", "-d", a, "python3", "/app/http_flood.py", VICTIM, "-p", "80", "-t", "6", "-d", "3600"];
    } else { // slowloris
      cmd = ["exec", "-d", a, "python3", "/app/slowloris.py", VICTIM, "-p", "80", "-c", "40", "-d", "3600"];
    }
    await docker(cmd);
  }
  running = id;
  broadcast({ type: "state", running: id, label: s.label, attackers: s.srcs, attackType: s.type, spoof: s.spoof });
  logEvent(`Attack started: ${s.label}`, "attack");
}

async function stopAttack(quiet) {
  for (const a of ATTACKERS) {
    await docker(["exec", a, "pkill", "-f", "flood.py"]).catch(() => {});
    await docker(["exec", a, "pkill", "-f", "slowloris"]).catch(() => {});
  }
  running = null;
  broadcast({ type: "state", running: null });
  if (!quiet) logEvent("Attack stopped.", "info");
}

// ---- defense (nginx rate-limit) ----
async function setMitigation(on) {
  if (on === mitigation) return;
  if (on) {
    await docker(["exec", "victim", "sh", "-c",
      "test -f /tmp/orig.conf || cp /etc/nginx/conf.d/default.conf /tmp/orig.conf"]);
    await docker(["cp", NGINX_CONF, "victim:/etc/nginx/conf.d/default.conf"]);
    await docker(["exec", "victim", "nginx", "-s", "reload"]);
  } else {
    await docker(["exec", "victim", "sh", "-c",
      "test -f /tmp/orig.conf && cp /tmp/orig.conf /etc/nginx/conf.d/default.conf"]);
    await docker(["exec", "victim", "nginx", "-s", "reload"]);
  }
  mitigation = on;
  broadcast({ type: "defense", mitigation: on });
  logEvent(`Mitigation ${on ? "ENABLED (nginx rate-limit)" : "disabled"}.`, on ? "ok" : "info");
}

// measure served HTTP requests (200) during a 5s flood from all attackers
function floodMeasure() {
  return Promise.all(ATTACKERS.map((a) => new Promise((res) => {
    execFile("docker", ["exec", a, "python3", "/app/http_flood.py", VICTIM, "-p", "80", "-t", "6", "-d", "5"],
      { timeout: 15000, windowsHide: true }, (e, so) => {
        const m = /thanh cong:\s*(\d+)/.exec(so || "");
        res(m ? parseInt(m[1], 10) : 0);
      });
  }))).then((arr) => arr.reduce((x, y) => x + y, 0));
}

async function benchmark() {
  await stopAttack(true);
  broadcast({ type: "bench", status: "running" });
  logEvent("Defense benchmark running (before/after)...", "info");
  await setMitigation(false);
  const before = await floodMeasure();
  await setMitigation(true);
  const after = await floodMeasure();
  await setMitigation(false);
  const blocked = before > 0 ? Math.round(100 * (1 - after / before)) : 0;
  broadcast({ type: "bench", status: "done", before, after, blocked });
  logEvent(`Benchmark: served ${before} -> ${after} requests (~${blocked}% blocked).`, "ok");
}

// ---- legitimate-client health probe (from host) ----
setInterval(async () => {
  if (!dockerOk) return;
  const t0 = Date.now();
  try {
    const r = await fetch("http://localhost:8080/", { signal: AbortSignal.timeout(2000) });
    broadcast({ type: "health", ok: r.ok, status: r.status, ms: Date.now() - t0 });
  } catch {
    broadcast({ type: "health", ok: false, ms: Date.now() - t0 });
  }
}, 2000);

// ---- http + ws server (127.0.0.1 only) ----
const app = express();
app.use(express.static(path.join(__dirname, "public")));
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

wss.on("connection", (ws) => {
  const snap = { type: "snapshot", running, mitigation, dockerOk,
    scenarios: Object.fromEntries(Object.entries(SCENARIOS).map(([k, v]) => [k, { label: v.label }])) };
  if (running && SCENARIOS[running]) {
    const s = SCENARIOS[running];
    Object.assign(snap, { label: s.label, attackers: s.srcs, attackType: s.type, spoof: s.spoof });
  }
  ws.send(JSON.stringify(snap));
  ws.on("message", async (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }
    try {
      if (msg.action === "attack" && typeof msg.scenario === "string") await startAttack(msg.scenario);
      else if (msg.action === "stop") await stopAttack(false);
      else if (msg.action === "mitigation") await setMitigation(!!msg.on);
      else if (msg.action === "benchmark") await benchmark();
    } catch (e) {
      logEvent("Action failed: " + (e && e.message ? e.message : String(e)), "error");
    }
  });
});

server.listen(PORT, HOST, () => {
  console.log(`[dashboard] http://${HOST}:${PORT}  (local only)`);
  startDetector();
});

// ---- cleanup on exit: stop attacks, restore nginx ----
async function cleanup() {
  try { if (detectorProc) detectorProc.kill(); } catch { /* */ }
  try { await stopAttack(true); } catch { /* */ }
  try { await setMitigation(false); } catch { /* */ }
}
process.on("SIGINT", async () => { await cleanup(); process.exit(0); });
process.on("SIGTERM", async () => { await cleanup(); process.exit(0); });
