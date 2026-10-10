// Local-only realtime dashboard backend for the DoS/DDoS lab.
// SECURITY: binds 127.0.0.1 only; the browser sends ENUMERATED actions, never raw
// shell input. Every docker command is a fixed argument array run with execFile/spawn
// (no shell string interpolation) -> no command injection.
"use strict";

const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const { spawn, execFile } = require("child_process");
const { WebSocketServer } = require("ws");

const HOST = "127.0.0.1";
const PORT = 3000;
const VICTIM = "172.30.0.10";
const ATTACKERS = ["attacker1", "attacker2", "attacker3", "attacker4", "attacker5", "attacker6"];
// Window ML model: host path (to check it exists) + in-container path (detector bind-mounts ./detection).
const ML_MODEL_HOST = path.join(__dirname, "..", "detection", "window_model.joblib");
const ML_MODEL_CONT = "/app/window_model.joblib";

// Fixed scenario definitions. The client only sends the KEY ("A"/"B"/"C").
// `pps` paces each SYN sender (per container) so the combined load stays controlled while
// a spoofed flood still produces many distinct source IPs per window.
const SCENARIOS = {
  A: { label: "DoS - 1 source SYN", type: "syn", spoof: false, srcs: ["attacker1"], pps: 150 },
  B: { label: "DDoS - 6 source SYN + spoof", type: "syn", spoof: true, srcs: ATTACKERS, pps: 400 },
  C: { label: "DDoS - 6 source HTTP (L7)", type: "http", spoof: false, srcs: ATTACKERS },
};

let running = null;        // active scenario id or null
let detectorProc = null;   // child process streaming detector JSON
let dockerOk = false;
let blocking = false;      // closed-loop IPS (eBPF XDP_DROP) on/off
let detStarting = false;   // guard: chi 1 luong startDetector chay cung luc (tranh pkill cheo)

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
  if (detStarting) return;   // tranh 2 luong khoi dong chong cheo (vd toggle luc dang start)
  detStarting = true;
  const info = await docker(["info", "--format", "{{.ServerVersion}}"], 8000);
  dockerOk = !info.err;
  broadcast({ type: "docker", up: dockerOk });
  if (!dockerOk) {
    logEvent("Docker not reachable - start Docker Desktop, then 'docker compose up -d'.", "error");
    detStarting = false;
    setTimeout(startDetector, 5000); // retry
    return;
  }
  // verify the detector actually SHARES the victim's network namespace (curl localhost -> nginx).
  // If recreate-victim-without-detector broke it, fail loudly instead of streaming silent zeros.
  const ns = await docker(["exec", "detector", "curl", "-s", "-m", "2", "-o", "/dev/null",
    "-w", "%{http_code}", "http://localhost:80"], 6000);
  if ((ns.stdout || "").trim() !== "200") {
    broadcast({ type: "detector", up: false });
    logEvent("Detector cannot reach the victim (shared netns broken). " +
             "Run: docker compose up -d --force-recreate", "error");
    detStarting = false;
    setTimeout(startDetector, 6000);
    return;
  }
  await docker(["exec", "detector", "pkill", "-f", "detector.py"]).catch(() => {});
  // Bat ML neu co san model (train_window.py da sinh). Neu khong co -> chay luat thuan (ml_verdict=null).
  let mlOn = false;
  try { mlOn = fs.existsSync(ML_MODEL_HOST); } catch { mlOn = false; }
  const detArgs = ["exec", "detector", "python3", "-u", "/app/detector.py",
    "--iface", "eth0", "--pps", "40", "--syn", "25", "--victim", VICTIM, "--stream"];
  if (mlOn) detArgs.push("--ml", ML_MODEL_CONT);
  // Blocking ON -> chay engine eBPF + --block (XDP_DROP). OFF -> detect-only nhu cu.
  if (blocking) detArgs.push("--engine", "ebpf", "--block", "--block-pps", "200",
                             "--block-ttl", "5", "--block-syn-rate", "2000");
  detectorProc = spawn("docker", detArgs, { windowsHide: true });
  detStarting = false;   // da spawn xong -> cho phep lan restart ke tiep

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
  broadcast({ type: "blocking", on: blocking });
  logEvent("Detector stream connected ("
    + (blocking ? "eBPF + BLOCKING" : "detect-only")
    + (mlOn ? " + ML" : "") + ").", "ok");
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
      if (s.pps) cmd.push("--pps", String(s.pps));
      if (s.spoof) cmd.push("--spoof");
    } else { // http
      cmd = ["exec", "-d", a, "python3", "/app/http_flood.py", VICTIM, "-p", "80", "-t", "6", "-d", "3600"];
    }
    await docker(cmd);
  }
  running = id;
  broadcast({ type: "state", running: id, label: s.label, attackers: s.srcs, attackType: s.type, spoof: s.spoof });
  logEvent(`Attack started: ${s.label}`, "attack");
}

async function stopAttack(quiet) {
  for (const a of ATTACKERS) await docker(["exec", a, "pkill", "-f", "flood.py"]).catch(() => {});
  running = null;
  broadcast({ type: "state", running: null });
  if (!quiet) logEvent("Attack stopped.", "info");
}

// ---- closed-loop blocking toggle: restart the detector with/without --block (eBPF) ----
async function setBlocking(on) {
  if (on === blocking) return;
  blocking = on;
  broadcast({ type: "blocking", on });
  logEvent(on ? "Blocking ENABLED - restarting detector with eBPF XDP_DROP (~a few seconds)..."
              : "Blocking disabled - restarting detector (detect-only)...", on ? "ok" : "info");
  // Kill the current detector; the exit handler restarts it with the new flags. startDetector()
  // pkills the in-container process first (SIGTERM -> its cleanup removes the XDP program).
  if (detectorProc) { try { detectorProc.kill(); } catch { /* */ } }
  else startDetector();
}

// ---- service-health probe (loopback, inside victim's netns) ----
// Probing from the detector over localhost goes via `lo`, NOT eth0, so it does NOT
// appear to the sniffer as an extra source (which previously made scenario A look like
// DDoS). curl's %{time_total} is the real request latency, excluding docker-exec overhead.
setInterval(async () => {
  if (!dockerOk) return;
  const r = await docker(["exec", "detector", "curl", "-s", "-m", "2", "-o", "/dev/null",
    "-w", "%{http_code} %{time_total}", "http://localhost:80"], 4000);
  const parts = (r.stdout || "").trim().split(/\s+/);
  const code = parts[0] || "000";
  const ms = parts[1] ? Math.round(parseFloat(parts[1]) * 1000) : null;
  broadcast({ type: "health", ok: code === "200", status: code, ms });
}, 2500);

// ---- http + ws server (127.0.0.1 only) ----
const app = express();
app.use(express.static(path.join(__dirname, "public")));
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

wss.on("connection", (ws) => {
  const snap = { type: "snapshot", running, dockerOk, blocking,
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
      else if (msg.action === "blocking") await setBlocking(!!msg.on);
    } catch (e) {
      logEvent("Action failed: " + (e && e.message ? e.message : String(e)), "error");
    }
  });
});

server.listen(PORT, HOST, () => {
  console.log(`[dashboard] http://${HOST}:${PORT}  (local only)`);
  startDetector();
});

// ---- cleanup on exit: stop the detector (and its XDP) + stop attacks ----
async function cleanup() {
  detStarting = true;   // chan auto-restart trong luc dang thoat
  try { if (detectorProc) detectorProc.kill(); } catch { /* */ }
  // Killing the local `docker exec` client does NOT stop the in-container detector, so it would
  // keep running (and keep dropping packets if --block was on) after the dashboard exits. Send
  // SIGTERM to the in-container process so it stops AND removes its XDP program.
  try { await docker(["exec", "detector", "pkill", "-f", "detector.py"], 4000); } catch { /* */ }
  try { await stopAttack(true); } catch { /* */ }
}
process.on("SIGINT", async () => { await cleanup(); process.exit(0); });
process.on("SIGTERM", async () => { await cleanup(); process.exit(0); });
