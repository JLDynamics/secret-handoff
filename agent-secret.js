#!/usr/bin/env node
// agent-secret — keep credentials out of agent chat transcripts.
//
// The agent creates a request. The human fills it in their own terminal with a
// hidden prompt. The agent then gets a file path or an env var, never the value.
//
// Threat model: this stops secrets from entering model context, transcripts,
// logs, and screenshots. It does NOT defend against a hostile agent that can
// run arbitrary shell commands, because such an agent can read the files.

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";

const ROOT =
  process.env.AGENT_SECRETS_DIR ||
  path.join(os.homedir(), ".local", "state", "agent-secrets");

const REQUESTS = path.join(ROOT, "requests");
const STORE = path.join(ROOT, "store");
const FILES = path.join(ROOT, "files");

// The path the human actually types. Resolved here so printed commands work
// no matter where the skill folder lives or what the CWD is.
const SELF = process.argv[1] ? path.resolve(process.argv[1]) : "agent-secret.js";
const SELF_CMD = SELF.includes(" ") ? `"${SELF}"` : SELF;

const c = {
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
};

function ensureDirs() {
  for (const d of [ROOT, REQUESTS, STORE, FILES]) {
    fs.mkdirSync(d, { recursive: true, mode: 0o700 });
    try {
      fs.chmodSync(d, 0o700);
    } catch {}
  }
}

/** Write a file that only the current user can read. */
function writePrivate(file, data) {
  const fd = fs.openSync(file, "w", 0o600);
  try {
    fs.writeSync(fd, data);
  } finally {
    fs.closeSync(fd);
  }
  try {
    fs.chmodSync(file, 0o600);
  } catch {}
}

function newId() {
  return crypto.randomBytes(6).toString("hex");
}

function recordPath(id) {
  return path.join(REQUESTS, `${id}.json`);
}

function readRecord(id) {
  if (!/^[0-9a-f]{12}$/.test(id)) {
    fail(`"${id}" is not a valid request id.`);
  }
  const p = recordPath(id);
  if (!fs.existsSync(p)) fail(`No secret request with id ${id}.`);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function saveRecord(rec) {
  writePrivate(recordPath(rec.id), JSON.stringify(rec, null, 2));
}

function fail(msg) {
  console.error(c.red("error: ") + msg);
  process.exit(1);
}

function human(ms) {
  const s = Math.round(ms / 1000);
  if (s < 90) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 90) return `${m}m`;
  return `${Math.round(m / 60)}h`;
}

/** Sweep every request: drop expired values and orphaned files. */
function sweep() {
  if (!fs.existsSync(REQUESTS)) return;
  const known = new Set();
  for (const f of fs.readdirSync(REQUESTS)) {
    if (!f.endsWith(".json")) continue;
    const rec = reconcile(readRecord(f.slice(0, -5)));
    known.add(rec.id);
  }
  for (const dir of [STORE, FILES]) {
    if (!fs.existsSync(dir)) continue;
    for (const f of fs.readdirSync(dir)) {
      if (!known.has(f)) fs.rmSync(path.join(dir, f), { force: true });
    }
  }
}

/** Mark expired requests and clean their values up. */
function reconcile(rec) {
  if (
    rec.expiresAt &&
    Date.now() > rec.expiresAt &&
    (rec.status === "ready" || rec.status === "delivered")
  ) {
    rec.status = "expired";
    saveRecord(rec);
    dropValue(rec.id);
  }
  return rec;
}

function dropValue(id) {
  for (const p of [path.join(STORE, id), path.join(FILES, id)]) {
    try {
      fs.rmSync(p, { force: true });
    } catch {}
  }
}

function readValue(rec) {
  const p = path.join(STORE, rec.id);
  if (!fs.existsSync(p)) fail("The stored secret is gone. Ask the human to fill it again.");
  return fs.readFileSync(p, "utf8");
}

function parseArgs(argv) {
  const flags = {};
  const rest = [];
  let i = 0;
  while (i < argv.length) {
    const a = argv[i];
    if (a === "--") {
      rest.push(...argv.slice(i + 1));
      break;
    }
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) {
        flags[key] = true;
        i += 1;
      } else {
        flags[key] = next;
        i += 2;
      }
    } else {
      rest.push(a);
      i += 1;
    }
  }
  return { flags, rest };
}

async function readHidden(promptText) {
  if (!process.stdin.isTTY) {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
  }
  process.stdout.write(promptText);
  return new Promise((resolve) => {
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
    let buf = "";
    const cleanup = () => {
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdin.off("data", onData);
    };
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") {
          cleanup();
          process.stdout.write("\n");
          resolve(buf);
          return;
        }
        if (ch === "\u0003") {
          cleanup();
          process.stdout.write("\n");
          process.exit(130);
        }
        if (ch === "\u007f" || ch === "\b") {
          buf = buf.slice(0, -1);
          continue;
        }
        if (ch < " ") continue;
        buf += ch;
      }
    };
    process.stdin.on("data", onData);
  });
}

// ---------------------------------------------------------------- commands

function cmdAsk({ flags }) {
  const name = flags.name;
  const why = flags.for;
  if (!name) fail("--name is required, e.g. --name 'Tailscale auth key'");
  if (!why) fail("--for is required: say what the agent will use it for.");
  const ttlHours = Number(flags.ttl ?? 24);
  if (!Number.isFinite(ttlHours) || ttlHours <= 0) fail("--ttl must be a positive number of hours.");
  const delivery = flags.delivery ?? "file";
  if (!["file", "env", "value"].includes(delivery)) fail("--delivery must be file, env or value.");

  ensureDirs();
  const rec = {
    id: newId(),
    name,
    for: why,
    hint: typeof flags.hint === "string" ? flags.hint : undefined,
    delivery,
    ttlHours,
    status: "pending",
    createdAt: Date.now(),
    answeredAt: null,
    expiresAt: null,
  };
  saveRecord(rec);

  if (flags.json) {
    process.stdout.write(JSON.stringify({ id: rec.id, name, status: "pending" }, null, 2) + "\n");
    return;
  }
  console.log(
    [
      c.bold(`REQUEST ${rec.id}`),
      `${c.dim("wants:")} ${name}`,
      `${c.dim("why:  ")} ${why}`,
      rec.hint ? `${c.dim("hint: ")} ${rec.hint}` : null,
      "",
      process.platform === "darwin"
        ? "Next: open a window for the human to paste into (no terminal):"
        : "The human must run this in their own terminal:",
      c.bold(
        `  ${SELF_CMD} ${process.platform === "darwin" ? "gui" : "fill"} ${rec.id}`,
      ),
      "",
      c.dim(`Then the agent uses it with: ${SELF_CMD} exec ${rec.id} --env NAME -- <command>`),
    ]
      .filter(Boolean)
      .join("\n"),
  );
}

async function cmdFill({ rest }) {
  const id = rest[0] ?? fail("usage: agent-secret fill <id>");
  const rec = reconcile(readRecord(id));
  if (rec.status === "ready" || rec.status === "delivered")
    fail(`Request ${id} was already filled. Revoke it first if you want to redo it.`);
  if (rec.status === "revoked") fail(`Request ${id} was revoked.`);

  ensureDirs();
  const label = rec.name.length > 60 ? rec.name.slice(0, 57) + "..." : rec.name;
  const value = await readHidden(`Paste ${c.bold(label)} ${c.dim("(input hidden)")}: `);
  if (!value.trim()) fail("Empty value; nothing saved.");

  writePrivate(path.join(STORE, rec.id), value);
  rec.status = "ready";
  rec.answeredAt = Date.now();
  rec.expiresAt = rec.answeredAt + rec.ttlHours * 60 * 60 * 1000;
  saveRecord(rec);

  console.log(
    c.green("saved") +
      ` ${rec.id} — held for ${rec.ttlHours}h, never shown in chat.`,
  );
}

/** Build a tiny .app bundle so macOS treats the prompt as a real window. */
function hudBinary() {
  const src = path.join(path.dirname(SELF), "secrethud.swift");
  if (!fs.existsSync(src)) return null;

  // Build next to the skill so it travels with it; fall back to the state dir
  // if the skill directory is read-only.
  let buildRoot = path.join(path.dirname(SELF), ".build");
  try {
    fs.mkdirSync(buildRoot, { recursive: true, mode: 0o700 });
    fs.accessSync(buildRoot, fs.constants.W_OK);
  } catch {
    buildRoot = path.join(ROOT, ".build");
    fs.mkdirSync(buildRoot, { recursive: true, mode: 0o700 });
  }
  const appDir = path.join(buildRoot, "Secret Request.app");
  const macos = path.join(appDir, "Contents", "MacOS");
  const bin = path.join(macos, "secrethud");
  const plist = path.join(appDir, "Contents", "Info.plist");

  let fresh = false;
  try {
    fresh = fs.existsSync(bin) && fs.statSync(bin).mtimeMs >= fs.statSync(src).mtimeMs;
  } catch {}

  if (!fresh) {
    fs.mkdirSync(macos, { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.join(appDir, "Contents", "Resources"), { recursive: true, mode: 0o700 });
    const built = spawnSync("swiftc", ["-O", src, "-o", bin], { encoding: "utf8" });
    if (built.status !== 0) {
      if (built.stderr) process.stderr.write(built.stderr);
      return null;
    }
  }

  if (!fs.existsSync(plist)) {
    fs.writeFileSync(
      plist,
      `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Secret Request</string>
  <key>CFBundleDisplayName</key><string>Secret Request</string>
  <key>CFBundleIdentifier</key><string>local.secret-handoff.prompt</string>
  <key>CFBundleExecutable</key><string>secrethud</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
`,
    );
  }
  return bin;
}

/** Fallback when swiftc is unavailable: a plain system dialog. */
function hudFallback(rec, target) {
  const msg = [rec.for, rec.hint].filter(Boolean).join("\\n\\n").replace(/"/g, '\\"');
  const script = `display dialog "${msg}" with title "${rec.name.replace(/"/g, '\\"')}" default answer "" with hidden answer buttons {"Decline", "Save"} default button "Save"`;
  const r = spawnSync("osascript", ["-e", script], { encoding: "utf8" });
  if (r.status !== 0) return false;
  const m = /text returned:(.*)$/m.exec(r.stdout || "");
  if (!m || !m[1].trim()) return false;
  writePrivate(target, m[1].replace(/\n$/, ""));
  return true;
}

/** Pop a native window so the human never touches a terminal. */
function cmdGui({ rest }) {
  const id = rest[0] ?? fail("usage: agent-secret gui <id>");
  const rec = reconcile(readRecord(id));
  if (rec.status === "ready" || rec.status === "delivered")
    fail(`Request ${id} was already filled. Revoke it first if you want to redo it.`);
  if (rec.status === "revoked") fail(`Request ${id} was revoked.`);
  if (process.platform !== "darwin")
    fail("The popup needs macOS. Use: agent-secret fill <id>");

  ensureDirs();
  const target = path.join(ROOT, `.incoming-${rec.id}`);
  const bin = hudBinary();

  let ok;
  if (bin) {
    const r = spawnSync(
      bin,
      ["--name", rec.name, "--for", rec.for, "--hint", rec.hint ?? "", "--ttl", String(rec.ttlHours), "--out", target],
      { stdio: "inherit" },
    );
    ok = r.status === 0 && fs.existsSync(target);
  } else {
    ok = hudFallback(rec, target);
  }

  if (!ok) {
    try { fs.rmSync(target, { force: true }); } catch {}
    console.log("declined — nothing was saved.");
    process.exit(2);
  }

  writePrivate(path.join(STORE, rec.id), fs.readFileSync(target, "utf8"));
  fs.rmSync(target, { force: true });
  rec.status = "ready";
  rec.answeredAt = Date.now();
  rec.expiresAt = rec.answeredAt + rec.ttlHours * 60 * 60 * 1000;
  saveRecord(rec);
  console.log(c.green("saved") + ` ${rec.id} — held for ${rec.ttlHours}h, never shown in chat.`);
}

function cmdPath({ rest }) {
  const id = rest[0] ?? fail("usage: agent-secret path <id>");
  const rec = reconcile(readRecord(id));
  if (rec.status === "pending")
    fail(`The human has not filled request ${id} yet. They need to run: ${SELF_CMD} fill ${id}`);
  if (rec.status !== "ready" && rec.status !== "delivered")
    fail(`Request ${id} is ${rec.status}.`);
  ensureDirs();
  const value = readValue(rec);
  const target = path.join(FILES, rec.id);
  writePrivate(target, value);
  rec.status = "delivered";
  rec.lastUsedAt = Date.now();
  saveRecord(rec);
  console.log(target);
}

function cmdExec({ rest, flags }) {
  const id = rest[0] ?? fail("usage: agent-secret exec <id> --env NAME -- <command...>");
  // parseArgs strips the `--` separator, so the command is everything after the id.
  const cmd = rest.slice(1);
  if (cmd.length === 0) fail("Pass the command after --, e.g. --env KEY -- mycli --token \"$KEY\"");

  const rec = reconcile(readRecord(id));
  if (rec.status !== "ready" && rec.status !== "delivered")
    fail(`Request ${id} is ${rec.status}; cannot run anything with it.`);

  const envName = flags.env ?? "AGENT_SECRET";
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(envName)) fail(`"${envName}" is not a valid env var name.`);

  const value = readValue(rec);
  const child = spawn(cmd[0], cmd.slice(1), {
    stdio: "inherit",
    env: { ...process.env, [envName]: value },
    shell: false,
  });
  child.on("exit", (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    process.exit(code ?? 1);
  });
  child.on("error", (e) => fail(`could not run ${cmd[0]}: ${e.message}`));
}

function cmdGet({ rest }) {
  const id = rest[0] ?? fail("usage: agent-secret get <id>");
  const rec = reconcile(readRecord(id));
  if (rec.status !== "ready" && rec.status !== "delivered")
    fail(`Request ${id} is ${rec.status}.`);
  console.error(
    c.yellow("warning: ") +
      "printing the value puts it in the agent's context. Prefer `path` or `exec`.",
  );
  process.stdout.write(readValue(rec));
}

function cmdList() {
  ensureDirs();
  const ids = fs
    .readdirSync(REQUESTS)
    .filter((f) => f.endsWith(".json"))
    .map((f) => f.slice(0, -5));
  if (ids.length === 0) {
    console.log(c.dim("no secret requests"));
    return;
  }
  const rows = ids
    .map((id) => reconcile(readRecord(id)))
    .sort((a, b) => b.createdAt - a.createdAt);
  for (const r of rows) {
    const left =
      r.expiresAt && (r.status === "ready" || r.status === "delivered")
        ? ` (${human(Math.max(0, r.expiresAt - Date.now()))} left)`
        : "";
    const color =
      r.status === "ready" || r.status === "delivered"
        ? c.green
        : r.status === "pending"
          ? c.yellow
          : c.dim;
    console.log(`${color(r.status.padEnd(9))} ${r.id}  ${r.name}${c.dim(left)}`);
  }
}

function cmdStatus({ rest }) {
  const id = rest[0] ?? fail("usage: agent-secret status <id>");
  const r = reconcile(readRecord(id));
  console.log(
    [
      `id:       ${r.id}`,
      `name:     ${r.name}`,
      `why:      ${r.for}`,
      `status:   ${r.status}`,
      `delivery: ${r.delivery}`,
      r.expiresAt
        ? `expires:  ${new Date(r.expiresAt).toISOString()} (${human(Math.max(0, r.expiresAt - Date.now()))} left)`
        : `expires:  —`,
      `value:    ${r.status === "ready" || r.status === "delivered" ? "stored" : "none"}`,
    ].join("\n"),
  );
}

function cmdRevoke({ rest }) {
  const id = rest[0] ?? fail("usage: agent-secret revoke <id>");
  const rec = reconcile(readRecord(id));
  rec.status = "revoked";
  saveRecord(rec);
  dropValue(id);
  console.log(c.green("revoked") + ` ${id}`);
}

function cmdPurge() {
  ensureDirs();
  let n = 0;
  for (const f of fs.readdirSync(REQUESTS)) {
    if (!f.endsWith(".json")) continue;
    const rec = reconcile(readRecord(f.slice(0, -5)));
    if (rec.status === "expired" || rec.status === "revoked") {
      fs.rmSync(recordPath(rec.id), { force: true });
      n += 1;
    }
  }
  console.log(n === 0 ? c.dim("nothing to purge") : `purged ${n} request(s)`);
}

function usage() {
  console.log(
    `agent-secret — hand secrets to agents without them entering the chat

  agent-secret ask --name <label> --for <purpose> [--hint <text>] [--ttl 24] [--json]
      Create a request. Prints an id. The agent relays the fill command.
  agent-secret gui <id>
      macOS: pop a window for the human to paste into. No terminal needed.
  agent-secret fill <id>
      Human runs this. Hidden input, nothing echoed.
  agent-secret path <id>
      Print a 0600 file path holding the secret (preferred for CLIs).
  agent-secret exec <id> --env NAME -- <command...>
      Run a command with the secret in $NAME (preferred, never printed).
  agent-secret get <id>
      Print the raw value. Last resort; it enters the transcript.
  agent-secret list | status <id> | revoke <id> | purge

State: ${ROOT}`,
  );
}

const [command, ...argv] = process.argv.slice(2);
const { flags, rest } = parseArgs(argv);

// Opportunistic cleanup: expired values should not linger just because nothing
// ran. Cheap, and it keeps the store honest without a background daemon.
if (!["help", "--help", "-h", undefined].includes(command)) {
  try {
    sweep();
  } catch {}
}

switch (command) {
  case "ask":
    cmdAsk({ flags });
    break;
  case "fill":
    await cmdFill({ rest });
    break;
  case "gui":
    cmdGui({ rest });
    break;
  case "path":
    cmdPath({ rest });
    break;
  case "exec":
    cmdExec({ rest, flags });
    break;
  case "get":
    cmdGet({ rest });
    break;
  case "list":
    cmdList();
    break;
  case "status":
    cmdStatus({ rest });
    break;
  case "revoke":
    cmdRevoke({ rest });
    break;
  case "purge":
    cmdPurge();
    break;
  case "help":
  case "--help":
  case "-h":
  case undefined:
    usage();
    break;
  default:
    fail(`unknown command "${command}". Try: agent-secret help`);
}
