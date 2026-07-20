// store.mjs — read/merge/write the site's utilization.json, and (optionally) push it.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { aggregateWorkbook } from "./aggregate.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = join(__dirname, "..");
export const STORE_PATH = join(REPO_ROOT, "utilization.json");       // plaintext, local only (gitignored)
export const ENC_PATH = join(REPO_ROOT, "utilization.enc.json");     // encrypted, published

// Encrypt the store to match the site's decryptConfig():
// PBKDF2(SHA-256, 310000) -> AES-GCM-256, blob = { salt, iv, data } (base64).
export async function encryptJSON(obj, password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" },
    baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc.encode(JSON.stringify(obj)));
  const b64 = (buf) => Buffer.from(buf).toString("base64");
  return { salt: b64(salt), iv: b64(iv), data: b64(data) };
}

export function loadStore() {
  if (existsSync(STORE_PATH)) {
    try { return JSON.parse(readFileSync(STORE_PATH, "utf8")); } catch { /* rebuild below */ }
  }
  return { generatedAt: null, latest: null, periods: {} };
}

// Aggregate one .xlsx and merge it into the store as a period. Returns the period.
export function mergeFile(filePath, store = loadStore()) {
  const period = aggregateWorkbook(filePath);
  const key = period.periodKey || period.sourceFile || `import-${Object.keys(store.periods).length + 1}`;
  period.periodKey = key;
  store.periods[key] = period;
  // "latest" = newest period key (keys sort lexically: 2026-Q2 > 2026-Q1)
  store.latest = Object.keys(store.periods).sort().pop();
  store.generatedAt = new Date().toISOString();
  return { store, period, key };
}

// Always writes the plaintext store locally (gitignored). If a password is
// given, also writes the encrypted utilization.enc.json that gets published.
export async function writeStore(store, password) {
  writeFileSync(STORE_PATH, JSON.stringify(store, null, 2) + "\n");
  if (password) {
    const enc = await encryptJSON(store, password);
    writeFileSync(ENC_PATH, JSON.stringify(enc) + "\n");
    return { encrypted: true };
  }
  return { encrypted: false };
}

// Commit + push the published store so GitHub Pages redeploys. Best-effort:
// returns {ok, msg}. Uses the repo's existing credential manager.
// Publishes utilization.enc.json when encrypted, else plaintext utilization.json.
export function publish(message, { encrypted } = {}) {
  const file = encrypted ? "utilization.enc.json" : "utilization.json";
  const git = (...args) => execFileSync("git", args, { cwd: REPO_ROOT, encoding: "utf8" }).trim();
  try {
    const changed = git("status", "--porcelain", file);
    if (!changed) return { ok: true, msg: "no change to publish" };
    git("add", file);
    git("commit", "-m", message);
    git("push");
    return { ok: true, msg: `pushed ${file} to origin` };
  } catch (e) {
    const out = (e.stdout || "") + (e.stderr || "") + e.message;
    return { ok: false, msg: out.trim() };
  }
}
