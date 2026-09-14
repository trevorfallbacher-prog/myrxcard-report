// sync-admin-kv.mjs — seed / seal / verify the root dashboard's admin data in
// the sync worker's KV, through the worker's master-gated routes (no wrangler).
//
//   node sync-admin-kv.mjs seed-brands [--force]   write a "myrx:brand:<slug>" doc
//                                                  for every client that has none
//                                                  (--force: overwrite admin edits)
//   node sync-admin-kv.mjs seal-passwords          encrypt clients.secrets.json with
//                                                  the master password -> "myrx:pws"
//   node sync-admin-kv.mjs verify                  print what KV holds (never passwords)
//
// The master (root gate) password is read from a muted terminal prompt (the
// default), from one line on a piped stdin (--pw-stdin), or from env REPORT_PW
// — which is consumed and deleted on read so no child process inherits it.
// Never put it on the command line: `REPORT_PW=… node …` lands the value in
// shell history and in `ps` for the life of the process. Use
//   read -rs REPORT_PW; export REPORT_PW; node sync-admin-kv.mjs …
// if it must come from the environment.
// It is verified against ../config.enc.json locally before anything is sent,
// and only ever sent to an https SYNC_API (or a localhost dev worker), which
// is announced when overridden. Every client password is verified against its
// own <slug>/utilization.enc.json before it goes into the vault, so the
// dashboard never shows a stale one. Password VALUES are never printed.

import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { encryptJSON, REPO_ROOT } from "./store.mjs";
import { CLIENTS, codeBrand } from "./clients.config.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SECRETS_PATH = join(__dirname, "clients.secrets.json");
const CONFIG_ENC = join(REPO_ROOT, "config.enc.json");
const SYNC_API = process.env.SYNC_API || "https://myrxcard-sync.trevorfallbacher.workers.dev";
const TIMEOUT_MS = 15000;
// escrow: written straight to KV through the Cloudflare API (no worker route
// in the loop, so it also recovers a locked-out master). Same account + KV
// namespace as sync-worker/wrangler.toml; the key file must hold the exact
// value bound as the ESCROW_KEY secret.
const ESCROW_KEY_FILE = join(__dirname, "sync-worker", ".escrowkey");
const CF_TOKEN_FILE = join(__dirname, "sync-worker", ".cftoken");
const CF_ACCOUNT = "b8a5fbaaa1c68973ff2775f3cf39cbc0", KV_NAMESPACE = "dadeb13cc98d45a59ccc1cf032b725a6";

const USAGE = `Usage: node sync-admin-kv.mjs <seed-brands [--force] | seal-passwords | escrow | verify> [--pw-stdin]
  escrow          re-seal the worker's escrow copy of the vault (myrx:pws-escrow) straight into KV.
                  Needed after rotating the master password (the worker checks admin_pw against the
                  escrow's root, so a new master is refused until the escrow is re-sealed) and whenever
                  the Clients tab shows the escrow as "stale"/"missing". seal-passwords runs it too.
                  Requires sync-worker/.escrowkey (= the ESCROW_KEY worker secret) and sync-worker/.cftoken.
  The master password is asked for at a muted prompt. Alternatives:
    --pw-stdin            read it as one line from a piped stdin
    REPORT_PW (env)       read and consumed on start — set it with \`read -rs REPORT_PW; export REPORT_PW\`,
                          never inline on the command line (shell history, ps).`;

// The master password goes in the body of every admin call, so the endpoint
// must be https (a localhost dev worker is the one exception) and an override
// is printed before anything is sent so it can never be in effect unnoticed.
const SYNC_URL = (() => {
  let u = null;
  try { u = new URL(SYNC_API); } catch {}
  if (!u || (u.protocol !== "https:" && !/^(localhost|127\.0\.0\.1|\[::1\])$/.test(u.hostname))) fail(`SYNC_API must be an https URL (or localhost for a dev worker): ${SYNC_API}`);
  return u;
})();

// ---- crypto: the exact inverse of store.mjs encryptJSON / the page's decryptConfig ----
const b64buf = (s) => Uint8Array.from(Buffer.from(String(s || ""), "base64"));
async function decryptJSON(blob, password) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64buf(blob.salt), iterations: 310000, hash: "SHA-256" },
    baseKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64buf(blob.iv) }, aesKey, b64buf(blob.data));
  return JSON.parse(new TextDecoder().decode(plain));
}
function readBlob(path) {
  const blob = JSON.parse(readFileSync(path, "utf8"));
  if (!blob || !blob.salt || !blob.iv || !blob.data) throw new Error(`${path} is not an encrypted blob`);
  return blob;
}
async function decrypts(path, password) {
  try { await decryptJSON(readBlob(path), password); return true; } catch { return false; }
}

// ---- master password: env or a muted TTY prompt ----
function promptHidden(question) {
  return new Promise((resolve, reject) => {
    const { stdin, stdout } = process;
    if (!stdin.isTTY) return reject(new Error("REPORT_PW is not set and stdin is not a terminal — set REPORT_PW=<master> in the environment"));
    stdout.write(question);
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding("utf8");
    let pw = "";
    const done = (err) => {
      stdin.setRawMode(false); stdin.pause(); stdin.removeListener("data", onData); stdout.write("\n");
      err ? reject(err) : resolve(pw);
    };
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") return done();
        if (ch === "\u0003" || ch === "\u0004") return done(new Error("cancelled"));
        if (ch === "\u007f" || ch === "\b") pw = pw.slice(0, -1);
        else if (ch >= " ") pw += ch;
      }
    };
    stdin.on("data", onData);
  });
}

function readStdinLine() {
  let txt = "";
  try { txt = readFileSync(0, "utf8"); } catch { fail("--pw-stdin: could not read stdin"); }
  return txt.split(/\r?\n/)[0];
}
async function getMaster(fromStdin) {
  // env first (consumed — nothing spawned later inherits it), then stdin, then the prompt
  let pw = process.env.REPORT_PW || "";
  delete process.env.REPORT_PW;
  if (!pw && fromStdin) pw = readStdinLine();
  if (!pw) pw = await promptHidden("Master (root gate) password: ");
  if (!pw) fail("No master password given.");
  if (!existsSync(CONFIG_ENC)) fail(`${CONFIG_ENC} not found — run this from the report repo's tools/ folder.`);
  if (!(await decrypts(CONFIG_ENC, pw))) fail("Master password does not decrypt config.enc.json — aborting, nothing was sent.");
  console.log("Master password verified against config.enc.json.");
  return pw;
}

function fail(msg, code = 1) { console.error(msg); process.exit(code); }

// ---- worker calls: { status, out }; errors carry out.error only (never the body we sent) ----
async function api(body) {
  let res;
  try {
    res = await fetch(SYNC_API, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch (e) { throw new Error(`worker unreachable: ${e && e.message ? e.message : e}`); }
  const out = await res.json().catch(() => null);
  return { status: res.status, out: out && typeof out === "object" ? out : {} };
}
function describe({ status, out }) {
  const extra = status === 429 && out.retryAfter ? ` (retry after ${out.retryAfter}s)` : "";
  return `${out.error || "error"} [HTTP ${status}]${extra}`;
}
async function adminCall(master, action, extra = {}) {
  const r = await api({ admin_pw: master, action, ...extra });
  if (!r.out.ok) {
    if (r.status === 403) fail(`Worker rejected the master password on ${action} (${describe(r)}) — is the deployed worker's verify cache stale, or config.enc.json unpublished?`);
    if (r.status === 429) fail(`Worker is rate-limiting this address: ${describe(r)}`);
    throw new Error(`${action}: ${describe(r)}`);
  }
  return r.out;
}
async function brandGet(slug) {
  const r = await api({ brand_get: slug });
  if (!r.out.ok) throw new Error(`brand_get ${slug}: ${describe(r)}`);
  return r.out;
}

const brandSummary = (doc) => doc && doc.brand ? "custom brand" : "stock look";

// ---- subcommands ----
async function seedBrands(master, force) {
  await adminCall(master, "ping");
  let written = 0, skipped = 0;
  for (const client of CLIENTS) {
    const cur = await brandGet(client.slug);
    if (cur.found && !force) {
      console.log(`- ${client.slug.padEnd(17)} already in KV (${cur.doc.updatedFrom || "?"}, ${brandSummary(cur.doc)}) — skipped`);
      skipped++; continue;
    }
    const brand = codeBrand(client) || null;
    const doc = { v: 1, slug: client.slug, name: client.name, type: client.type || "pharmacy", demo: !!client.demo, brand, updatedFrom: "seed" };
    const out = await adminCall(master, "brand.put", { slug: doc.slug, name: doc.name, brand: doc.brand, type: doc.type, demo: doc.demo, updatedFrom: doc.updatedFrom });
    const got = out.doc || {};
    console.log(`✓ ${client.slug.padEnd(17)} ${cur.found ? "overwritten" : "seeded"} (${brandSummary(got)}${got.demo ? ", demo" : ""}, updatedFrom ${got.updatedFrom || "?"})`);
    written++;
  }
  console.log(`\n${written} written, ${skipped} skipped${skipped && !force ? " (pass --force to overwrite admin edits)" : ""}.`);
}

async function sealPasswords(master) {
  if (!existsSync(SECRETS_PATH)) fail(`${SECRETS_PATH} not found — build the client sites first.`);
  const secrets = JSON.parse(readFileSync(SECRETS_PATH, "utf8"));
  const passwords = {};
  for (const [slug, pw] of Object.entries(secrets)) {
    if (!/^[a-z0-9-]{1,40}$/.test(slug)) fail(`clients.secrets.json: bad slug "${slug}"`);
    if (typeof pw !== "string" || !pw) fail(`clients.secrets.json: no password for ${slug}`);
    const encPath = join(REPO_ROOT, slug, "utilization.enc.json");
    if (!existsSync(encPath)) fail(`${slug}: ${encPath} does not exist — cannot verify its password; rebuild that site or remove the slug.`);
    if (!(await decrypts(encPath, pw))) fail(`${slug}: the password in clients.secrets.json does not decrypt ${slug}/utilization.enc.json — aborting, nothing was sent.`);
    passwords[slug] = pw;
    console.log(`✓ ${slug.padEnd(17)} password verified against its utilization.enc.json`);
  }
  const missing = CLIENTS.map((c) => c.slug).filter((s) => !passwords[s]);
  if (missing.length) console.warn(`! no password in clients.secrets.json for: ${missing.join(", ")} (they will not appear in the dashboard)`);
  const updatedAt = new Date().toISOString();
  const enc = await encryptJSON({ v: 1, updatedAt, passwords }, master);
  const out = await adminCall(master, "pws.put", { enc });
  console.log(`\nVault sealed: ${Object.keys(passwords).length} password(s), stored at ${out.updatedAt || updatedAt}.`);
  if (existsSync(ESCROW_KEY_FILE) && existsSync(CF_TOKEN_FILE)) await escrowSeal(master);
  else console.warn(`! escrow not refreshed (${ESCROW_KEY_FILE} or ${CF_TOKEN_FILE} missing) — the worker keeps serving the OLD passwords to admin_pw/feed_pw/email sign-in until you run: node sync-admin-kv.mjs escrow`);
}

async function verify(master) {
  console.log("Brands:");
  for (const client of CLIENTS) {
    let line;
    try {
      const r = await brandGet(client.slug);
      line = r.found
        ? `found   ${(r.doc.updatedFrom || "?").padEnd(6)} ${r.doc.updatedAt || "?"}  ${brandSummary(r.doc)}${r.doc.demo ? " (demo)" : ""}  "${r.doc.name}"`
        : "absent  (code default in effect)";
    } catch (e) { line = `ERROR   ${e.message}`; }
    console.log(`  ${client.slug.padEnd(17)} ${line}`);
  }
  console.log("\nPassword vault (myrx:pws):");
  const r = await api({ admin_pw: master, action: "pws.get" });
  if (r.status === 404) { console.log("  not seeded — run: node sync-admin-kv.mjs seal-passwords"); return; }
  if (!r.out.ok) { console.log(`  ERROR ${describe(r)}`); return; }
  let plain = null;
  try { plain = await decryptJSON(r.out.enc, master); } catch { /* sealed with another master */ }
  if (!plain || !plain.passwords) { console.log(`  stored ${r.out.updatedAt || "?"} but does NOT decrypt with this master — re-run seal-passwords`); return; }
  const slugs = Object.keys(plain.passwords);
  const missing = CLIENTS.map((c) => c.slug).filter((s) => !slugs.includes(s));
  console.log(`  decrypts with the master: yes — ${slugs.length} password(s), sealed ${plain.updatedAt || r.out.updatedAt || "?"}`);
  console.log(`  slugs: ${slugs.join(", ")}`);
  if (missing.length) console.log(`  ! missing: ${missing.join(", ")} — re-run seal-passwords after building those sites`);
}

// ---- escrow: mirror myrx:pws into myrx:pws-escrow under ESCROW_KEY (the worker's exact scheme) ----
async function kvValue(method, key, body) {
  if (!existsSync(CF_TOKEN_FILE)) fail(`${CF_TOKEN_FILE} not found (Cloudflare API token with Workers KV Storage Write).`);
  const tok = readFileSync(CF_TOKEN_FILE, "utf8").trim();
  const url = `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT}/storage/kv/namespaces/${KV_NAMESPACE}/values/${encodeURIComponent(key)}`;
  const res = await fetch(url, { method, headers: { authorization: `Bearer ${tok}`, ...(body !== undefined ? { "content-type": "text/plain" } : {}) }, body, signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (method === "GET" && res.status === 404) return null;
  if (!res.ok) fail(`KV ${method} ${key} -> HTTP ${res.status}`);
  return method === "GET" ? res.text() : true;
}
async function escrowSeal(master) {
  if (!existsSync(ESCROW_KEY_FILE)) fail(`${ESCROW_KEY_FILE} not found. Create it and bind the SAME value as the worker secret:\n  (cd sync-worker && openssl rand -hex 32 | tr -d '\\n' > .escrowkey && chmod 600 .escrowkey && npx wrangler secret put ESCROW_KEY < .escrowkey)`);
  const escrowKey = readFileSync(ESCROW_KEY_FILE, "utf8").trim();
  if (!/^[0-9a-f]{64}$/.test(escrowKey)) fail(`${ESCROW_KEY_FILE}: expected 64 hex characters.`);
  const raw = await kvValue("GET", "myrx:pws");
  if (raw === null) fail("myrx:pws is not in KV yet — run seal-passwords first.");
  let vault; try { vault = JSON.parse(raw); } catch { fail("myrx:pws is not JSON."); }
  let plain = null;
  try { plain = await decryptJSON(vault.enc, master); } catch { /* sealed under another master */ }
  if (!plain || !plain.passwords) fail("myrx:pws does not decrypt with this master — re-run seal-passwords (it re-seals the vault, then the escrow).");
  const passwords = plain.passwords;
  // identical to the worker's sealEscrow(): key = SHA-256(ESCROW_KEY || salt), AES-GCM-256, {v:1, passwords, root}
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const digest = await crypto.subtle.digest("SHA-256", Buffer.concat([Buffer.from(escrowKey), Buffer.from(salt)]));
  const key = await crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt"]);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify({ v: 1, passwords, root: master })));
  const b64 = (buf) => Buffer.from(buf).toString("base64");
  const rec = { v: 1, updatedAt: new Date().toISOString(), pwsUpdatedAt: typeof vault.updatedAt === "string" ? vault.updatedAt : null, count: Object.keys(passwords).length,
    enc: { salt: b64(salt), iv: b64(iv), data: b64(data) } };
  await kvValue("PUT", "myrx:pws-escrow", JSON.stringify(rec));
  console.log(`Escrow sealed (myrx:pws-escrow): ${rec.count} partner password(s) + the master; mirrors the vault sealed ${rec.pwsUpdatedAt || "?"}. Live within a minute (per-isolate cache).`);
}

// ---- main ----
const args = process.argv.slice(2);
const cmd = args.find((a) => !a.startsWith("--"));
const flags = new Set(args.filter((a) => a.startsWith("--")));
const KNOWN = { "seed-brands": ["--force", "--pw-stdin"], "seal-passwords": ["--pw-stdin"], "escrow": ["--pw-stdin"], "verify": ["--pw-stdin"] };
if (!cmd || !(cmd in KNOWN)) fail(USAGE, 2);
for (const f of flags) if (!KNOWN[cmd].includes(f)) fail(`Unknown flag ${f} for ${cmd}\n${USAGE}`, 2);

try {
  if (process.env.SYNC_API) console.log(`Using worker ${SYNC_URL.origin} (SYNC_API override)`);
  const master = await getMaster(flags.has("--pw-stdin"));
  if (cmd === "seed-brands") await seedBrands(master, flags.has("--force"));
  else if (cmd === "seal-passwords") await sealPasswords(master);
  else if (cmd === "escrow") await escrowSeal(master);
  else await verify(master);
} catch (e) {
  fail(e && e.message ? e.message : String(e));
}
