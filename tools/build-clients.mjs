// build-clients.mjs — generate per-client gated report sites under /<slug>/.
//
// Each client folder gets:
//   index.html            copy of the root dashboard + window.CLIENT_SITE marker
//                         (client mode: utilization-only, gate = their data file)
//   utilization.enc.json  ONLY that client's rows — sliced from the claims
//                         workbook BEFORE aggregation, dims rebuilt from the
//                         slice, fee fields stripped — encrypted with the
//                         client's own password. Isolation comes from the data:
//                         other clients' rows are never in the file.
//
// Passwords live in clients.secrets.json next to this script (gitignored,
// NEVER published). Missing ones are generated (3 words + 2 digits, like the
// main gate password). Re-running keeps existing passwords stable.
//
//   node build-clients.mjs "<All ... claims.xlsx>" [more.xlsx ...] [--push] [--no-kv]
//   node build-clients.mjs --html-only [--push] [--no-kv]
//
// --html-only  rebuild every <slug>/index.html from the root index.html + marker
//              without touching claims, utilization.enc.json or passwords (no
//              workbook needed). The demo block (nameMap) is carried over from
//              the existing copy since it can only be computed from claims.
// --no-kv      skip the KV brand lookup and bake the code-default brands.
//
// Brands: before markers are built, the current "myrx:brand:<slug>" doc is
// fetched from the sync worker (public brand_get route) for every client. A
// found doc's name/brand override the code defaults in clients.config.mjs, so a
// rebuild never reverts an edit made from the root dashboard's Clients tab.
// Every KV doc is re-validated here (brand-validate.mjs, the worker's own
// rules) before it is baked into a committed, published index.html — the KV
// namespace is shared and writable outside the worker, so nothing from it is
// trusted on the way into git. If any lookup fails OR fails validation the
// build still runs on code defaults, but --push is refused (stale or bad
// brands must not be published) unless --no-kv was passed.
//
// The roster (CLIENTS) lives in clients.config.mjs, shared with sync-admin-kv.mjs.
//
// Input files need the "Pharmacy Group" column (the annual "All MyRxCard …"
// export has it; per-quarter exports without it are skipped with a warning).

import XLSX from "xlsx";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomInt } from "node:crypto";
import { execFileSync } from "node:child_process";
import { aggregateRows } from "./aggregate.mjs";
import { encryptJSON, REPO_ROOT } from "./store.mjs";
import { CLIENTS, codeBrand } from "./clients.config.mjs";
import { validateBrand, validateName, isPlainObject } from "./brand-validate.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SECRETS_PATH = join(__dirname, "clients.secrets.json");
const SYNC_API = process.env.SYNC_API || "https://myrxcard-sync.trevorfallbacher.workers.dev";
const KV_TIMEOUT_MS = 5000;
// Only public brand_get bodies go here, but the endpoint is held to the same
// rule as sync-admin-kv.mjs: https, or a local dev worker, and an override
// is announced so it is never silently in effect.
{
  let u = null;
  try { u = new URL(SYNC_API); } catch {}
  if (!u || (u.protocol !== "https:" && !/^(localhost|127\.0\.0\.1|\[::1\])$/.test(u.hostname))) {
    console.error(`SYNC_API must be an https URL (or localhost for a dev worker): ${SYNC_API}`);
    process.exit(1);
  }
  if (process.env.SYNC_API) console.log(`Using worker ${u.origin} (SYNC_API override)`);
}
// terminal-safe rendering of any name that came from KV
const printable = (s) => String(s ?? "").replace(/[\x00-\x1f\x7f]/g, "");

// Rewrite a source partner's claim rows into a demo partner's: every distinct
// pharmacy becomes one of the demo locations (stable order), NPIs are replaced
// with a hash-derived number, dollars are scaled. Returns rows + the
// UPPERCASE original-name -> demo-name map the page uses to relabel searches.
function demoRows(rows, demo) {
  const hash = (str) => { let h = 2166136261; for (const ch of str) { h ^= ch.charCodeAt(0); h = Math.imul(h, 16777619) >>> 0; } return h; };
  const map = new Map(); let n = 0;
  const out = rows.map((r) => {
    const k = norm(r.PharmacyName).toUpperCase() + "|" + norm(r.NPI);
    if (!map.has(k)) {
      const loc = demo.locations[n % demo.locations.length]; const round = Math.floor(n / demo.locations.length);
      map.set(k, { name: round ? `${loc[0]} ${round + 1}` : loc[0], address: loc[1], city: loc[2], state: loc[3], zip: loc[4], npi: String(1000000000 + (hash(k) % 899999999)) });
      n++;
    }
    const m = map.get(k), o = { ...r };
    o.PharmacyName = m.name; o.NPI = m.npi; o.PharmacyAddress = m.address; o.PharmacyCity = m.city; o.PharmacyState = m.state; o.PharmacyZip = m.zip;
    o["Pharmacy Group"] = demo.groupName;
    for (const f of ["PlanGrossAmount", "PatientResponsibility", "AWP", "UsualAndCustomary", "BillDispFee"])
      if (o[f] !== null && o[f] !== undefined && o[f] !== "" && Number.isFinite(+o[f])) o[f] = Math.round(+o[f] * demo.scale * 100) / 100;
    return o;
  });
  const nameMap = {}; for (const [k, m] of map) nameMap[k.split("|")[0]] = m.name;
  return { rows: out, nameMap };
}

const norm = (s) => String(s ?? "").trim();

function genPassword() {
  const words = readFileSync("/usr/share/dict/words", "utf8").split("\n")
    .filter((w) => /^[a-z]{4,8}$/.test(w));
  const pick = () => words[randomInt(words.length)];
  return `${pick()}-${pick()}-${pick()}-${randomInt(10)}${randomInt(10)}`;
}

function loadSecrets() {
  try { return JSON.parse(readFileSync(SECRETS_PATH, "utf8")); } catch { return {}; }
}

function readWorkbook(path) {
  const wb = XLSX.read(readFileSync(path), { type: "buffer", cellDates: false, raw: true });
  let best = null, bestRows = null;
  for (const name of wb.SheetNames) {
    const rows = XLSX.utils.sheet_to_json(wb.Sheets[name], { defval: null });
    if (!best || rows.length > bestRows.length) { best = name; bestRows = rows; }
  }
  // normalize the padded column names once so "Pharmacy Group" is findable
  return bestRows.map((r) => { const o = {}; for (const k in r) o[norm(k)] = r[k]; return o; });
}

// ---- KV brand lookup (public brand_get route on the sync worker) ----
// Returns Map slug -> { found:true, doc } | { found:false } | { failed:true }.
// A doc that fails validation counts as failed: it is neither baked nor
// pushed over (see kvDocProblem).
async function fetchKvBrand(slug) {
  const res = await fetch(SYNC_API, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ brand_get: slug }),
    signal: AbortSignal.timeout(KV_TIMEOUT_MS),
  });
  const out = await res.json().catch(() => null);
  if (!res.ok || !out || out.ok !== true) throw new Error((out && out.error) || `HTTP ${res.status}`);
  if (!(out.found && isPlainObject(out.doc))) return { found: false };
  const problem = kvDocProblem(out.doc);
  if (problem) return { failed: true, invalid: problem };
  return { found: true, doc: out.doc };
}

// The same checks the worker applies on brand.put, applied again on the way
// out of KV: name text rules, brand schema (validateBrand also normalizes in
// place — lowercased colors, stripped control characters — so what is baked
// is the normalized form). Returns a "path: reason" string or null.
function kvDocProblem(doc) {
  const nm = validateName(doc.name);
  if (nm.error) return `name: ${nm.error}`;
  doc.name = nm.name;
  if (doc.brand === null || doc.brand === undefined) return null;
  if (!isPlainObject(doc.brand)) return "brand: must be an object or null";
  const e = validateBrand(doc.brand);
  return e ? `${e.path}: ${e.reason}` : null;
}

async function fetchKvBrands(clients) {
  const results = new Map();
  await Promise.all(clients.map(async (client) => {
    try {
      const r = await fetchKvBrand(client.slug);
      if (r.invalid) console.warn(`! KV brand for ${client.slug} failed validation (${printable(r.invalid)}) — using code default`);
      results.set(client.slug, r);
    } catch (e) {
      console.warn(`! KV brand for ${client.slug} unavailable — using code default (${printable(e && e.message ? e.message : e)})`);
      results.set(client.slug, { failed: true });
    }
  }));
  return results;
}

// Name + brand block for a client's marker: the KV doc when one exists
// (brand null => stock look => no brand block), else the code default.
function resolveBrand(client, kv) {
  if (kv && kv.found) {
    const name = typeof kv.doc.name === "string" && kv.doc.name ? kv.doc.name : client.name;
    const brand = kv.doc.brand && typeof kv.doc.brand === "object" ? { ...kv.doc.brand, name } : undefined;
    return { name, brand, demoBadge: kv.doc.demoBadge !== false, source: kv.doc.brand ? "KV brand" : "KV stock" };
  }
  return { name: client.name, brand: codeBrand(client), demoBadge: true, source: kv && kv.failed ? "code default (KV unavailable)" : "code default" };
}

// "<" is escaped so admin-edited text (tagline, headings…) can never close
// the injected <script>, whatever validation upstream did.
function markerFor({ slug, name, type, brand, demo }) {
  const json = JSON.stringify({ slug, name, type: type || "pharmacy", ...(brand ? { brand } : {}), ...(demo ? { demo } : {}) })
    .replace(/</g, "\\u003c");
  return `<script>window.CLIENT_SITE = ${json};</script>`;
}

// Does an existing gate.enc.json still open with this client's current password?
// Mirrors the worker's check (PBKDF2-SHA256 310k -> AES-GCM-256, blob {salt,iv,data}
// base64) so an --html-only rebuild can leave a good gate file alone instead of
// re-encrypting it with a fresh salt on every run (which churned one file per
// client per build). Returns null when the file is fine, else why it needs writing.
async function gateFileProblem(path, slug, password) {
  if (!existsSync(path)) return "missing";
  let blob;
  try { blob = JSON.parse(readFileSync(path, "utf8")); } catch { return "unreadable"; }
  if (!isPlainObject(blob) || [blob.salt, blob.iv, blob.data].some((v) => typeof v !== "string")) return "malformed";
  try {
    const b = (x) => new Uint8Array(Buffer.from(x, "base64"));
    const baseKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
    const aesKey = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: b(blob.salt), iterations: 310000, hash: "SHA-256" },
      baseKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b(blob.iv) }, aesKey, b(blob.data));
    const doc = JSON.parse(new TextDecoder().decode(plain));
    if (!isPlainObject(doc) || doc.purpose !== "gate" || doc.slug !== slug) return "wrong contents";
    return null;
  } catch {
    return "does not decrypt with the current password";
  }
}

// The demo block from an already-built copy (nameMap is derived from claims
// rows, so --html-only has to carry it over rather than recompute it).
function existingMarker(slug) {
  const path = join(REPO_ROOT, slug, "index.html");
  if (!existsSync(path)) return null;
  const m = readFileSync(path, "utf8").match(/<script>window\.CLIENT_SITE = (\{.*?\});<\/script>/);
  if (!m) return null;
  try { return JSON.parse(m[1]); } catch { return null; }
}

const args = process.argv.slice(2);
const doPush = args.includes("--push");
const noKv = args.includes("--no-kv");
const htmlOnly = args.includes("--html-only");
const files = args.filter((a) => !a.startsWith("--"));
if (!files.length && !htmlOnly) {
  console.error('Usage: node build-clients.mjs "<All … claims.xlsx>" [more.xlsx ...] [--push] [--no-kv]\n       node build-clients.mjs --html-only [--push] [--no-kv]');
  process.exit(1);
}
if (htmlOnly && files.length) console.warn("! --html-only ignores workbook arguments");

// KV brands first: cheap, and a --push with stale brands aborts before any work.
let kvBrands = new Map();
if (noKv) {
  console.log("KV brand lookup skipped (--no-kv) — baking code-default brands.");
} else {
  kvBrands = await fetchKvBrands(CLIENTS);
  const failed = [...kvBrands.entries()].filter(([, v]) => v.failed).map(([s]) => s);
  const found = [...kvBrands.values()].filter((v) => v.found).length;
  console.log(`KV brands: ${found} found, ${CLIENTS.length - found - failed.length} unset, ${failed.length} unavailable.`);
  if (doPush && failed.length) {
    console.error(`Refusing to push: KV brand lookup failed or returned an invalid doc for ${failed.join(", ")} — a push now could revert admin edits or publish bad data.\n` +
      "Retry once the worker is reachable (or fix the doc from the Clients tab), run without --push, or pass --no-kv to knowingly bake code defaults.");
    process.exit(1);
  }
}

const rootIndex = readFileSync(join(REPO_ROOT, "index.html"), "utf8");
const built = [];

if (htmlOnly) {
  const secrets = loadSecrets(); // needed for the gate files; passwords are never regenerated here
  for (const client of CLIENTS) {
    const dir = join(REPO_ROOT, client.slug);
    if (!existsSync(join(dir, "utilization.enc.json"))) { console.warn(`! /${client.slug}/ has no utilization.enc.json yet — skipped (build it from claims first)`); continue; }
    // The tiny gate file is written only when it is missing or no longer opens
    // with the client's current password (sites built before gate files existed,
    // or a password change since). A good one is left byte-for-byte alone so an
    // html-only rebuild does not churn every client's gate.enc.json with a fresh
    // salt. The claims build below still writes it unconditionally.
    let gateNote = "";
    if (secrets[client.slug]) {
      const gatePath = join(dir, "gate.enc.json");
      const problem = await gateFileProblem(gatePath, client.slug, secrets[client.slug]);
      if (problem) {
        writeFileSync(gatePath, JSON.stringify(await encryptJSON({ v: 1, slug: client.slug, purpose: "gate" }, secrets[client.slug])) + "\n");
        gateNote = `, gate.enc.json rewritten (${problem})`;
      }
    }
    const prev = existingMarker(client.slug);
    let demo;
    if (client.demo) {
      if (prev && prev.demo) demo = prev.demo;
      else { demo = { from: client.demo.from, note: client.demo.note, nameMap: {} }; console.warn(`! /${client.slug}/ demo nameMap not found in the existing copy — searches will not be relabeled until a claims rebuild`); }
    }
    const { name, brand, demoBadge, source } = resolveBrand(client, kvBrands.get(client.slug));
    if (demo && demoBadge === false) demo = { ...demo, badge: false }; // offline fallback for the admin's badge choice
    const marker = markerFor({ slug: client.slug, name, type: client.type, brand, demo });
    writeFileSync(join(dir, "index.html"), rootIndex.replace("<body>", "<body>\n" + marker));
    built.push(client.slug);
    console.log(`✓ /${client.slug}/  ${printable(name)} — index.html rebuilt (${brand ? "branded" : "stock look"}, ${source}${gateNote})`);
  }
  if (!built.length) { console.error("No client folders to rebuild."); process.exit(1); }
} else {
  const secrets = loadSecrets();
  const stores = new Map(); // slug -> {generatedAt, latest, periods}

  for (const file of files) {
    const rows = readWorkbook(file);
    if (!rows.length || !("Pharmacy Group" in rows[0])) {
      console.warn(`! ${file.split(/[\\/]/).pop()} has no "Pharmacy Group" column — skipped`);
      continue;
    }
    const label = file.split(/[\\/]/).pop();
    const slugOf = label.toLowerCase().replace(/\.xlsx$/, "").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48);
    for (const client of CLIENTS) {
      let subset = rows.filter((r) => client.match(norm(r["Pharmacy Group"]).toUpperCase()));
      if (!subset.length) continue;
      if (client.demo) { const d = demoRows(subset, client.demo); subset = d.rows; client.demo.nameMap = { ...(client.demo.nameMap || {}), ...d.nameMap }; }
      const period = aggregateRows(subset, label);
      // clients see utilization only: strip Avalon's fee measures entirely
      // (zero placeholders hold slots 13-14 so member/savings/qty stay at 15-18)
      delete period.money.adminFees;
      period.facts = period.facts.map((f) => [...f.slice(0, 13), 0, 0, ...f.slice(15, 19)]);
      period.client = client.name;
      const key = `${period.periodKey || "import"}~${slugOf}`;
      period.periodKey = key;
      period.processedAt = new Date().toISOString();
      const store = stores.get(client.slug) || { generatedAt: null, latest: null, periods: {} };
      store.periods[key] = period;
      stores.set(client.slug, store);
    }
  }

  if (!stores.size) { console.error("No client rows found in the given files."); process.exit(1); }

  for (const client of CLIENTS) {
    const store = stores.get(client.slug);
    if (!store) continue;
    store.latest = Object.keys(store.periods).sort().pop();
    store.generatedAt = new Date().toISOString();
    if (!secrets[client.slug]) secrets[client.slug] = genPassword();

    const dir = join(REPO_ROOT, client.slug);
    mkdirSync(dir, { recursive: true });
    const enc = await encryptJSON(store, secrets[client.slug]);
    writeFileSync(join(dir, "utilization.enc.json"), JSON.stringify(enc) + "\n");
    // tiny gate file: what the sync worker decrypts to verify this client's
    // password (instead of the multi-MB utilization file)
    writeFileSync(join(dir, "gate.enc.json"), JSON.stringify(await encryptJSON({ v: 1, slug: client.slug, purpose: "gate" }, secrets[client.slug])) + "\n");
    // brand block: KV doc if the owner has one, else the code default (logos inlined as data URIs)
    const { name, brand, demoBadge, source } = resolveBrand(client, kvBrands.get(client.slug));
    let demo = client.demo ? { from: client.demo.from, note: client.demo.note, nameMap: client.demo.nameMap || {} } : undefined;
    if (demo && demoBadge === false) demo = { ...demo, badge: false };
    const marker = markerFor({ slug: client.slug, name, type: client.type, brand, demo });
    writeFileSync(join(dir, "index.html"), rootIndex.replace("<body>", "<body>\n" + marker));

    const p = store.periods[store.latest];
    built.push(client.slug);
    console.log(`✓ /${client.slug}/  ${printable(name)} — ${Object.keys(store.periods).length} period(s), latest ${p.periodLabel}, ` +
      `${p.claims.paid.toLocaleString()} paid claims, ${p.pharmacies.length} pharmacies (${source})`);
  }

  writeFileSync(SECRETS_PATH, JSON.stringify(secrets, null, 2) + "\n");
  console.log(`\nPasswords are in ${SECRETS_PATH} (gitignored — do not publish).`);
  console.log("If any password is new, re-seal the admin vault: node sync-admin-kv.mjs seal-passwords");
}
console.log("URLs: https://reports.myrxcard.com/<slug>/");

if (doPush) {
  const git = (...a) => execFileSync("git", a, { cwd: REPO_ROOT, encoding: "utf8" }).trim();
  git("add", ...(htmlOnly ? built.flatMap((s) => [join(s, "index.html"), join(s, "gate.enc.json")].filter((f) => existsSync(join(REPO_ROOT, f)))) : built));
  const changed = git("status", "--porcelain");
  if (!changed) { console.log("Nothing to publish."); }
  else {
    git("commit", "-m", `client sites: ${built.join(", ")}${htmlOnly ? " (html only)" : ""}`);
    git("push");
    console.log("Pushed — Pages redeploys in ~1 minute.");
  }
}
