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
//   node build-clients.mjs "<All ... claims.xlsx>" [more.xlsx ...] [--push]
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

const __dirname = dirname(fileURLToPath(import.meta.url));
const SECRETS_PATH = join(__dirname, "clients.secrets.json");

// slug -> which "Pharmacy Group" values (uppercased) belong to the client
const CLIENTS = [
  { slug: "uwhc", name: "UW Health (UWHC)", type: "pharmacy", match: (g) => g === "UWHC PHARMACIES",
    brand: {
      logo: "brands/uwhc.svg", logoHeight: 26, tagline: "Pharmacy services report",
      colors: { primary: "#c5050c", secondary: "#9b0407", tertiary: "#d9484d", accent: "#065dba", accentBright: "#2b7ddb",
        dark: { primary: "#ff7075", secondary: "#ff9094", tertiary: "#d9484d", accent: "#6ea9ff", accentBright: "#8fbcff" } },
      fonts: { google: "family=Public+Sans:wght@400;500;600;700", body: "'Public Sans', 'Helvetica Neue', Arial, sans-serif", heading: "'Public Sans', 'Helvetica Neue', Arial, sans-serif" },
      headings: { transform: "uppercase", weight: 700, letterSpacing: "0.04em", gate: "UW Health", menuLabel: "REPORTS",
        tabs: { search: "Website searches", util: "Claims utilization" }, titles: { search: "Website searches", util: "Claims utilization" } },
      layout: { header: "view-first", radius: "6px", density: "compact" }, poweredBy: true } },
  { slug: "marshfield", name: "Marshfield Clinic", type: "pharmacy", match: (g) => g === "MARSHFIELD PHARMACIES" },
  { slug: "brookshire", name: "Brookshire Brothers", type: "pharmacy", match: (g) => g === "BROOKSHIRE BROTHERS PHARMACY" },
  { slug: "rrh", name: "Rochester Regional Health", type: "pharmacy", match: (g) => g.startsWith("RRH"),
    brand: {
      logo: "brands/rrh.svg", logoDark: "brands/rrh-dark.svg", logoHeight: 30, tagline: "Pharmacy savings report",
      colors: { primary: "#0077c8", secondary: "#005b99", tertiary: "#3a97d8", accent: "#e8a317", accentBright: "#f7b733",
        dark: { primary: "#5fb2f5", secondary: "#8ac8ff", tertiary: "#3a97d8", accent: "#f0b43c", accentBright: "#ffc95e" } },
      fonts: { google: "family=Source+Sans+3:wght@400;500;600;700", body: "'Source Sans 3', 'Helvetica Neue', Arial, sans-serif", heading: "'Source Sans 3', 'Helvetica Neue', Arial, sans-serif" },
      headings: { weight: 700, letterSpacing: "-0.01em", gate: "Rochester Regional Health", menuLabel: "REPORTS",
        tabs: { search: "Website searches", util: "Claims utilization" }, titles: { search: "Website searches", util: "Claims utilization" } },
      layout: { header: "title-first", radius: "8px", density: "comfortable" }, poweredBy: true } },
  { slug: "sunlife", name: "Sun Life Pharmacies", type: "pharmacy", match: (g) => g === "SUN LIFE PHARMACIES" },
  { slug: "altscripts", name: "AltScripts Specialty Pharmacy", type: "pharmacy", match: (g) => g === "ALTSCRIPTS SPECIALTY PHARMACY" },
  { slug: "ryan", name: "Ryan Pharmacy", type: "pharmacy", match: (g) => g === "RYAN PHARMACY" },
  { slug: "candc", name: "C & C Pharmacy", type: "pharmacy", match: (g) => g === "C & C PHARMACY" },
  { slug: "communitymarkets", name: "Community Markets", type: "pharmacy", match: (g) => g === "COMMUNITY MARKETS" },
  { slug: "greatscot", name: "Great Scot Pharmacies", type: "pharmacy", match: (g) => g === "GREAT SCOT PHARMACIES" },
];

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

const args = process.argv.slice(2);
const doPush = args.includes("--push");
const files = args.filter((a) => !a.startsWith("--"));
if (!files.length) {
  console.error('Usage: node build-clients.mjs "<All … claims.xlsx>" [more.xlsx ...] [--push]');
  process.exit(1);
}

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
    const subset = rows.filter((r) => client.match(norm(r["Pharmacy Group"]).toUpperCase()));
    if (!subset.length) continue;
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

const rootIndex = readFileSync(join(REPO_ROOT, "index.html"), "utf8");
const built = [];
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
  // brand block: logos are inlined as data URIs so the page needs no extra assets
  const inlineImg = (rel) => {
    if (!rel) return undefined;
    const buf = readFileSync(join(__dirname, rel));
    const mime = rel.endsWith(".svg") ? "image/svg+xml" : rel.endsWith(".png") ? "image/png" : "image/jpeg";
    return `data:${mime};base64,${buf.toString("base64")}`;
  };
  const brand = client.brand ? { ...client.brand, name: client.name, logo: inlineImg(client.brand.logo), logoDark: inlineImg(client.brand.logoDark) } : undefined;
  const marker = `<script>window.CLIENT_SITE = ${JSON.stringify({ slug: client.slug, name: client.name, type: client.type || "pharmacy", ...(brand ? { brand } : {}) })};</script>`;
  writeFileSync(join(dir, "index.html"), rootIndex.replace("<body>", "<body>\n" + marker));

  const p = store.periods[store.latest];
  built.push(client.slug);
  console.log(`✓ /${client.slug}/  ${client.name} — ${Object.keys(store.periods).length} period(s), latest ${p.periodLabel}, ` +
    `${p.claims.paid.toLocaleString()} paid claims, ${p.pharmacies.length} pharmacies`);
}

writeFileSync(SECRETS_PATH, JSON.stringify(secrets, null, 2) + "\n");
console.log(`\nPasswords are in ${SECRETS_PATH} (gitignored — do not publish).`);
console.log("URLs: https://reports.myrxcard.com/<slug>/");

if (doPush) {
  const git = (...a) => execFileSync("git", a, { cwd: REPO_ROOT, encoding: "utf8" }).trim();
  git("add", ...built);
  const changed = git("status", "--porcelain");
  if (!changed) { console.log("Nothing to publish."); }
  else {
    git("commit", "-m", `client sites: ${built.join(", ")}`);
    git("push");
    console.log("Pushed — Pages redeploys in ~1 minute.");
  }
}
