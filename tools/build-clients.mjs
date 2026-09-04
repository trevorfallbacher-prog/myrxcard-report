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
  // ---- DEMO sites: a prospect sees the full report on anonymized, scaled claims
  // cloned from an existing partner's slice (pharmacies renamed and relocated,
  // NPIs replaced, dollars scaled). `from` names the source Pharmacy Group; the
  // page relabels the source microsite's search activity the same way.
  { slug: "aurora", name: "Aurora Health Care", type: "pharmacy", match: (g) => g === "UWHC PHARMACIES",
    demo: { from: "uwhc", scale: 0.82, groupName: "AURORA PHARMACY", note: "Demo data: anonymized, scaled sample. Not Aurora Health Care's claims.",
      locations: [
        ["Aurora Pharmacy - St. Luke's Medical Center", "2900 W Oklahoma Ave", "Milwaukee", "WI", "53215"],
        ["Aurora Pharmacy - Sinai Medical Center", "945 N 12th St", "Milwaukee", "WI", "53233"],
        ["Aurora Pharmacy - West Allis Medical Center", "8901 W Lincoln Ave", "West Allis", "WI", "53227"],
        ["Aurora Pharmacy - Grafton Medical Center", "975 Port Washington Rd", "Grafton", "WI", "53024"],
        ["Aurora Pharmacy - Summit Medical Center", "36500 Aurora Dr", "Summit", "WI", "53066"],
        ["Aurora Pharmacy - Kenosha Medical Center", "10400 75th St", "Kenosha", "WI", "53142"],
        ["Aurora Pharmacy - BayCare Medical Center", "2845 Greenbrier Rd", "Green Bay", "WI", "54311"],
        ["Aurora Pharmacy - Sheboygan Memorial", "2629 N 7th St", "Sheboygan", "WI", "53083"],
        ["Aurora Pharmacy - Oshkosh Medical Center", "855 N Westhaven Dr", "Oshkosh", "WI", "54904"],
        ["Aurora Pharmacy - Burlington Memorial", "252 McHenry St", "Burlington", "WI", "53105"],
        ["Aurora Pharmacy - Two Rivers Medical Center", "5000 Memorial Dr", "Two Rivers", "WI", "54241"],
        ["Aurora Pharmacy - Hartford Medical Center", "1032 E Sumner St", "Hartford", "WI", "53027"],
        ["Aurora Pharmacy - Mount Pleasant", "10200 Washington Ave", "Mount Pleasant", "WI", "53406"],
        ["Aurora Pharmacy - Waukesha Health Center", "1101 Delafield St", "Waukesha", "WI", "53188"],
        ["Aurora Pharmacy - Lakeland Medical Center", "W3985 County Rd NN", "Elkhorn", "WI", "53121"],
        ["Aurora Pharmacy - Marinette", "1505 Main St", "Marinette", "WI", "54143"],
        ["Aurora Pharmacy - Kaukauna", "2600 Lawe St", "Kaukauna", "WI", "54130"],
        ["Aurora Pharmacy - Fond du Lac", "210 Wisconsin American Dr", "Fond du Lac", "WI", "54937"],
      ] },
    brand: {
      logo: "brands/aurora.png", logoDark: "brands/aurora-footer.webp", logoHeight: 22, tagline: "Pharmacy performance demo",
      colors: { primary: "#00805f", secondary: "#005f47", tertiary: "#2ea083", accent: "#814fa0", accentBright: "#9d6bc0",
        dark: { primary: "#3fbf95", secondary: "#6fd6b3", tertiary: "#2ea083", accent: "#b48ad4", accentBright: "#c9a6e3" } },
      fonts: { google: "family=Montserrat:wght@400;500;600;700", body: "'Montserrat', 'Helvetica Neue', Arial, sans-serif", heading: "'Montserrat', 'Helvetica Neue', Arial, sans-serif" },
      headings: { weight: 700, letterSpacing: "-0.01em", gate: "Aurora Health Care", menuLabel: "REPORTS",
        tabs: { search: "Website searches", util: "Claims utilization" }, titles: { search: "Website searches", util: "Claims utilization" } },
      layout: { header: "title-first", radius: "10px", density: "comfortable" }, poweredBy: true } },
];

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
    const mime = rel.endsWith(".svg") ? "image/svg+xml" : rel.endsWith(".png") ? "image/png" : rel.endsWith(".webp") ? "image/webp" : "image/jpeg";
    return `data:${mime};base64,${buf.toString("base64")}`;
  };
  const brand = client.brand ? { ...client.brand, name: client.name, logo: inlineImg(client.brand.logo), logoDark: inlineImg(client.brand.logoDark) } : undefined;
  const demo = client.demo ? { from: client.demo.from, note: client.demo.note, nameMap: client.demo.nameMap || {} } : undefined;
  const marker = `<script>window.CLIENT_SITE = ${JSON.stringify({ slug: client.slug, name: client.name, type: client.type || "pharmacy", ...(brand ? { brand } : {}), ...(demo ? { demo } : {}) })};</script>`;
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
