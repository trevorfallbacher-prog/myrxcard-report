// ndc-strength.mjs — resolve 11-digit claim NDCs to a strength string ("20 mg
// capsule") via the FDA NDC directory (openFDA, free/public). Results cache to
// data/ndc-strength.json so the watcher works offline after the first run and
// only NDCs it has never seen hit the API.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import XLSX from "xlsx";

const CACHE_PATH = join(dirname(fileURLToPath(import.meta.url)), "data", "ndc-strength.json");

const ndc11 = (v) => String(v ?? "").replace(/\D/g, "").padStart(11, "0");

export function loadStrengthCache() {
  try { return JSON.parse(readFileSync(CACHE_PATH, "utf8")); } catch { return {}; }
}

// 11-digit CMS NDC (5-4-2) -> candidate FDA product_ndc strings (labeler-product).
// FDA segments are unpadded: 4-4-2, 5-3-2, 5-4-1 package formats each gain a pad
// zero in the 11-digit form, so dropping the possible pad recovers the original.
function productCandidates(n) {
  const lab5 = n.slice(0, 5), prod4 = n.slice(5, 9);
  const out = new Set([`${lab5}-${prod4}`]);
  if (lab5[0] === "0") out.add(`${lab5.slice(1)}-${prod4}`);   // 4-4-2
  if (prod4[0] === "0") out.add(`${lab5}-${prod4.slice(1)}`);  // 5-3-2
  return [...out];
}

// "10 mg/1" -> "10 mg"; multi-ingredient products join with "/"
function strengthLabel(rec) {
  const parts = (rec.active_ingredients || [])
    .map((a) => String(a.strength || "").replace(/\/1$/, "").trim().toLowerCase())
    .filter(Boolean);
  if (!parts.length) return "";
  const form = String(rec.dosage_form || "").split(",")[0].trim().toLowerCase();
  return parts.join(" / ") + (form ? ` ${form}` : "");
}

// Fetch any uncached NDCs from openFDA (chunked, throttled) and return the
// full cache. Network failures leave the missing entries unresolved so a
// later run retries them; confirmed directory misses are negative-cached.
export async function ensureStrengths(ndcs) {
  const cache = loadStrengthCache();
  const missing = [...new Set(ndcs.map(ndc11))].filter((n) => /^\d{11}$/.test(n) && !(n in cache));
  if (!missing.length) return cache;

  const byProduct = new Map(); // product_ndc candidate -> [11-digit NDCs]
  for (const n of missing) for (const c of productCandidates(n)) {
    if (!byProduct.has(c)) byProduct.set(c, []);
    byProduct.get(c).push(n);
  }
  const products = [...byProduct.keys()];
  const done = new Set(); // product candidates whose chunk completed (hit or 404)
  const CHUNK = 40;
  console.log(`  NDC strengths: ${missing.length} new NDCs → ${products.length} product lookups…`);
  for (let i = 0; i < products.length; i += CHUNK) {
    const slice = products.slice(i, i + CHUNK);
    const q = slice.map((p) => `"${p}"`).join("+OR+");
    const url = `https://api.fda.gov/drug/ndc.json?search=product_ndc:(${q})&limit=${CHUNK * 3}`;
    try {
      const res = await fetch(url);
      if (res.ok) {
        const body = await res.json();
        for (const rec of body.results || []) {
          const label = strengthLabel(rec);
          for (const n of byProduct.get(rec.product_ndc) || []) if (!cache[n]) cache[n] = label;
        }
      } else if (res.status !== 404) { // 404 = no match for the whole chunk
        throw new Error(`openFDA HTTP ${res.status}`);
      }
      slice.forEach((p) => done.add(p));
      await new Promise((r) => setTimeout(r, 350)); // stay far under the rate limit
    } catch (e) {
      console.log(`  (NDC lookup stopped early: ${e.message} — the rest resolve on a later run)`);
      break;
    }
  }
  // negative-cache only NDCs whose every candidate was actually checked
  for (const n of missing)
    if (!(n in cache) && productCandidates(n).every((c) => done.has(c))) cache[n] = "";
  mkdirSync(dirname(CACHE_PATH), { recursive: true });
  writeFileSync(CACHE_PATH, JSON.stringify(cache) + "\n");
  return cache;
}

// Scan a claims workbook's NDC column and make sure the cache covers it.
export async function prepareStrengths(filePath) {
  const wb = XLSX.read(readFileSync(filePath), { type: "buffer", cellDates: false, raw: true });
  let rows = null;
  for (const name of wb.SheetNames) {
    const r = XLSX.utils.sheet_to_json(wb.Sheets[name], { defval: null });
    if (!rows || r.length > rows.length) rows = r;
  }
  const ndcs = [];
  for (const r of rows) for (const k in r) if (k.trim() === "NDC" && r[k] != null) ndcs.push(r[k]);
  return ensureStrengths(ndcs);
}
