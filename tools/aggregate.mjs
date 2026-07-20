// aggregate.mjs — parse a MyRx quarterly claims .xlsx into a compact period summary.
//
// Data model (reverse-engineered from "MyRx Avalon Claims Q*.xlsx"):
//   ClaimType  P = Paid claim, R = Reversal (its PlanGrossAmount / ClaimCount are negative)
//   PlanGrossAmount  the plan's gross $ on the claim (negative on reversals)
//   So, matching the Power BI "Performance Summary":
//     Paid $        = Σ PlanGrossAmount over P rows
//     Reversed $    = |Σ PlanGrossAmount over R rows|
//     Collected $   = Paid $ − Reversed $   (== Σ PlanGrossAmount over ALL rows)
//     Reversed % $  = Reversed $ / Paid $
//   Claims mirror the same split using row counts.
//   Pharmacy bar  = Collected $ (net PlanGrossAmount) grouped by PharmacyName, desc.

import XLSX from "xlsx";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// ZIP -> [lat, lon] centroids (GeoNames postal data, CC-BY 4.0) for the map view
let ZIPS = null;
function zipLatLon(zip) {
  if (!ZIPS) {
    try { ZIPS = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "data", "us-zips.json"), "utf8")); }
    catch { ZIPS = {}; }
  }
  return ZIPS[String(zip).replace(/[^0-9]/g, "").slice(0, 5)] || null;
}

const norm = (s) => String(s ?? "").trim();
const num = (v) => {
  if (v === null || v === undefined || v === "") return 0;
  const n = typeof v === "number" ? v : parseFloat(String(v).replace(/[$,]/g, ""));
  return Number.isFinite(n) ? n : 0;
};

// yyyymmdd (number or string) -> {y, m}  (m is 1-12)
function ymd(v) {
  const s = norm(v);
  if (!/^\d{8}$/.test(s)) return null;
  return { y: +s.slice(0, 4), m: +s.slice(4, 6), d: +s.slice(6, 8) };
}

const MONTHS = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// Titlecase a SHOUTED pharmacy name for display, preserving short tokens.
function titleize(s) {
  return norm(s)
    .toLowerCase()
    .replace(/\b([a-z])/g, (m) => m.toUpperCase())
    .replace(/\b(Llc|Inc|Rx|Cvs|Uw|Np|Ii|Iii)\b/gi, (m) => m.toUpperCase());
}

export function aggregateWorkbook(filePath) {
  const wb = XLSX.read(readFileSync(filePath), { type: "buffer", cellDates: false, raw: true });
  // Some exports carry extra partial sheets (e.g. a single-month preview) next
  // to the full extract — use the sheet with the most claim rows.
  let best = null, bestRows = null;
  for (const name of wb.SheetNames) {
    const rows = XLSX.utils.sheet_to_json(wb.Sheets[name], { defval: null });
    if (!best || rows.length > bestRows.length) { best = name; bestRows = rows; }
  }
  if (wb.SheetNames.length > 1)
    console.log(`  (workbook has ${wb.SheetNames.length} sheets — using largest: "${best}", ${bestRows.length} rows)`);
  return aggregateRows(bestRows, filePath);
}

export function aggregateRows(rows, sourceLabel = "") {
  // Column names carry leading spaces in the source file — normalize keys once.
  const clean = rows.map((r) => {
    const o = {};
    for (const k in r) o[norm(k)] = r[k];
    return o;
  });

  let paidMoney = 0, reversedMoney = 0;
  let paidClaims = 0, reversedClaims = 0;
  const byPharm = new Map();          // name -> net PlanGrossAmount
  let minKey = null, maxKey = null;   // process-date span (yyyymm)
  let group = "", carrier = "";

  // Slicer cube: facts keyed by (month, client group, state, pharmacy, brand,
  // therapeutic class, drug, paid-at-U&C flag), each holding paid$/reversed$/
  // paid claims/reversed claims. Dimension values are interned into arrays and
  // facts store indexes, keeping the JSON small (~9k rows per quarter).
  const dims = { months: [], groups: [], states: [], pharmacies: [], brands: [], classes: [], drugs: [] };
  const dimIdx = { months: new Map(), groups: new Map(), states: new Map(), pharmacies: new Map(), brands: new Map(), classes: new Map(), drugs: new Map() };
  const pharmMeta = []; // parallel to dims.pharmacies: {city, st, npi4, ll:[lat,lon]|null}
  // key defaults to the label; pharmacies pass name+NPI as key so distinct
  // locations sharing a name stay separate bars (matching the Power BI axis)
  const intern = (dim, label, key = label) => {
    let i = dimIdx[dim].get(key);
    if (i === undefined) { i = dims[dim].length; dims[dim].push(label); dimIdx[dim].set(key, i); }
    return i;
  };
  const factMap = new Map(); // "m|g|s|p|b" -> [paid$, rev$, paidN, revN]

  for (const r of clean) {
    const type = norm(r.ClaimType).toUpperCase();
    const gross = num(r.PlanGrossAmount);
    if (!group) group = norm(r.GroupName);
    if (!carrier) carrier = norm(r.CarrierCode);

    const pd = ymd(r.ProcessDate) || ymd(r.DOS);
    if (pd) {
      const k = pd.y * 100 + pd.m;
      if (minKey === null || k < minKey) minKey = k;
      if (maxKey === null || k > maxKey) maxKey = k;
    }

    if (type !== "P" && type !== "R") continue; // skip blanks / unknown types

    if (type === "P") { paidMoney += gross; paidClaims += 1; }
    else { reversedMoney += gross; reversedClaims += 1; }

    const pharm = norm(r.PharmacyName) || "—";
    const pharmKey = `${pharm}|${norm(r.NPI)}`;
    byPharm.set(pharmKey, (byPharm.get(pharmKey) || 0) + gross);

    const mi = intern("months", pd ? `${pd.y}-${String(pd.m).padStart(2, "0")}` : "—");
    const gi = intern("groups", titleize(norm(r.GroupName)) || "—");
    const si = intern("states", norm(r.PharmacyState).toUpperCase() || "—");
    const pi = intern("pharmacies", titleize(pharm), pharmKey);
    if (pi === pharmMeta.length) {
      const npi = norm(r.NPI);
      pharmMeta.push({
        city: titleize(norm(r.PharmacyCity)),
        st: norm(r.PharmacyState).toUpperCase(),
        npi4: npi.slice(-4),
        ll: zipLatLon(r.PharmacyZip),
      });
    }
    const bi = intern("brands", norm(r.BrandCode).toUpperCase() || "—");
    const ci = intern("classes", titleize(norm(r.TherapeuticClass).replace(/\*/g, "").trim()) || "—");
    const di = intern("drugs", norm(r.DrugName) || "—");
    const uc = num(r.CostBasis) === 4 ? 1 : 0; // NCPDP basis-of-cost 04 = Usual & Customary
    const fk = `${mi}|${gi}|${si}|${pi}|${bi}|${ci}|${di}|${uc}`;
    let f = factMap.get(fk);
    if (!f) { f = [mi, gi, si, pi, bi, ci, di, uc, 0, 0, 0, 0]; factMap.set(fk, f); }
    if (type === "P") { f[8] += gross; f[10] += 1; }
    else { f[9] += gross; f[11] += 1; } // reversal gross is negative; keep sign
  }

  const reversedMoneyAbs = Math.abs(reversedMoney);
  const collectedMoney = paidMoney - reversedMoneyAbs;
  const collectedClaims = paidClaims - reversedClaims;

  const pharmacies = [...byPharm.entries()]
    .map(([key, collected]) => ({ name: titleize(key.split("|")[0]), collected: Math.round(collected * 100) / 100 }))
    .sort((a, b) => b.collected - a.collected);

  // Period label + key from the process-date span.
  const startY = minKey ? Math.floor(minKey / 100) : null;
  const startM = minKey ? minKey % 100 : null;
  const endY = maxKey ? Math.floor(maxKey / 100) : null;
  const endM = maxKey ? maxKey % 100 : null;
  let periodLabel = "", periodKey = "";
  if (minKey && maxKey) {
    periodLabel = startY === endY
      ? `${MONTHS[startM]}–${MONTHS[endM]} ${endY}`
      : `${MONTHS[startM]} ${startY} – ${MONTHS[endM]} ${endY}`;
    const qStart = Math.floor((startM - 1) / 3) + 1;
    const qEnd = Math.floor((endM - 1) / 3) + 1;
    // one quarter -> "2026-Q2"; longer spans -> year key ("2025" or "2025-2026")
    if (startY === endY && qStart === qEnd) periodKey = `${endY}-Q${qEnd}`;
    else periodKey = startY === endY ? String(endY) : `${startY}-${endY}`;
  }

  const r2 = (n) => Math.round(n * 100) / 100;
  const r4 = (n) => Math.round(n * 10000) / 10000;

  return {
    periodKey,
    periodLabel,
    client: titleize(carrier || group) || "MyRxCard",
    sourceFile: sourceLabel.split(/[\\/]/).pop(),
    rowCount: clean.length,
    money: {
      paid: r2(paidMoney),
      reversed: r2(reversedMoneyAbs),
      collected: r2(collectedMoney),
      reversedPct: paidMoney ? r4(reversedMoneyAbs / paidMoney) : 0,
    },
    claims: {
      paid: paidClaims,
      reversed: reversedClaims,
      collected: collectedClaims,
      reversedPct: paidClaims ? r4(reversedClaims / paidClaims) : 0,
    },
    pharmacies,
    dims,
    pharmMeta,
    // [monthIdx, groupIdx, stateIdx, pharmacyIdx, brandIdx, classIdx, drugIdx,
    //  paidAtUC flag, paid$, reversed$ (negative), paidClaims, reversedClaims]
    facts: [...factMap.values()].map((f) => [f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], r2(f[8]), r2(f[9]), f[10], f[11]]),
  };
}
