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
  const ws = wb.Sheets[wb.SheetNames[0]];
  const rows = XLSX.utils.sheet_to_json(ws, { defval: null });
  return aggregateRows(rows, filePath);
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

    if (type === "P") { paidMoney += gross; paidClaims += 1; }
    else if (type === "R") { reversedMoney += gross; reversedClaims += 1; }
    else continue; // skip blanks / unknown types

    const pharm = norm(r.PharmacyName) || "—";
    byPharm.set(pharm, (byPharm.get(pharm) || 0) + gross);
  }

  const reversedMoneyAbs = Math.abs(reversedMoney);
  const collectedMoney = paidMoney - reversedMoneyAbs;
  const collectedClaims = paidClaims - reversedClaims;

  const pharmacies = [...byPharm.entries()]
    .map(([name, collected]) => ({ name: titleize(name), collected: Math.round(collected * 100) / 100 }))
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
    const q = Math.floor((endM - 1) / 3) + 1;
    periodKey = `${endY}-Q${q}`;
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
  };
}
