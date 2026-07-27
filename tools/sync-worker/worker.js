// myrxcard-sync — Zoho CRM → Xano bridge for Avalon process aggregates.
//
// Zoho pushes AGGREGATE rows only (recomputed in Deluge when a record
// changes). This worker is the PHI firewall: strict field whitelist, type
// checks, and content heuristics — anything unexpected is rejected wholesale,
// never forwarded. Clean rows are upserted into Xano.
//
//   POST / { secret, rows: [ {bucket_key, process, month, ...metrics} ] }
//
// Secrets: SYNC_SECRET  shared with the Zoho Deluge function
//          XANO_ENDPOINT  full URL of the Xano upsert endpoint
//          XANO_API_KEY   optional bearer for that endpoint
// (After any `wrangler deploy`, re-run a `wrangler secret put` to re-bind.)

const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "content-type" };
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", ...CORS } });

// the ONLY fields allowed out: aggregate dimensions + numeric measures
const FIELDS = {
  bucket_key: { t: "string", max: 120 },   // e.g. "assist|1689773905|2026-07"
  process: { t: "string", max: 60 },       // Avalon process/program name
  pharmacy_name: { t: "string", max: 80 },
  pharmacy_npi: { t: "string", max: 10, re: /^\d{0,10}$/ },
  state: { t: "string", max: 2, re: /^[A-Za-z]{0,2}$/ },
  month: { t: "string", max: 7, re: /^\d{4}-\d{2}$/ },
  record_count: { t: "number" },
  open_count: { t: "number" },
  completed_count: { t: "number" },
  amount: { t: "number" },
  amount_secondary: { t: "number" },
};
const REQUIRED = ["bucket_key", "process", "month"];

// PHI tripwires for string values that slipped into allowed fields
const SUSPECT = [
  /\b\d{3}-\d{2}-\d{4}\b/,                  // SSN
  /\b\d{1,2}\/\d{1,2}\/\d{2,4}\b/,          // DOB-style date
  /@[a-z0-9.-]+\.[a-z]{2,}/i,               // email
  /\(\d{3}\)\s*\d{3}[- ]?\d{4}|\b\d{3}[-.]\d{3}[-.]\d{4}\b/, // phone
];

function validateRow(row) {
  if (typeof row !== "object" || row === null || Array.isArray(row)) return "row is not an object";
  for (const k of Object.keys(row)) if (!FIELDS[k]) return `unexpected field "${k}" — whitelist only`;
  for (const k of REQUIRED) if (!(k in row)) return `missing required field "${k}"`;
  for (const [k, v] of Object.entries(row)) {
    const spec = FIELDS[k];
    if (spec.t === "number") {
      if (typeof v !== "number" || !isFinite(v)) return `${k} must be a finite number`;
    } else {
      if (typeof v !== "string") return `${k} must be a string`;
      if (v.length > spec.max) return `${k} too long (${v.length} > ${spec.max})`;
      if (spec.re && !spec.re.test(v)) return `${k} has an invalid format`;
      for (const re of SUSPECT) if (re.test(v)) return `${k} looks like it contains PHI — rejected`;
    }
  }
  return null;
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
    if (req.method !== "POST") return json({ error: "POST only" }, 405);
    let body;
    try { body = await req.json(); } catch { return json({ error: "bad json" }, 400); }
    if (!env.SYNC_SECRET || body.secret !== env.SYNC_SECRET) return json({ error: "bad secret" }, 403);
    if (!env.XANO_ENDPOINT) return json({ error: "XANO_ENDPOINT not configured" }, 500);
    const rows = body.rows;
    if (!Array.isArray(rows) || !rows.length) return json({ error: "rows[] required" }, 400);
    if (rows.length > 500) return json({ error: "too many rows in one push (max 500)" }, 400);
    // all-or-nothing: one bad row rejects the whole batch, so a PHI leak
    // can't ride along with valid rows
    for (let i = 0; i < rows.length; i++) {
      const err = validateRow(rows[i]);
      if (err) return json({ error: `row ${i}: ${err}` }, 422);
    }
    // the key travels in the body — trivial to verify with a Xano Precondition
    const forward = { rows };
    if (env.XANO_API_KEY) forward.key = env.XANO_API_KEY;
    const r = await fetch(env.XANO_ENDPOINT, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(forward) });
    const out = await r.text();
    if (!r.ok) return json({ error: `Xano ${r.status}: ${out.slice(0, 300)}` }, 502);
    return json({ ok: true, upserted: rows.length });
  },
};
