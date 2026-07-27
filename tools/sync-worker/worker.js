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

// the ONLY fields allowed out — mirrors the Avalon Assist report columns
// (dims from the report's own vocabulary; per-case fields like dosage,
// quantity, relationship-to-insured, and any dates stay in Zoho).
// Bucket grain: client × source × medication × month. Status is a set of
// counters inside the bucket, not part of the key — cases move between
// statuses, and counters can't strand a stale row the way a keyed status can.
const FIELDS = {
  bucket_key: { t: "string", max: 160 },   // client|source|medication|month
  client_name: { t: "string", max: 80 },
  tpa: { t: "string", max: 60 },
  group_number: { t: "string", max: 40 },
  source: { t: "string", max: 40 },        // Canada Outreach / MedsDirect / NASH / …
  medication_name: { t: "string", max: 80 },
  ndc: { t: "string", max: 11, re: /^\d{0,11}$/ },
  medication_type: { t: "string", max: 20 },  // Brand / Generic
  month: { t: "string", max: 7, re: /^\d{4}-\d{2}$/ },
  cases: { t: "number" },
  open_cases: { t: "number" },              // "Open…" + "Targeted for Switch"
  completed_cases: { t: "number" },         // "Completed"
  closed_no_fill_cases: { t: "number" },    // "Closed, No Fill"
  awp_total: { t: "number" },
  avalon_fee_total: { t: "number" },
  aa_price_total: { t: "number" },
  aa_savings_total: { t: "number" },
  avalon_savings_total: { t: "number" },
  myrxcard_total: { t: "number" },
  medsdirect_total: { t: "number" },
  rxfree4me_total: { t: "number" },
  globalrx_total: { t: "number" },
  canada_total: { t: "number" },
};
const REQUIRED = ["bucket_key", "client_name", "medication_name", "month"];

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
