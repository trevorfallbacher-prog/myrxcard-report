// myrxcard-sync — Zoho CRM → Xano bridge for Avalon process aggregates.
//
// Zoho pushes AGGREGATE rows only (recomputed in Deluge when a record
// changes). This worker is the PHI firewall: strict field whitelist, type
// checks, and content heuristics — anything unexpected is rejected wholesale,
// never forwarded. Clean rows are upserted into Xano.
//
//   POST / { secret, rows: [ {bucket_key, client_name, month, ...metrics} ] }
//
// The upsert happens here, directly against Xano's Metadata API content
// endpoints (search by bucket_key → update or insert) — no Xano-side
// endpoint to build or expose.
//
// Vars:    XANO_CONTENT_URL  the table's meta content base (wrangler.toml)
// Secrets: SYNC_SECRET       shared with the Zoho Deluge function
//          XANO_META_TOKEN   Xano Metadata API token (expires — see README)
// (After any `wrangler deploy`, re-run a `wrangler secret put` to re-bind.)

const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "content-type" };
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", ...CORS } });

// the ONLY fields allowed out — one row per Avalon Assist case, identifier-
// free. Member fields (name, DOB, email, phone, government ID, relationship,
// dose/quantity free text, survey comments) are not in this list and any
// attempt to send them rejects the whole batch. Upsert key: case_key (the
// Zoho record id — a surrogate, so status changes overwrite in place).
const FIELDS = {
  case_key: { t: "string", max: 30, re: /^\d+$/ },      // Zoho record id
  assist_number: { t: "string", max: 20 },              // Case_Number autonumber
  client_name: { t: "string", max: 80 },
  tpa: { t: "string", max: 60 },
  group_number: { t: "string", max: 40 },
  source: { t: "string", max: 40 },                     // canonical channel
  status: { t: "string", max: 60 },
  closed_reason: { t: "string", max: 80 },
  medication_name: { t: "string", max: 80 },
  ndc: { t: "string", max: 11, re: /^\d{0,11}$/ },
  medication_type: { t: "string", max: 20 },            // Brand / Generic
  month: { t: "string", max: 7, re: /^\d{4}-\d{2}$/ },  // created month (bucketing)
  created_date: { t: "string", max: 10, re: /^\d{4}-\d{2}-\d{2}$/ },
  closed_date: { t: "string", max: 10, re: /^(\d{4}-\d{2}-\d{2})?$/ },
  awp: { t: "number" },
  avalon_fee: { t: "number" },
  aa_price: { t: "number" },
  aa_savings: { t: "number" },
  avalon_savings: { t: "number" },
  myrxcard_pricing: { t: "number" },
  medsdirect_pricing: { t: "number" },
  rxfree4me_pricing: { t: "number" },
  globalrx_pricing: { t: "number" },
  canada_pricing: { t: "number" },
  shipping_fees: { t: "number" },
  physician_fees: { t: "number" },
  other_fees: { t: "number" },
};
const REQUIRED = ["case_key", "client_name", "medication_name", "month"];

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
    if (!env.XANO_META_TOKEN || !env.XANO_CONTENT_URL) return json({ error: "Xano connection not configured" }, 500);
    const rows = body.rows;
    if (!Array.isArray(rows) || !rows.length) return json({ error: "rows[] required" }, 400);
    if (rows.length > 500) return json({ error: "too many rows in one push (max 500)" }, 400);
    // all-or-nothing: one bad row rejects the whole batch, so a PHI leak
    // can't ride along with valid rows
    for (let i = 0; i < rows.length; i++) {
      const err = validateRow(rows[i]);
      if (err) return json({ error: `row ${i}: ${err}` }, 422);
    }
    // upsert each row by case_key via the Metadata API
    const H = { "content-type": "application/json", authorization: `Bearer ${env.XANO_META_TOKEN}` };
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      const sr = await fetch(`${env.XANO_CONTENT_URL}/search`, { method: "POST", headers: H,
        body: JSON.stringify({ page: 1, per_page: 1, search: [{ field: "case_key", operator: "=", value: row.case_key }] }) });
      const sout = await sr.json().catch(() => ({}));
      if (!sr.ok) return json({ error: `Xano search ${sr.status} on row ${i}: ${JSON.stringify(sout).slice(0, 200)}` }, 502);
      const existing = (sout.items || [])[0];
      const wr = existing
        ? await fetch(`${env.XANO_CONTENT_URL}/${existing.id}`, { method: "PUT", headers: H, body: JSON.stringify(row) })
        : await fetch(env.XANO_CONTENT_URL, { method: "POST", headers: H, body: JSON.stringify(row) });
      if (!wr.ok) return json({ error: `Xano write ${wr.status} on row ${i}: ${(await wr.text()).slice(0, 200)}` }, 502);
    }
    return json({ ok: true, upserted: rows.length });
  },
};
