// myrxcard-sync — Zoho CRM → Xano bridge for Avalon process aggregates.
//
// Zoho pushes AGGREGATE rows only (recomputed in Deluge when a record
// changes). This worker is the PHI firewall: strict field whitelist, type
// checks, and content heuristics — anything unexpected is rejected wholesale,
// never forwarded. Clean rows are upserted into Xano.
//
//   POST / { secret, rows: [ {bucket_key, client_name, month, ...metrics} ] }
//   POST / { report_pw }   → read route for reports.avalonsaves.com: returns
//                            every case row (already identifier-free)
//
// The upsert happens here, directly against Xano's Metadata API content
// endpoints (search by bucket_key → update or insert) — no Xano-side
// endpoint to build or expose.
//
// Vars:    XANO_CONTENT_URL  the table's meta content base (wrangler.toml)
// Secrets: SYNC_SECRET       shared with the Zoho Deluge function
//          REPORT_PW         unlocks the read route (shared with the report UI)
//          XANO_META_TOKEN   Xano Metadata API token (expires — see README)
// (After any `wrangler deploy`, re-run a `wrangler secret put` to re-bind.)

const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "content-type" };
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", ...CORS } });

// ---- client microsites (reports.avalonsaves.com/<slug>/) ----
// Secret CLIENT_PWS = JSON {"<slug>": {"pw": "...", "label": "..."}}.
// A client password returns ONLY that client's rows, server-side white-labeled:
// no fee/supplier pricing, sourcing names collapsed to Domestic/International,
// member tokens re-HMACed per client so tokens can't be linked across sites.
const INTL_SOURCES = new Set(["Canada Outreach", "GlobalRx", "MedsDirect", "NASH"]);
const DOMESTIC_SOURCES = new Set(["Direct", "RxFree4me"]);
// fields a client browser is allowed to receive — everything else is dropped
const CLIENT_FIELDS = ["case_key","assist_number","group_number","source","status","closed_reason",
  "medication_name","ndc","medication_type","month","created_date","closed_date",
  "awp","aa_price","aa_savings","avalon_savings","member_ref","member_age"];
// ---- report-password verification for the search feed ----
// The report pages are gated by AES-GCM files (PBKDF2-SHA256, 310k iterations)
// published on the site itself. A password is valid iff it decrypts that file:
// config.enc.json for the root dashboard, /<slug>/utilization.enc.json for a
// partner page. Verified passwords are cached per isolate so the PBKDF2 cost
// is paid once per session, not per 5-minute refresh.
// ---- PBKDF2-HMAC-SHA256 in plain JS ----
// Workers' WebCrypto refuses PBKDF2 above 100,000 iterations
// ("Pbkdf2 failed: iteration counts above 100000 are not supported") and the
// report files use 310,000, so the key must be derived here. ~190 ms per
// check; verified passwords are cached per isolate (see verifyReportPassword).
// Output matches crypto.subtle.deriveBits bit-for-bit (checked in Node).
const K = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
const W = new Uint32Array(64);
function compress(h, blk, off) { // blk: Uint8Array, 64 bytes at off
  for (let i=0;i<16;i++) W[i]=(blk[off+i*4]<<24)|(blk[off+i*4+1]<<16)|(blk[off+i*4+2]<<8)|blk[off+i*4+3];
  for (let i=16;i<64;i++){const a=W[i-15],b=W[i-2];W[i]=(W[i-16]+(((a>>>7)|(a<<25))^((a>>>18)|(a<<14))^(a>>>3))+W[i-7]+(((b>>>17)|(b<<15))^((b>>>19)|(b<<13))^(b>>>10)))|0;}
  let a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
  for (let i=0;i<64;i++){const t1=(hh+(((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7)))+((e&f)^(~e&g))+K[i]+W[i])|0;const t2=((((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10)))+((a&b)^(a&c)^(b&c)))|0;hh=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;}
  h[0]=(h[0]+a)|0;h[1]=(h[1]+b)|0;h[2]=(h[2]+c)|0;h[3]=(h[3]+d)|0;h[4]=(h[4]+e)|0;h[5]=(h[5]+f)|0;h[6]=(h[6]+g)|0;h[7]=(h[7]+hh)|0;
}
const H0 = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
function sha256(msg) { // Uint8Array -> Uint8Array(32)
  const h = new Uint32Array(H0); const len = msg.length; const padLen = ((len + 9 + 63) >> 6) << 6;
  const buf = new Uint8Array(padLen); buf.set(msg); buf[len] = 0x80;
  const bits = len * 8; buf[padLen-4]=(bits>>>24)&255; buf[padLen-3]=(bits>>>16)&255; buf[padLen-2]=(bits>>>8)&255; buf[padLen-1]=bits&255;
  for (let off=0; off<padLen; off+=64) compress(h, buf, off);
  const out = new Uint8Array(32); for (let i=0;i<8;i++){out[i*4]=h[i]>>>24;out[i*4+1]=(h[i]>>>16)&255;out[i*4+2]=(h[i]>>>8)&255;out[i*4+3]=h[i]&255;} return out;
}
// HMAC with precomputed inner/outer states (the PBKDF2 hot loop only hashes one 32-byte block each)
function hmacState(key) {
  if (key.length > 64) key = sha256(key);
  const ipad = new Uint8Array(64), opad = new Uint8Array(64);
  for (let i=0;i<64;i++){ const k = i<key.length ? key[i] : 0; ipad[i]=k^0x36; opad[i]=k^0x5c; }
  const hi = new Uint32Array(H0), ho = new Uint32Array(H0); compress(hi, ipad, 0); compress(ho, opad, 0);
  return { hi, ho };
}
const blk32 = new Uint8Array(64); blk32[32]=0x80; blk32[62]=0x03; // (64+32)*8 = 768 = 0x0300
function hmac32(st, data32) { // data exactly 32 bytes -> 32 bytes
  const h = new Uint32Array(st.hi); blk32.set(data32, 0); compress(h, blk32, 0);
  const inner = new Uint8Array(32); for (let i=0;i<8;i++){inner[i*4]=h[i]>>>24;inner[i*4+1]=(h[i]>>>16)&255;inner[i*4+2]=(h[i]>>>8)&255;inner[i*4+3]=h[i]&255;}
  const h2 = new Uint32Array(st.ho); blk32.set(inner, 0); compress(h2, blk32, 0);
  const out = new Uint8Array(32); for (let i=0;i<8;i++){out[i*4]=h2[i]>>>24;out[i*4+1]=(h2[i]>>>16)&255;out[i*4+2]=(h2[i]>>>8)&255;out[i*4+3]=h2[i]&255;} return out;
}
function hmacAny(st, data) { // general-length data (first PBKDF2 block: salt||INT(1))
  const inner = new Uint32Array(st.hi); const len=data.length, total=64+len, padLen=((total+9+63)>>6)<<6;
  const buf=new Uint8Array(padLen-64); buf.set(data); buf[len]=0x80; const bits=total*8; buf[buf.length-4]=(bits>>>24)&255; buf[buf.length-3]=(bits>>>16)&255; buf[buf.length-2]=(bits>>>8)&255; buf[buf.length-1]=bits&255;
  for (let off=0; off<buf.length; off+=64) compress(inner, buf, off);
  const ib = new Uint8Array(32); for (let i=0;i<8;i++){ib[i*4]=inner[i]>>>24;ib[i*4+1]=(inner[i]>>>16)&255;ib[i*4+2]=(inner[i]>>>8)&255;ib[i*4+3]=inner[i]&255;}
  const h2 = new Uint32Array(st.ho); blk32.set(ib,0); compress(h2, blk32, 0);
  const out = new Uint8Array(32); for (let i=0;i<8;i++){out[i*4]=h2[i]>>>24;out[i*4+1]=(h2[i]>>>16)&255;out[i*4+2]=(h2[i]>>>8)&255;out[i*4+3]=h2[i]&255;} return out;
}
function pbkdf2Sha256_32(password, salt, iterations) { // -> Uint8Array(32) (one block)
  const st = hmacState(password); const s1 = new Uint8Array(salt.length+4); s1.set(salt); s1[salt.length+3]=1;
  let u = hmacAny(st, s1); const t = new Uint8Array(u);
  for (let i=1;i<iterations;i++){ u = hmac32(st, u); for (let j=0;j<32;j++) t[j]^=u[j]; }
  return t;
}
const FEED_SITE = "https://reports.myrxcard.com";
const verifiedFeedPw = new Map(); // `${slug}|${pw}` -> expiry ms
let feedTableId = null; // search_events table id, resolved by name once per isolate
async function verifyReportPassword(slug, pw) {
  if (!pw || pw.length > 200) return false;
  const key = slug + "|" + pw, now = Date.now();
  if ((verifiedFeedPw.get(key) || 0) > now) return true;
  const url = slug ? `${FEED_SITE}/${slug}/utilization.enc.json` : `${FEED_SITE}/config.enc.json`;
  let blob;
  try {
    const r = await fetch(url, { cf: { cacheTtl: 300, cacheEverything: true } });
    if (!r.ok) { console.log(`feed: ${url} -> HTTP ${r.status}`); return false; }
    blob = await r.json();
  } catch (e) { console.log(`feed: ${url} fetch failed: ${e && e.message}`); return false; }
  if (!blob || !blob.salt || !blob.iv || !blob.data) { console.log(`feed: ${url} -> not an encrypted blob`); return false; }
  try {
    const b64 = (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
    const raw = pbkdf2Sha256_32(new TextEncoder().encode(pw), b64(blob.salt), 310000);
    const aesKey = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(blob.iv) }, aesKey, b64(blob.data));
  } catch (e) { console.log(`feed: verify failed: ${e && e.name}: ${e && e.message}`); return false; }
  verifiedFeedPw.set(key, now + 15 * 60 * 1000);
  return true;
}
async function hmacHex16(secret, message) {
  if (!secret || !message) return "";
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].slice(0, 8).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function clientOwns(row, slug) {
  return (((row.tpa || "") + " " + (row.client_name || "")).toLowerCase().includes(slug));
}
function whitelabel(row, label) {
  const out = {};
  for (const k of CLIENT_FIELDS) if (row[k] !== undefined) out[k] = row[k];
  out.client_name = label;
  const s = row.source || "";
  out.source = INTL_SOURCES.has(s) ? "International" : DOMESTIC_SOURCES.has(s) ? "Domestic" : "Other";
  return out;
}

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
  member_ref: { t: "string", max: 30, re: /^\d*$/ },    // Zoho member record id — tokenized (HMAC) before storage, never persisted raw
  member_age: { t: "number", min: 0, max: 90 },         // whole years, capped at 90 (HIPAA safe harbor) — computed in Deluge from DOB; the DOB itself never leaves Zoho
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
  // satisfaction survey (QBR NPS) — matches the 3 columns added to Xano table 12
  // on 2026-08-24. Scores are range-checked; nps 0-10, experience 1-5.
  nps_recommend: { t: "number", min: 0, max: 10 },
  experience_score: { t: "number", min: 1, max: 5 },
  survey_completed: { t: "string", max: 3, re: /^(yes|no)?$/ },
  // response-time milestones (QBR Response tile). Five map to existing Zoho
  // date fields; first_contact_date / order_date light up once those fields
  // are added to the Assist layout. Date-only, same format as closed_date.
  request_date: { t: "string", max: 10, re: /^(\d{4}-\d{2}-\d{2})?$/ },
  rx_script_date: { t: "string", max: 10, re: /^(\d{4}-\d{2}-\d{2})?$/ },
  awp_pricing_date: { t: "string", max: 10, re: /^(\d{4}-\d{2}-\d{2})?$/ },
  initial_fill_date: { t: "string", max: 10, re: /^(\d{4}-\d{2}-\d{2})?$/ },
  refill_date: { t: "string", max: 10, re: /^(\d{4}-\d{2}-\d{2})?$/ },
  first_contact_date: { t: "string", max: 10, re: /^(\d{4}-\d{2}-\d{2})?$/ },
  order_date: { t: "string", max: 10, re: /^(\d{4}-\d{2}-\d{2})?$/ },
  // final pass 2026-08-24: survey detail picklists (short answers), claim date,
  // fill-conversion flags, and the ONE free-text exception — survey comments,
  // which are scrubbed (PHI patterns redacted) rather than batch-rejected.
  would_use_again: { t: "string", max: 40 },
  rx_accurate: { t: "string", max: 40 },
  advocate_clear: { t: "string", max: 40 },
  member_shipping_issue: { t: "string", max: 40 },
  used_home_delivery: { t: "string", max: 40 },
  claim_date: { t: "string", max: 10, re: /^(\d{4}-\d{2}-\d{2})?$/ },
  day_supply_eligible: { t: "string", max: 3, re: /^(yes|no)?$/ },
  converted_90d: { t: "string", max: 3, re: /^(yes|no)?$/ },
  survey_comments: { t: "string", max: 2000, scrub: true },
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
      if (spec.min !== undefined && (v < spec.min || v > spec.max)) return `${k} out of range`;
    } else {
      if (typeof v !== "string") return `${k} must be a string`;
      if (v.length > spec.max) return `${k} too long (${v.length} > ${spec.max})`;
      if (spec.re && !spec.re.test(v)) return `${k} has an invalid format`;
      if (spec.scrub) {
        // free-text exception: redact PHI-shaped content instead of rejecting the batch
        let s = v;
        for (const re of SUSPECT) s = s.replace(new RegExp(re.source, "gi"), "[redacted]");
        row[k] = s;
      } else {
        for (const re of SUSPECT) if (re.test(v)) return `${k} looks like it contains PHI — rejected`;
      }
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
    if (!env.XANO_META_TOKEN || !env.XANO_CONTENT_URL) return json({ error: "Xano connection not configured" }, 500);
    // Live website-search feed for reports.myrxcard.com (root dashboard and the
    // /<slug>/ partner pages). Replaces the public Xano GET on search_events,
    // which handed the entire search log to anyone who requested the URL.
    // No new secrets: the caller proves it holds a report password by that
    // password decrypting the site's own published encrypted file — exactly
    // the check the page itself passes at its gate. Any valid password gets
    // the full feed (the browser scopes it to the client's microsites, as it
    // did with the public endpoint).
    if (body.feed_pw !== undefined) {
      const slug = String(body.site || "").toLowerCase();
      if (!/^[a-z0-9-]{0,40}$/.test(slug)) return json({ error: "bad site" }, 400);
      if (!(await verifyReportPassword(slug, String(body.feed_pw || "")))) return json({ error: "bad password" }, 403);
      // Find the search_events table by NAME through the Metadata API. Never
      // by id: XANO_EVENTS_URL pointed at the Avalon process-events table, and
      // rows from the wrong table rendered on the dashboard as blank searches.
      const metaBase = String(env.XANO_CONTENT_URL || "").replace(/\/table\/\d+\/content\/?$/, "");
      if (!/\/api:meta\/workspace\/\d+$/.test(metaBase)) return json({ error: "events feed not configured" }, 500);
      const H3 = { "content-type": "application/json", authorization: `Bearer ${env.XANO_META_TOKEN}` };
      if (!feedTableId) {
        const tr = await fetch(`${metaBase}/table?page=1&per_page=100`, { headers: H3 });
        if (!tr.ok) return json({ error: `Xano tables ${tr.status}` }, 502);
        const tb = await tr.json();
        const list = Array.isArray(tb) ? tb : (tb.items || []);
        const hit = list.find((t) => t && t.name === "search_events");
        if (!hit) { console.log("feed: tables seen: " + list.map((t) => t && `${t.id}:${t.name}`).join(", ")); return json({ error: "search_events table not found" }, 502); }
        feedTableId = hit.id;
      }
      let events = [], page = 1;
      for (;;) {
        const r = await fetch(`${metaBase}/table/${feedTableId}/content/search`, { method: "POST", headers: H3,
          body: JSON.stringify({ page, per_page: 500, search: [] }) });
        if (!r.ok) return json({ error: `Xano read ${r.status}` }, 502);
        const it = (await r.json()).items || [];
        events = events.concat(it);
        if (it.length < 500 || page > 400) break;
        page++;
      }
      // belt and braces: search_events rows carry these columns; anything else
      // is the wrong table and must not reach the dashboard
      if (events.length && !("drug_name" in events[0] && "session_id" in events[0])) {
        console.log("feed: unexpected row shape: " + Object.keys(events[0]).slice(0, 12).join(","));
        feedTableId = null;
        return json({ error: "unexpected events shape" }, 502);
      }
      return json({ ok: true, generatedAt: new Date().toISOString(), events });
    }
    // read route for the gated reports. The master password returns everything;
    // a client password (CLIENT_PWS secret) returns only that client's rows,
    // white-labeled server-side — the browser never sees other clients, fees,
    // supplier pricing, or real sourcing names.
    if (body.report_pw !== undefined) {
      let clientMeta = null;
      if (!env.REPORT_PW || body.report_pw !== env.REPORT_PW) {
        let map = {};
        try { map = JSON.parse(env.CLIENT_PWS || "{}"); } catch {}
        for (const [slug, c] of Object.entries(map)) {
          if (c && c.pw && body.report_pw === c.pw) { clientMeta = { slug, label: c.label || slug }; break; }
        }
        if (!clientMeta) return json({ error: "bad password" }, 403);
      }
      // AAPS supplier pricing snapshot for the internal /nash/ dashboard.
      // MASTER password only — supplier prices never ship to client views.
      if (body.dataset === "pricing") {
        if (clientMeta) return json({ error: "bad password" }, 403);
        if (!env.AAPS_DATA) return json({ error: "pricing store not bound" }, 500);
        const txt = await env.AAPS_DATA.get("pricing_data.json");
        if (!txt) return json({ error: "no pricing snapshot loaded" }, 404);
        return new Response(txt, { headers: { "content-type": "application/json", ...CORS } });
      }
      const H2 = { "content-type": "application/json", authorization: `Bearer ${env.XANO_META_TOKEN}` };
      let cases = [], page = 1;
      for (;;) {
        const r = await fetch(`${env.XANO_CONTENT_URL}/search`, { method: "POST", headers: H2,
          body: JSON.stringify({ page, per_page: 250, search: [] }) });
        if (!r.ok) return json({ error: `Xano read ${r.status}` }, 502);
        const it = (await r.json()).items || [];
        cases = cases.concat(it);
        if (it.length < 250) break;
        page++;
      }
      const clean = cases.map(({ id, created_at, ...rest }) => rest);
      if (clientMeta) {
        const out = [];
        for (const r of clean) {
          if (!clientOwns(r, clientMeta.slug)) continue;
          const w = whitelabel(r, clientMeta.label);
          if (w.member_ref) w.member_ref = await hmacHex16(env.MEMBER_SALT, clientMeta.slug + "|" + w.member_ref);
          out.push(w);
        }
        return json({ ok: true, generatedAt: new Date().toISOString(), client: clientMeta, cases: out });
      }
      // master view also carries per-client account profiles (KV, pushed from
      // the Accounts Deluge function): covered lives, AA-client flag, status
      let profiles = {};
      if (env.AAPS_DATA) { try { profiles = JSON.parse((await env.AAPS_DATA.get("account_profiles")) || "{}"); } catch {} }
      const coveredLives = {};
      for (const [n, p] of Object.entries(profiles)) if (Number.isInteger(p.covered_lives)) coveredLives[n] = p.covered_lives;
      return json({ ok: true, generatedAt: new Date().toISOString(), cases: clean, covered_lives: coveredLives, account_profiles: profiles });
    }
    if (!env.SYNC_SECRET || body.secret !== env.SYNC_SECRET) return json({ error: "bad secret" }, 403);
    // account-profile push (Accounts Deluge function):
    //   {secret, accounts:{"Client":{covered_lives:300, aa_client:"yes", status:"Active"}}}
    // Deliberately tiny: three whitelisted keys, nothing else about the account.
    if (body.accounts !== undefined) {
      const ac = body.accounts;
      if (typeof ac !== "object" || ac === null || Array.isArray(ac)) return json({ error: "accounts must be an object" }, 400);
      const entries = Object.entries(ac);
      if (!entries.length || entries.length > 200) return json({ error: "accounts needs 1-200 entries" }, 400);
      const cleanAc = {};
      for (const [name, p] of entries) {
        if (typeof name !== "string" || !name.trim() || name.length > 80) return json({ error: "bad account name" }, 422);
        for (const re of SUSPECT) if (re.test(name)) return json({ error: "account name looks like PHI — rejected" }, 422);
        if (typeof p !== "object" || p === null || Array.isArray(p)) return json({ error: "account profile must be an object" }, 400);
        const prof = {};
        for (const [k, v] of Object.entries(p)) {
          if (k === "covered_lives") {
            const n = Number(v);
            if (!Number.isInteger(n) || n < 0 || n > 10000000) return json({ error: `covered_lives for "${name.slice(0, 40)}" must be a whole number` }, 422);
            prof.covered_lives = n;
          } else if (k === "aa_client") {
            if (v !== "yes" && v !== "no" && v !== "") return json({ error: "aa_client must be yes/no" }, 422);
            prof.aa_client = v;
          } else if (k === "status") {
            if (typeof v !== "string" || v.length > 60) return json({ error: "bad status" }, 422);
            for (const re of SUSPECT) if (re.test(v)) return json({ error: "status looks like PHI — rejected" }, 422);
            prof.status = v;
          } else return json({ error: `unexpected account field "${k}" — whitelist only` }, 422);
        }
        cleanAc[name.trim()] = prof;
      }
      if (!env.AAPS_DATA) return json({ error: "KV not bound" }, 500);
      let cur = {};
      try { cur = JSON.parse((await env.AAPS_DATA.get("account_profiles")) || "{}"); } catch {}
      for (const [name, prof] of Object.entries(cleanAc)) cur[name] = { ...(cur[name] || {}), ...prof };
      await env.AAPS_DATA.put("account_profiles", JSON.stringify(cur));
      return json({ ok: true, account_profiles: cur });
    }
    const rows = body.rows;
    if (!Array.isArray(rows) || !rows.length) return json({ error: "rows[] required" }, 400);
    // each row costs up to 4 Xano calls (search + write + up to 2 events);
    // 12 keeps a full batch inside Cloudflare's per-request subrequest budget
    if (rows.length > 12) return json({ error: "too many rows in one push (max 12)" }, 400);
    // all-or-nothing: one bad row rejects the whole batch, so a PHI leak
    // can't ride along with valid rows
    for (let i = 0; i < rows.length; i++) {
      const err = validateRow(rows[i]);
      if (err) return json({ error: `row ${i}: ${err}` }, 422);
    }
    // upsert each row by case_key via the Metadata API, and append timeline
    // events for what changed (compared against the row's previous state)
    const H = { "content-type": "application/json", authorization: `Bearer ${env.XANO_META_TOKEN}` };
    const now = new Date().toISOString();
    // pseudonymize member linkage: same member → same opaque token; the raw
    // Zoho id is used only in-memory and the salt exists only as a secret here
    const tokenize = async (raw) => {
      if (!raw || !env.MEMBER_SALT) return "";
      const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.MEMBER_SALT), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(raw));
      return [...new Uint8Array(sig)].slice(0, 8).map((b) => b.toString(16).padStart(2, "0")).join("");
    };
    for (const row of rows) if (row.member_ref) row.member_ref = await tokenize(row.member_ref);
    // case_key arrives as a 19-digit Zoho id; prefix it so Xano's "=" search
    // treats it as text, not a number (big-int coercion made distinct ids
    // collide, collapsing every upsert onto one row).
    for (const row of rows) row.case_key = "c" + row.case_key;
    let events = 0;
    const logEvent = async (row, type, field, oldV, newV) => {
      if (!env.XANO_EVENTS_URL) return;
      events++;
      await fetch(env.XANO_EVENTS_URL, { method: "POST", headers: H, body: JSON.stringify({
        case_key: row.case_key, assist_number: row.assist_number || "", client_name: row.client_name,
        medication_name: row.medication_name, source: row.source || "", member_ref: row.member_ref || "",
        event_type: type, field: field || "", old_value: String(oldV ?? ""), new_value: String(newV ?? ""),
        occurred_at: now,
      }) }).catch(() => {}); // the case row is the source of truth; a lost event never fails the sync
    };
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      // Xano meta content search: [{col: value}] does an exact match; the
      // {field,operator,value} form is silently ignored and returns all rows
      const sr = await fetch(`${env.XANO_CONTENT_URL}/search`, { method: "POST", headers: H,
        body: JSON.stringify({ page: 1, per_page: 1, search: [{ case_key: row.case_key }] }) });
      const sout = await sr.json().catch(() => ({}));
      if (!sr.ok) return json({ error: `Xano search ${sr.status} on row ${i}: ${JSON.stringify(sout).slice(0, 200)}` }, 502);
      const existing = (sout.items || [])[0];
      const wr = existing
        ? await fetch(`${env.XANO_CONTENT_URL}/${existing.id}`, { method: "PUT", headers: H, body: JSON.stringify(row) })
        : await fetch(env.XANO_CONTENT_URL, { method: "POST", headers: H, body: JSON.stringify(row) });
      if (!wr.ok) return json({ error: `Xano write ${wr.status} on row ${i}: ${(await wr.text()).slice(0, 200)}` }, 502);
      if (!existing) {
        await logEvent(row, "created", "status", "", row.status || "");
      } else {
        // status change gets its own event (closed reason rides along)
        const oldStatus = existing.status || "", newStatus = row.status || "";
        if (oldStatus !== newStatus) {
          const reason = (row.closed_reason || "") && newStatus.startsWith("Closed") ? ` — ${row.closed_reason}` : "";
          await logEvent(row, "status_change", "status", oldStatus, newStatus + reason);
        }
        // everything else changed rolls into one compact event
        const changed = [];
        for (const k of Object.keys(FIELDS)) {
          if (k === "case_key" || k === "status") continue;
          const oldV = existing[k], newV = row[k];
          if (newV === undefined) continue; // field not sent — not a change claim
          const same = FIELDS[k].t === "number"
            ? Math.abs((Number(oldV) || 0) - (Number(newV) || 0)) < 0.005
            : String(oldV ?? "") === String(newV ?? "");
          if (!same) changed.push(k);
        }
        if (changed.length) await logEvent(row, "updated", changed.join(","), "", "");
      }
    }
    return json({ ok: true, upserted: rows.length, events });
  },
};
