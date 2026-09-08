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
//   POST / { feed_pw, site } → live website-search feed for reports.myrxcard.com
//
// reports.myrxcard.com admin (live partner brands + sealed password vault):
//   POST / { brand_get: "<slug>" }                  PUBLIC — {ok, found, doc}
//   POST / { admin_pw, action: "ping" }             MASTER — {ok, kv}
//   POST / { admin_pw, action: "brands.list" }      MASTER — {ok, clients:[BrandDoc]}
//   POST / { admin_pw, action: "brand.put", slug, name, brand: Brand|null }
//   POST / { admin_pw, action: "pws.get" }          MASTER — {ok, enc, updatedAt}
//   POST / { admin_pw, action: "pws.put", enc: {salt, iv, data} }
//   admin_pw is the root dashboard's master password, proven by decrypting
//   /config.enc.json (verifyMaster). KV keys (namespace shared with the
//   avalon-aaps project, so every key is prefixed "myrx:"):
//     myrx:brand:<slug> → BrandDoc {v, slug, name, type, demo, brand|null, updatedAt, updatedFrom}
//     myrx:pws          → {v, updatedAt, enc} — the partner-password vault, encrypted
//                          client-side with the master password; the worker
//                          only ever stores and returns ciphertext.
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
//
// AUTH SURFACE: REPORT_PW is the same value as the reports.myrxcard.com master
// password, so report_pw, feed_pw with site "" and admin_pw all prove the
// master. Every one of them goes through checkPassword(): one per-network
// failure counter (in-memory, plus the ADMIN_RL rate-limit binding when bound)
// checked before any PBKDF2, constant-time compares for the secret-backed
// routes, and never a password value in a log line.
//
// Brand schema validation lives in ../brand-validate.mjs (shared with
// build-clients.mjs and the tests); wrangler bundles the import on deploy.

import { validateBrand, validateName, isPlainObject, BRAND_DOC_MAX } from "../brand-validate.mjs";

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
  // Partner sites: verify against the tiny /<slug>/gate.enc.json (a few bytes
  // sealed with the same password by build-clients.mjs) — decrypting the
  // multi-MB utilization.enc.json just to check a password cost ~1.1 s CPU on
  // the biggest site and tripped the Worker limit on cold starts. Falls back to
  // the utilization file for sites built before gate files existed.
  const urls = slug ? [`${FEED_SITE}/${slug}/gate.enc.json`, `${FEED_SITE}/${slug}/utilization.enc.json`] : [`${FEED_SITE}/config.enc.json`];
  let blob = null, url = urls[0];
  for (url of urls) {
    try {
      const r = await fetch(url, { cf: { cacheTtl: 300, cacheEverything: true } });
      if (r.status === 404 && urls.length > 1 && url !== urls[urls.length - 1]) continue;
      if (!r.ok) { console.log(`feed: ${url} -> HTTP ${r.status}`); return false; }
      blob = await r.json(); break;
    } catch (e) { console.log(`feed: ${url} fetch failed: ${e && e.message}`); return false; }
  }
  if (!blob || !blob.salt || !blob.iv || !blob.data) { console.log(`feed: ${url} -> not an encrypted blob`); return false; }
  try {
    // decode into a preallocated buffer: Uint8Array.from(str, fn) materialises a
    // multi-million-element iterator for the big files and spikes memory
    const b64 = (str) => { const bin = atob(str), out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; };
    const raw = pbkdf2Sha256_32(new TextEncoder().encode(pw), b64(blob.salt), 310000);
    const aesKey = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(blob.iv) }, aesKey, b64(blob.data));
  } catch (e) { console.log(`feed: verify failed: ${e && e.name}: ${e && e.message}`); return false; }
  verifiedFeedPw.set(key, now + 15 * 60 * 1000);
  return true;
}
// ---- reports.myrxcard.com admin auth ----
// The master password is the one that decrypts the ROOT config.enc.json; the
// slug is hard-coded to "" so a partner password (which decrypts its own
// /<slug>/utilization.enc.json) can never pass as master. The 15-minute
// success cache in verifyReportPassword applies here too.
async function verifyMaster(pw) { return verifyReportPassword("", pw); }
// ---- brute-force lockout, shared by every password-proving route ----
// Checked BEFORE the ~190 ms PBKDF2 (or the secret compare): 5 failures within
// 10 minutes lock the caller out for 10 minutes; a success clears the counter.
// Keyed by NETWORK + scope, not bare IP: an IPv6 caller is collapsed to its
// /64 (a single subscriber's allocation), so address rotation inside it buys
// nothing. Scope "master" is shared by admin_pw, feed_pw with site "" and
// report_pw — the three routes that prove the master; partner-page feed
// guesses count under "site:<slug>". Per isolate; the ADMIN_RL binding (see
// wrangler.toml) adds a limit that survives isolate churn.
const authFails = new Map(); // netKey -> { n, first, until } (ms)
const LOCK_MAX = 5, LOCK_WINDOW_MS = 10 * 60 * 1000, LOCK_FOR_MS = 10 * 60 * 1000, LOCK_MAP_MAX = 2000;
function ipv6Prefix64(ip) { // "2001:db8::1" -> "2001:0db8:0000:0000::/64"
  const [head, tail = ""] = ip.split("::");
  const h = head ? head.split(":") : [], t = tail ? tail.split(":") : [];
  const groups = ip.includes("::") ? [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill("0"), ...t] : h;
  return groups.slice(0, 4).map((g) => g.toLowerCase().padStart(4, "0")).join(":") + "::/64";
}
function netKey(req, scope) {
  const ip = (req.headers.get("cf-connecting-ip") || "unknown").trim();
  return (ip.includes(":") ? ipv6Prefix64(ip) : ip) + "|" + scope;
}
function lockoutSeconds(key) { // > 0 = locked, seconds remaining
  const e = authFails.get(key);
  if (!e) return 0;
  const now = Date.now();
  if (e.until > now) return Math.ceil((e.until - now) / 1000);
  if (e.until || now - e.first > LOCK_WINDOW_MS) authFails.delete(key); // lock expired / window rolled over
  return 0;
}
function lockoutFail(key) {
  const now = Date.now();
  let e = authFails.get(key);
  if (!e || now - e.first > LOCK_WINDOW_MS) e = { n: 0, first: now, until: 0 };
  e.n++;
  if (e.n >= LOCK_MAX) e.until = now + LOCK_FOR_MS;
  authFails.set(key, e);
  if (authFails.size > LOCK_MAP_MAX) lockoutEvict(now);
}
function lockoutReset(key) { authFails.delete(key); }
// Memory bound WITHOUT clear(): expired entries go first, then the oldest
// unlocked ones (Map keeps insertion order). An active lock is only dropped
// under a pathological pile-up of live locks, never by a flood of new keys.
function lockoutEvict(now) {
  for (const [k, e] of authFails) if (e.until ? e.until < now : now - e.first > LOCK_WINDOW_MS) authFails.delete(k);
  if (authFails.size <= LOCK_MAP_MAX) return;
  let drop = 500;
  for (const [k, e] of authFails) { if (drop <= 0) break; if (e.until <= now) { authFails.delete(k); drop--; } }
  if (authFails.size <= LOCK_MAP_MAX * 2) return;
  drop = 500;
  for (const k of authFails.keys()) { if (drop-- <= 0) break; authFails.delete(k); }
}
// One gate for every route that proves a password: lockout first, then the
// optional Rate Limiting binding (per network, counts attempts across
// isolates), then `verify`. Returns a Response to send on refusal, or null
// when the caller is authenticated. Logs never carry the password.
async function checkPassword(req, env, scope, verify) {
  const key = netKey(req, scope);
  const wait = lockoutSeconds(key);
  if (wait) return json({ error: "locked", retryAfter: wait }, 429);
  if (env && env.ADMIN_RL && typeof env.ADMIN_RL.limit === "function") {
    try {
      const { success } = await env.ADMIN_RL.limit({ key });
      if (!success) { console.log(`auth: rate limited (${key})`); return json({ error: "locked", retryAfter: 60 }, 429); }
    } catch (e) { console.log(`auth: rate limiter unavailable: ${e && e.message}`); } // in-memory lockout still applies
  }
  if (!(await verify())) {
    lockoutFail(key);
    console.log(`auth: bad password (${key})`); // never the value
    return json({ error: "bad password" }, 403);
  }
  lockoutReset(key);
  return null;
}
// Constant-time string equality for the secret-backed routes (REPORT_PW,
// CLIENT_PWS, SYNC_SECRET): both sides are hashed so the comparison never
// depends on where the first differing byte is, or on the lengths.
async function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || !a || !b) return false;
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([crypto.subtle.digest("SHA-256", enc.encode(a)), crypto.subtle.digest("SHA-256", enc.encode(b))]);
  const x = new Uint8Array(ha), y = new Uint8Array(hb);
  let d = 0;
  for (let i = 0; i < 32; i++) d |= x[i] ^ y[i];
  return d === 0;
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

// validateBrand / validateName: see ../brand-validate.mjs (imported above).

// ---- admin KV keys (namespace is shared — never list() without the prefix) ----
const BRAND_KEY_PREFIX = "myrx:brand:";
const PWS_KEY = "myrx:pws";
const ADMIN_SLUG_RE = /^[a-z0-9-]{1,40}$/;
const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const MAX_ADMIN_BODY_BYTES = 1000000;

// Read and parse the JSON body under a hard byte cap that does not trust the
// Content-Length header (absent on chunked uploads, unparseable if forged):
// the header is a fast path to a 413, the stream count is the real limit.
// Returns { body } or { error: Response }.
async function readJsonBody(req, max) {
  const bad = (msg, status) => ({ error: json({ error: msg }, status) });
  const cl = req.headers.get("content-length");
  if (cl !== null) {
    const n = Number(cl);
    if (!Number.isFinite(n) || n < 0) return bad("bad json", 400);
    if (n > max) return bad("too large", 413);
  }
  if (!req.body) return bad("bad json", 400);
  const chunks = [];
  let n = 0;
  try {
    const reader = req.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      n += value.byteLength;
      if (n > max) { await reader.cancel().catch(() => {}); return bad("too large", 413); }
      chunks.push(value);
    }
  } catch { return bad("bad json", 400); }
  const buf = new Uint8Array(n);
  let off = 0;
  for (const c of chunks) { buf.set(c, off); off += c.byteLength; }
  let body;
  try { body = JSON.parse(new TextDecoder().decode(buf)); } catch { return bad("bad json", 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return bad("bad json", 400);
  return { body };
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
    if (req.method !== "POST") return json({ error: "POST only" }, 405);
    // size cap enforced while reading: nothing legitimate here is near 1 MB
    // (the largest is a brand.put with two 200 KB logos)
    const parsed = await readJsonBody(req, MAX_ADMIN_BODY_BYTES);
    if (parsed.error) return parsed.error;
    const body = parsed.body;
    // ---- reports.myrxcard.com admin routes ----
    // Kept ABOVE the Xano guard: partner pages read their live brand from here
    // on every load and must keep working when the Xano token is missing.
    // PUBLIC: a partner page fetching its live brand. Only that slug's doc —
    // never passwords, never other slugs.
    if (body.brand_get !== undefined) {
      const slug = String(body.brand_get || "").toLowerCase();
      if (!ADMIN_SLUG_RE.test(slug)) return json({ error: "bad site" }, 400);
      if (!env.AAPS_DATA) return json({ error: "KV not bound" }, 500);
      const doc = await env.AAPS_DATA.get(BRAND_KEY_PREFIX + slug, { type: "json", cacheTtl: 60 });
      if (!doc) return json({ ok: true, found: false, doc: null });
      return json({ ok: true, found: true, doc });
    }
    if (body.admin_pw !== undefined) {
      const denied = await checkPassword(req, env, "master", () => verifyMaster(String(body.admin_pw || "")));
      if (denied) return denied;
      const action = String(body.action || "");
      if (action === "ping") return json({ ok: true, kv: !!env.AAPS_DATA });
      if (!env.AAPS_DATA) return json({ error: "KV not bound" }, 500);
      if (action === "brands.list") {
        const lst = await env.AAPS_DATA.list({ prefix: BRAND_KEY_PREFIX, limit: 50 });
        const docs = await Promise.all(lst.keys.map((k) => env.AAPS_DATA.get(k.name, { type: "json" })));
        const clients = docs.filter((d) => isPlainObject(d) && typeof d.slug === "string");
        clients.sort((a, b) => String(a.name || a.slug).localeCompare(String(b.name || b.slug)));
        return json({ ok: true, clients });
      }
      if (action === "brand.put") {
        const slug = String(body.slug || "").toLowerCase();
        if (!ADMIN_SLUG_RE.test(slug)) return json({ error: "bad slug" }, 400);
        // name follows the same text rules as brand strings, and must be present
        const nm = validateName(body.name);
        if (nm.error) return json({ error: `name: ${nm.error}`, path: "name" }, 422);
        const name = nm.name;
        const brand = body.brand;
        if (brand === undefined) return json({ error: "brand: must be an object or null", path: "brand" }, 422);
        if (brand !== null) {
          if (!isPlainObject(brand)) return json({ error: "brand: must be an object or null", path: "brand" }, 422);
          if (JSON.stringify(brand).length > BRAND_DOC_MAX) return json({ error: "too large", path: "brand" }, 413);
          const err = validateBrand(brand);
          if (err) {
            if (err.status === 413) return json({ error: "too large", path: err.path }, 413);
            return json({ error: `${err.path}: ${err.reason}`, path: err.path }, err.status);
          }
          brand.name = name;
        }
        let existing = null;
        try { existing = await env.AAPS_DATA.get(BRAND_KEY_PREFIX + slug, { type: "json" }); } catch {}
        if (!isPlainObject(existing)) existing = null;
        // type / demo / updatedFrom: the seed script (master-gated like every
        // caller here) sends them so a seeded doc reads as a seed and a demo
        // client keeps its DEMO badge; the admin page never sends them, so an
        // admin save preserves the existing flags and stamps "admin".
        const doc = {
          v: 1, slug, name,
          type: (typeof body.type === "string" && /^[a-z]{1,20}$/.test(body.type) && body.type)
            || (existing && typeof existing.type === "string" && existing.type) || "pharmacy",
          demo: typeof body.demo === "boolean" ? body.demo : (existing ? !!existing.demo : false),
          brand,
          updatedAt: new Date().toISOString(),
          updatedFrom: body.updatedFrom === "seed" ? "seed" : "admin",
        };
        await env.AAPS_DATA.put(BRAND_KEY_PREFIX + slug, JSON.stringify(doc));
        return json({ ok: true, doc });
      }
      // The vault is ciphertext sealed by the admin page / seed script with the
      // master password (encryptJSON: PBKDF2 310k + AES-GCM). Stored and
      // returned as-is; the worker never sees a partner password.
      if (action === "pws.get") {
        const vault = await env.AAPS_DATA.get(PWS_KEY, { type: "json" });
        if (!isPlainObject(vault) || !isPlainObject(vault.enc)) return json({ error: "not seeded" }, 404);
        return json({ ok: true, enc: vault.enc, updatedAt: vault.updatedAt || null });
      }
      if (action === "pws.put") {
        const enc = body.enc;
        if (!isPlainObject(enc)) return json({ error: "enc: must be {salt, iv, data}", path: "enc" }, 422);
        for (const k of Object.keys(enc)) if (!["salt", "iv", "data"].includes(k)) return json({ error: `enc.${k}: unknown key`, path: `enc.${k}` }, 422);
        let total = 0;
        for (const k of ["salt", "iv", "data"]) {
          if (typeof enc[k] !== "string" || !B64_RE.test(enc[k])) return json({ error: `enc.${k}: must be a base64 string`, path: `enc.${k}` }, 422);
          total += enc[k].length;
        }
        if (total > 100000) return json({ error: "too large", path: "enc" }, 413);
        const updatedAt = new Date().toISOString();
        await env.AAPS_DATA.put(PWS_KEY, JSON.stringify({ v: 1, updatedAt, enc: { salt: enc.salt, iv: enc.iv, data: enc.data } }));
        return json({ ok: true, updatedAt });
      }
      return json({ error: "bad action" }, 400);
    }
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
      // site "" proves the MASTER (same check as admin_pw) — same lockout counter
      const denied = await checkPassword(req, env, slug ? "site:" + slug : "master", () => verifyReportPassword(slug, String(body.feed_pw || "")));
      if (denied) return denied;
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
      // REPORT_PW is the reports.myrxcard.com master password, so this route
      // is a master oracle too: same lockout scope, constant-time compares.
      let clientMeta = null;
      const denied = await checkPassword(req, env, "master", async () => {
        const given = typeof body.report_pw === "string" ? body.report_pw : "";
        if (await safeEqual(given, env.REPORT_PW)) return true;
        let map = {};
        try { map = JSON.parse(env.CLIENT_PWS || "{}"); } catch {}
        for (const [slug, c] of Object.entries(map)) {
          if (c && typeof c.pw === "string" && (await safeEqual(given, c.pw))) { clientMeta = { slug, label: c.label || slug }; return true; }
        }
        return false;
      });
      if (denied) return denied;
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
    if (!(await safeEqual(typeof body.secret === "string" ? body.secret : "", env.SYNC_SECRET))) return json({ error: "bad secret" }, 403);
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
