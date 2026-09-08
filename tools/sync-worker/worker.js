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
// reports.avalonsaves.com admin (live client brands + a worker-sealed client vault):
//   POST / { aa_brand_get: "<slug>" }                 PUBLIC — {ok, found, doc} (whitelisted projection; never a password)
//   POST / { aa_admin_pw, action: "ping" }            MASTER — {ok, kv, vault:"absent"|"ok"|"sealed"|"error"} ("error" = KV unreadable right now)
//   POST / { aa_admin_pw, action: "clients.list" }    MASTER — {ok, vault, updatedAt, clients:[{slug,label,demo,demoBadge,doc}]} (no passwords)
//   POST / { aa_admin_pw, action: "client.reveal", slug }       MASTER — {ok, slug, pw}
//   POST / { aa_admin_pw, action: "clients.seed", force? }      MASTER — seal CLIENT_PWS into the vault + stock docs (force: ONLY over a sealed vault)
//   POST / { aa_admin_pw, action: "clients.reseal", oldPw }     MASTER — re-key the vault after a REPORT_PW rotation
//   POST / { aa_admin_pw, action: "client.put", slug, label?, pw?, regenPw?, demo?, demoBadge?, brand? }
//   POST / { aa_admin_pw, action: "client.delete", slug, force? }
//   aa_admin_pw is REPORT_PW, the Avalon Assist master. KV keys (prefix "aa:"):
//     aa:brand:<slug> → BrandDoc {v, slug, name, demo, demoBadge, brand|null, updatedAt, updatedFrom}
//     aa:clients      → {v, updatedAt, enc} — the client-password vault, sealed by
//                        THIS worker under REPORT_PW (PBKDF2 310k + AES-GCM);
//                        plaintext lives only in isolate memory (see aaLoadVault).
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
// AUTH SURFACE: two masters, one gate. REPORT_PW is the reports.avalonsaves.com
// (Avalon Assist) report password: it unlocks report_pw, proves aa_admin_pw and
// is the key that seals aa:clients. The reports.myrxcard.com master is a
// DIFFERENT value, proven only by verifyMaster decrypting /config.enc.json
// (admin_pw, feed_pw with site ""). Every one of them goes through
// checkPassword(): one per-network failure counter per scope ("master" for the
// MyRxCard master, "aa" for the Avalon routes, "site:<slug>" for partner feeds;
// in-memory, plus the ADMIN_RL rate-limit binding when bound) checked before
// any PBKDF2, constant-time compares for the secret-backed routes, and never a
// password value in a log line.
//
// Brand schema validation lives in ../brand-validate.mjs (shared with
// build-clients.mjs and the tests); wrangler bundles the import on deploy.

import { validateBrand, validateBrandAA, validateName, isPlainObject, BRAND_DOC_MAX } from "../brand-validate.mjs";

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
// base64 <-> bytes. Decode into a preallocated buffer: Uint8Array.from(str, fn)
// materialises a multi-million-element iterator for the big report files and
// spikes memory. Encode via btoa over a string (the vault is a few KB).
const b64dec = (str) => { const bin = atob(str), out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; };
const b64enc = (u8) => { let bin = ""; for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]); return btoa(bin); };
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
    const raw = pbkdf2Sha256_32(new TextEncoder().encode(pw), b64dec(blob.salt), 310000);
    const aesKey = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64dec(blob.iv) }, aesKey, b64dec(blob.data));
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
// 10 minutes lock the caller out for 10 minutes; a MASTER success clears the
// counter (a client password proving itself under "aa" never does).
// Keyed by NETWORK + scope, not bare IP: an IPv6 caller is collapsed to its
// /64 (a single subscriber's allocation), so address rotation inside it buys
// nothing. Scope "master" is shared by admin_pw and feed_pw with site "" (the
// routes that prove the MyRxCard master); scope "aa" by report_pw and
// aa_admin_pw (the Avalon Assist master, REPORT_PW) — so guesses at one site
// never lock the other's admin; partner-page feed guesses count under
// "site:<slug>". Per isolate; the ADMIN_RL binding (see wrangler.toml) adds a
// limit that survives isolate churn.
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
// `verify` resolves to "master" (the scope's own credential: clears the
// failure counter), true (authenticated with a lesser credential that shares
// the scope — a client or demo password under "aa" — the counter is left
// alone, so a handed-out demo password can never launder guesses at the
// master), false (a failure), or a Response when it could not decide (KV
// unavailable): that Response is sent as-is with no lockout accounting.
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
  const r = await verify();
  if (r instanceof Response) return r;
  if (!r) {
    lockoutFail(key);
    console.log(`auth: bad password (${key})`); // never the value
    return json({ error: "bad password" }, 403);
  }
  if (r === "master") lockoutReset(key);
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
// Which rows a client key owns (its own slug for a real client, demo.from for
// a demo): a WHOLE-WORD match over tpa + client_name, with "-" in the slug
// standing for an optional "-"/" " — "marpai" owns "Marpai Health" and
// "Marpai TPA", "acme-health" owns "Acme Health" / "AcmeHealth", and "pai" or
// "rx" own nothing (a bare substring test let a short slug own every client's
// rows). Keys always satisfy ADMIN_SLUG_RE, so the pattern needs no escaping.
const ownsRe = new Map(); // slug -> RegExp (a handful of clients; bounded anyway)
function clientOwns(row, slug) {
  if (!ADMIN_SLUG_RE.test(slug)) return false;
  let re = ownsRe.get(slug);
  if (!re) {
    if (ownsRe.size > 200) ownsRe.clear();
    re = new RegExp("(^|[^a-z0-9])" + slug.replace(/-/g, "[- ]?") + "([^a-z0-9]|$)");
    ownsRe.set(slug, re);
  }
  return re.test(((row.tpa || "") + " " + (row.client_name || "")).toLowerCase());
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

// ---- reports.avalonsaves.com admin: client vault + brand docs ----
// Vault aa:clients = {v:1, updatedAt, enc:{salt, iv, data}} sealed by THIS
// worker under REPORT_PW (pbkdf2Sha256_32 310k -> AES-GCM-256; fresh 16-byte
// salt and 12-byte IV per seal — IV reuse under GCM is catastrophic).
// Plaintext {v:1, clients:{<slug>:{pw, label, demo?:{from, scale}, demoBadge?}}}
// lives only in isolate memory: aaVault caches the last read for 60 s and
// re-derives only when the ciphertext actually changed, so the ~190 ms PBKDF2
// is paid once per isolate per vault change — never on aa_brand_get, never on
// a master unlock (the master compare runs first). A vault that will not open
// under the current REPORT_PW ("sealed") degrades the read route to the
// CLIENT_PWS secret instead of locking every client out; clients.reseal
// re-keys it with the old password after a rotation.
const AA_BRAND_KEY_PREFIX = "aa:brand:";
const AA_CLIENTS_KEY = "aa:clients";
const AA_RESERVED_SLUGS = new Set(["nash", "tools", "admin", "root", "index", "404", "assets"]);
const AA_PW_RE = /^[\x21-\x7e]{8,128}$/;
const AA_SCALE_MIN = 0.05, AA_SCALE_MAX = 20;
const AA_SCALE_FIELDS = ["awp", "aa_price", "aa_savings", "avalon_savings"];
const AA_VAULT_TTL_MS = 60000;
const AA_PW_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"; // no 0/O/1/I/l look-alikes
const AA_SEALED = "vault sealed with a different password";
const AA_KV_FAILED = "KV read failed"; // 503: KV unreadable right now — retry, never write
const AA_REAL_SLUG_MIN = 3; // a real client's slug is its CRM match key (clientOwns)
const AA_ACTIONS = new Set(["ping", "clients.list", "client.reveal", "clients.seed", "clients.reseal", "client.put", "client.delete"]);
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
let aaVault = { at: 0, pw: undefined, raw: null, state: "absent", clients: null, updatedAt: null }; // state: absent | ok | sealed | error

// Vault key. New seals use the NATIVE WebCrypto PBKDF2 at 100k iterations
// (Workers cap WebCrypto PBKDF2 at 100k) — ~30 ms instead of the ~400 ms the
// pure-JS 310k derivation costs here; a vault write (open + reseal) was ~1.2 s
// CPU and tripped the Worker limit on cold isolates. Only the worker ever
// opens this vault, so it is not bound to the page's 310k file format. Records
// sealed before this change (no enc.iter) still open through the JS path and
// are re-sealed in the new format on their next write.
const AA_VAULT_ITER = 100000;
async function aaKey(pw, salt, usages, iter) {
  if (iter === AA_VAULT_ITER) {
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: AA_VAULT_ITER, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, usages);
  }
  const raw = pbkdf2Sha256_32(new TextEncoder().encode(pw), salt, 310000);
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, usages);
}
// {<slug>:{pw, label, demo?, demoBadge?}} from any source (vault plaintext or
// the CLIENT_PWS secret): only well-formed entries survive, keys lowercased.
function aaNormalizeClients(map) {
  const out = {};
  if (!isPlainObject(map)) return out;
  for (const [k, c] of Object.entries(map)) {
    const slug = String(k).toLowerCase();
    if (!ADMIN_SLUG_RE.test(slug) || !isPlainObject(c) || typeof c.pw !== "string" || !c.pw) continue;
    const e = { pw: c.pw, label: typeof c.label === "string" && c.label.trim() ? c.label : slug };
    if (isPlainObject(c.demo) && typeof c.demo.from === "string" && ADMIN_SLUG_RE.test(c.demo.from.toLowerCase()) && typeof c.demo.scale === "number") e.demo = { from: c.demo.from.toLowerCase(), scale: c.demo.scale };
    if (typeof c.demoBadge === "boolean") e.demoBadge = c.demoBadge;
    out[slug] = e;
  }
  return out;
}
function aaSecretClients(env) {
  let map = {};
  try { map = JSON.parse(env.CLIENT_PWS || "{}"); } catch {}
  return aaNormalizeClients(map);
}
// ciphertext record -> {clients, updatedAt}; throws on a wrong key or a malformed record
async function aaOpenVault(raw, pw) {
  const rec = JSON.parse(raw);
  const enc = rec && rec.enc;
  if (!isPlainObject(enc) || [enc.salt, enc.iv, enc.data].some((v) => typeof v !== "string" || !B64_RE.test(v))) throw new Error("malformed vault record");
  const key = await aaKey(pw, b64dec(enc.salt), ["decrypt"], enc.iter === AA_VAULT_ITER ? AA_VAULT_ITER : undefined);
  const pt = JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64dec(enc.iv) }, key, b64dec(enc.data))));
  if (!isPlainObject(pt) || !isPlainObject(pt.clients)) throw new Error("malformed vault plaintext");
  return { clients: aaNormalizeClients(pt.clients), updatedAt: typeof rec.updatedAt === "string" ? rec.updatedAt : null };
}
// Cached vault state for this isolate: {state:"absent"|"ok"|"sealed"|"error", clients, updatedAt}.
// Re-read from KV after AA_VAULT_TTL_MS (or when REPORT_PW itself changed, or
// when `fresh` — every writer passes it, so a reseal never starts from a
// roster another isolate has since changed); the PBKDF2 runs only when the
// stored ciphertext differs from the cached one. A KV read FAILURE is its own
// state, "error": never cached (at: 0) and never mistaken for "absent" —
// which the writers would otherwise paper over with the CLIENT_PWS secret.
async function aaLoadVault(env, fresh) {
  const now = Date.now();
  if (!fresh && aaVault.pw === env.REPORT_PW && now - aaVault.at < AA_VAULT_TTL_MS) return aaVault;
  let raw = null;
  try { raw = await env.AAPS_DATA.get(AA_CLIENTS_KEY); }
  catch (e) {
    console.log(`aa: vault read failed: ${e && e.name}`); // never a value
    aaVault = { at: 0, pw: env.REPORT_PW, raw: null, state: "error", clients: null, updatedAt: null };
    return aaVault;
  }
  if (typeof raw !== "string") { aaVault = { at: now, pw: env.REPORT_PW, raw: null, state: "absent", clients: null, updatedAt: null }; return aaVault; }
  if (raw === aaVault.raw && aaVault.pw === env.REPORT_PW) { aaVault.at = now; return aaVault; }
  try {
    const { clients, updatedAt } = await aaOpenVault(raw, String(env.REPORT_PW || ""));
    aaVault = { at: now, pw: env.REPORT_PW, raw, state: "ok", clients, updatedAt };
  } catch (e) {
    console.log(`aa: vault did not open: ${e && e.name}`); // never a value
    aaVault = { at: now, pw: env.REPORT_PW, raw, state: "sealed", clients: null, updatedAt: null };
  }
  return aaVault;
}
// Seal `clients` under the current REPORT_PW, write it, and serve it from this
// isolate immediately (the cache is primed from the plaintext just written).
async function aaSeal(env, clients) {
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await aaKey(String(env.REPORT_PW || ""), salt, ["encrypt"], AA_VAULT_ITER);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify({ v: 1, clients })));
  const updatedAt = new Date().toISOString();
  const raw = JSON.stringify({ v: 1, updatedAt, enc: { salt: b64enc(salt), iv: b64enc(iv), data: b64enc(new Uint8Array(data)), iter: AA_VAULT_ITER } });
  await env.AAPS_DATA.put(AA_CLIENTS_KEY, raw);
  aaVault = { at: Date.now(), pw: env.REPORT_PW, raw, state: "ok", clients: aaNormalizeClients(clients), updatedAt };
  return updatedAt;
}
// The admin roster: the open vault, or CLIENT_PWS while no vault exists yet.
// A sealed vault is an error here (the read route degrades; the admin must
// reseal), and so is an unreadable KV (503: retry — the alternative is to
// write over a vault that is really there) — returns {clients (a private
// copy), fromVault, updatedAt} | {error}. Writers pass `fresh`.
async function aaRoster(env, fresh) {
  const v = await aaLoadVault(env, fresh);
  if (v.state === "error") return { error: json({ error: AA_KV_FAILED }, 503) };
  if (v.state === "sealed") return { error: json({ error: AA_SEALED }, 500) };
  if (v.state === "ok") return { clients: JSON.parse(JSON.stringify(v.clients)), fromVault: true, updatedAt: v.updatedAt };
  return { clients: aaSecretClients(env), fromVault: false, updatedAt: null };
}
// The public projection of a brand doc: never a password, never demo.from/scale.
function aaPublicDoc(d) {
  if (!isPlainObject(d) || typeof d.slug !== "string") return null;
  return { v: 1, slug: d.slug, name: typeof d.name === "string" ? d.name : d.slug, demo: !!d.demo, demoBadge: d.demoBadge !== false,
    brand: isPlainObject(d.brand) ? d.brand : null, updatedAt: typeof d.updatedAt === "string" ? d.updatedAt : null, updatedFrom: d.updatedFrom === "seed" ? "seed" : "admin" };
}
async function aaGetDoc(env, slug, opts) {
  let d = null;
  try { d = await env.AAPS_DATA.get(AA_BRAND_KEY_PREFIX + slug, { type: "json", ...(opts || {}) }); } catch {}
  return aaPublicDoc(d);
}
// Invariant: every client in the roster has an aa:brand:<slug> doc. Writes a
// stock one where missing; returns the roster's slugs sorted.
async function aaEnsureDocs(env, clients) {
  const slugs = Object.keys(clients).sort();
  for (const slug of slugs) {
    if (await aaGetDoc(env, slug)) continue;
    const c = clients[slug];
    await env.AAPS_DATA.put(AA_BRAND_KEY_PREFIX + slug, JSON.stringify({ v: 1, slug, name: c.label, demo: !!c.demo, demoBadge: c.demoBadge !== false, brand: null, updatedAt: new Date().toISOString(), updatedFrom: "seed" }));
  }
  return slugs;
}
// xxxx-xxxx-xxxx over a 31-symbol alphabet (~60 bits) from getRandomValues,
// with rejection sampling so no symbol is favoured.
function aaGenPw() {
  const n = AA_PW_ALPHABET.length, lim = 256 - (256 % n);
  let s = "";
  while (s.length < 12) for (const b of crypto.getRandomValues(new Uint8Array(24))) if (b < lim && s.length < 12) s += AA_PW_ALPHABET[b % n];
  return `${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}`;
}
// ...and never one that already unlocks something else (the first safeEqual
// match decides a caller's identity).
async function aaFreshPw(env, clients, slug) {
  for (;;) {
    const pw = aaGenPw();
    if (await safeEqual(pw, env.REPORT_PW)) continue;
    let dup = false;
    for (const [s, c] of Object.entries(clients)) if (s !== slug && (await safeEqual(pw, c.pw))) { dup = true; break; }
    if (!dup) return pw;
  }
}
// Demo anonymization of an already white-labeled row: no case/group numbers,
// ages to the bottom of their 5-year band, dollar fields scaled. member_ref
// is re-HMACed by the caller under the DEMO slug so tokens never join up with
// the source client's site.
function aaAnonymize(w, scale) {
  delete w.assist_number;
  delete w.group_number;
  if (typeof w.member_age === "number" && Number.isFinite(w.member_age)) w.member_age = Math.floor(w.member_age / 5) * 5;
  for (const k of AA_SCALE_FIELDS) if (typeof w[k] === "number") w[k] = Math.round(w[k] * scale * 100) / 100;
}

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
      const denied = await checkPassword(req, env, "master", async () => (await verifyMaster(String(body.admin_pw || ""))) ? "master" : false);
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
        if (body.demoBadge !== undefined && typeof body.demoBadge !== "boolean") return json({ error: "demoBadge: must be true or false", path: "demoBadge" }, 422);
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
          // demo sites only: whether the page shows the DEMO DATA badge (data is anonymized regardless)
          demoBadge: typeof body.demoBadge === "boolean" ? body.demoBadge : (existing && typeof existing.demoBadge === "boolean" ? existing.demoBadge : true),
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
    // ---- reports.avalonsaves.com admin routes ----
    // Same placement rule as the myrx block: above the Xano guard, so the
    // client pages' brand fetch and the admin tab work without the Xano token.
    // PUBLIC: a client page fetching its live brand. One KV key by validated
    // slug, projected through aaPublicDoc — never the vault, never CLIENT_PWS.
    if (body.aa_brand_get !== undefined) {
      const slug = String(body.aa_brand_get || "").toLowerCase();
      if (!ADMIN_SLUG_RE.test(slug)) return json({ error: "bad site" }, 400);
      if (!env.AAPS_DATA) return json({ error: "KV not bound" }, 500);
      const doc = await aaGetDoc(env, slug, { cacheTtl: 60 });
      if (!doc) return json({ ok: true, found: false, doc: null });
      return json({ ok: true, found: true, doc });
    }
    if (body.aa_admin_pw !== undefined) {
      // the Avalon Assist master is REPORT_PW itself: constant-time compare,
      // lockout scope "aa" (shared with report_pw, separate from the MyRx master)
      const denied = await checkPassword(req, env, "aa", async () => (await safeEqual(typeof body.aa_admin_pw === "string" ? body.aa_admin_pw : "", env.REPORT_PW)) ? "master" : false);
      if (denied) return denied;
      const action = String(body.action || "");
      if (!AA_ACTIONS.has(action)) return json({ error: "bad action" }, 400);
      if (action === "ping") return json({ ok: true, kv: !!env.AAPS_DATA, vault: env.AAPS_DATA ? (await aaLoadVault(env)).state : "absent" });
      if (!env.AAPS_DATA) return json({ error: "KV not bound" }, 500);
      // Vault absent -> seal the CLIENT_PWS entries; always make sure every
      // client has a stock brand doc. Idempotent. force is ONLY the recovery
      // for a vault sealed under a password nobody has: over an open vault it
      // would discard every admin-created client and rotated password, so it
      // is refused there. Reads KV afresh — never the 60 s cache.
      if (action === "clients.seed") {
        const v = await aaLoadVault(env, true);
        if (v.state === "error") return json({ error: AA_KV_FAILED }, 503);
        if (body.force === true && v.state !== "sealed") return json({ error: "force only recovers a sealed vault", hint: "vault is " + v.state }, 409);
        if (v.state === "sealed" && body.force !== true) return json({ error: AA_SEALED, hint: "force" }, 409);
        let clients = v.state === "ok" ? v.clients : null;
        const sealed = !clients;
        if (sealed) { clients = aaSecretClients(env); await aaSeal(env, clients); }
        const slugs = await aaEnsureDocs(env, clients);
        return json({ ok: true, sealed, count: slugs.length, slugs });
      }
      // REPORT_PW rotated: open the vault with the previous password, reseal
      // under the current one. Reads KV directly — the cache says "sealed".
      if (action === "clients.reseal") {
        const oldPw = typeof body.oldPw === "string" ? body.oldPw : "";
        if (!oldPw || oldPw.length > 200) return json({ error: "oldPw: required", path: "oldPw" }, 422);
        let raw = null;
        try { raw = await env.AAPS_DATA.get(AA_CLIENTS_KEY); } catch { return json({ error: AA_KV_FAILED }, 503); }
        if (typeof raw !== "string") return json({ error: "not seeded" }, 404);
        let opened;
        try { opened = await aaOpenVault(raw, oldPw); } catch { return json({ error: AA_SEALED }, 409); }
        await aaSeal(env, opened.clients);
        return json({ ok: true, count: Object.keys(opened.clients).length });
      }
      // everything below works on an open roster; the writers re-read KV so a
      // reseal never starts from a roster cached up to 60 s ago in this isolate
      // (a client created, rotated or deleted elsewhere would be undone)
      const roster = await aaRoster(env, action === "client.put" || action === "client.delete");
      if (roster.error) return roster.error;
      const clients = roster.clients;
      const slug = String(body.slug || "").toLowerCase();
      if (action === "clients.list") {
        const list = [];
        for (const [s, c] of Object.entries(clients)) list.push({ slug: s, label: c.label, demo: c.demo ? { from: c.demo.from, scale: c.demo.scale } : null, demoBadge: c.demoBadge !== false, doc: await aaGetDoc(env, s) });
        list.sort((a, b) => a.label.localeCompare(b.label));
        return json({ ok: true, vault: roster.fromVault, updatedAt: roster.updatedAt, clients: list });
      }
      // the ONLY route that returns a client password: one slug, on demand
      if (action === "client.reveal") {
        if (!ADMIN_SLUG_RE.test(slug) || !own(clients, slug)) return json({ error: "unknown client" }, 404);
        return json({ ok: true, slug, pw: clients[slug].pw });
      }
      if (action === "client.put") {
        if (!ADMIN_SLUG_RE.test(slug)) return json({ error: "bad slug", path: "slug" }, 400);
        const existing = own(clients, slug) ? clients[slug] : null;
        if (!existing && AA_RESERVED_SLUGS.has(slug)) return json({ error: "slug: reserved", path: "slug" }, 422);
        // a real client's slug is the key clientOwns matches against the CRM
        // (a demo's rows come from demo.from): too short and it owns everyone's
        if (!existing && body.demo === undefined && slug.length < AA_REAL_SLUG_MIN) return json({ error: `slug: real client slugs need at least ${AA_REAL_SLUG_MIN} characters`, path: "slug" }, 422);
        const entry = existing ? { ...existing } : {};
        if (body.label !== undefined || !existing) {
          if (body.label === undefined) return json({ error: "label: required", path: "label" }, 422);
          const nm = validateName(body.label);
          if (nm.error) return json({ error: `label: ${nm.error}`, path: "label" }, 422);
          entry.label = nm.name;
        }
        // password: supplied, regenerated (existing clients), or generated on create
        let pwSet = false;
        if (body.pw !== undefined) {
          const pw = body.pw;
          if (typeof pw !== "string" || !AA_PW_RE.test(pw)) return json({ error: "pw: 8-128 printable characters, no spaces", path: "pw" }, 422);
          if (await safeEqual(pw, env.REPORT_PW)) return json({ error: "pw: must differ from the report password", path: "pw" }, 422);
          for (const [s, c] of Object.entries(clients)) if (s !== slug && (await safeEqual(pw, c.pw))) return json({ error: "pw: already used by another client", path: "pw" }, 422);
          entry.pw = pw; pwSet = true;
        } else if (!existing || body.regenPw === true) {
          entry.pw = await aaFreshPw(env, clients, slug); pwSet = true;
        }
        if (body.demo !== undefined) {
          const d = body.demo;
          if (!isPlainObject(d) || Object.keys(d).some((k) => k !== "from" && k !== "scale")) return json({ error: "demo: must be {from, scale}", path: "demo" }, 422);
          if (existing && !existing.demo) return json({ error: "demo: only demo clients", path: "demo" }, 422);
          // from must be a KNOWN, REAL client: clientOwns is a substring match
          // over tpa + client_name and must never see arbitrary text
          const from = typeof d.from === "string" ? d.from.toLowerCase() : "";
          if (!ADMIN_SLUG_RE.test(from) || from === slug || !own(clients, from) || clients[from].demo) return json({ error: "demo.from: unknown client", path: "demo.from" }, 422);
          const scale = typeof d.scale === "number" ? Math.round(d.scale * 1000) / 1000 : NaN;
          if (!Number.isFinite(scale) || scale < AA_SCALE_MIN || scale > AA_SCALE_MAX) return json({ error: "demo.scale: must be a number from 0.05 to 20", path: "demo.scale" }, 422);
          entry.demo = { from, scale };
        }
        if (body.demoBadge !== undefined) {
          if (typeof body.demoBadge !== "boolean") return json({ error: "demoBadge: must be true or false", path: "demoBadge" }, 422);
          entry.demoBadge = body.demoBadge;
        }
        const brand = body.brand;
        if (brand !== undefined && brand !== null) {
          if (!isPlainObject(brand)) return json({ error: "brand: must be an object or null", path: "brand" }, 422);
          if (JSON.stringify(brand).length > BRAND_DOC_MAX) return json({ error: "too large", path: "brand" }, 413);
          const err = validateBrandAA(brand);
          if (err) {
            if (err.status === 413) return json({ error: "too large", path: err.path }, 413);
            return json({ error: `${err.path}: ${err.reason}`, path: err.path }, err.status);
          }
        }
        clients[slug] = entry;
        // the vault is resealed iff the entry changed (or the roster was still
        // CLIENT_PWS: first write materialises the vault, docs included)
        if (!roster.fromVault) await aaEnsureDocs(env, clients);
        if (!existing || !roster.fromVault || body.label !== undefined || pwSet || body.demo !== undefined || body.demoBadge !== undefined) await aaSeal(env, clients);
        const prev = await aaGetDoc(env, slug);
        const doc = { v: 1, slug, name: entry.label, demo: !!entry.demo, demoBadge: entry.demoBadge !== false,
          brand: brand !== undefined ? brand : (prev && prev.brand) || null, updatedAt: new Date().toISOString(), updatedFrom: "admin" };
        if (doc.brand) doc.brand.name = entry.label;
        await env.AAPS_DATA.put(AA_BRAND_KEY_PREFIX + slug, JSON.stringify(doc));
        // the password rides along only when this call set it (create, custom, regenPw)
        const client = { slug, label: entry.label, demo: entry.demo ? { ...entry.demo } : null, demoBadge: entry.demoBadge !== false };
        if (pwSet) client.pw = entry.pw;
        return json({ ok: true, client, doc });
      }
      if (action === "client.delete") {
        if (!ADMIN_SLUG_RE.test(slug) || !own(clients, slug)) return json({ error: "unknown client" }, 404);
        if (!clients[slug].demo) {
          for (const [s, c] of Object.entries(clients)) if (c.demo && c.demo.from === slug) return json({ error: `referenced by demo ${s}` }, 409);
          if (body.force !== true) return json({ error: "only demo clients can be deleted", hint: "force" }, 409);
        }
        delete clients[slug];
        await aaSeal(env, clients);
        await env.AAPS_DATA.delete(AA_BRAND_KEY_PREFIX + slug);
        // a real client's password may still be in the CLIENT_PWS secret, which
        // the read route falls back to while the vault is absent or sealed
        return json({ ok: true, slug, secretFallback: own(aaSecretClients(env), slug) });
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
      // site "" proves the MASTER (same check as admin_pw) — same lockout counter.
      // Either way the password proven here is its scope's own credential
      // (the partner's under "site:<slug>"), so a success clears that counter.
      const denied = await checkPassword(req, env, slug ? "site:" + slug : "master", async () => (await verifyReportPassword(slug, String(body.feed_pw || ""))) ? "master" : false);
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
    // a client password returns only that client's rows, white-labeled
    // server-side — the browser never sees other clients, fees, supplier
    // pricing, or real sourcing names. Client passwords come from the sealed
    // aa:clients vault when it opens, else from the CLIENT_PWS secret; a DEMO
    // client is a scaled, anonymized clone of a real client's rows.
    if (body.report_pw !== undefined) {
      // REPORT_PW is the Avalon Assist master (NOT the MyRxCard one): this
      // route is that site's master oracle, so it shares lockout scope "aa"
      // with aa_admin_pw and uses constant-time compares throughout.
      let clientMeta = null;
      const denied = await checkPassword(req, env, "aa", async () => {
        const given = typeof body.report_pw === "string" ? body.report_pw : "";
        if (await safeEqual(given, env.REPORT_PW)) return "master"; // the only success that clears the "aa" counter
        const v = env.AAPS_DATA ? await aaLoadVault(env) : null;
        // KV unreadable is neither "absent" nor "sealed": no CLIENT_PWS fallback
        // (it would re-arm a password retired from the vault) — 503, retry,
        // and no lockout accounting for the caller
        if (v && v.state === "error") return json({ error: AA_KV_FAILED }, 503);
        const clients = v && v.state === "ok" ? v.clients : aaSecretClients(env); // absent / sealed / no KV: the secret (documented degrade)
        for (const [slug, c] of Object.entries(clients)) {
          if (await safeEqual(given, c.pw)) {
            clientMeta = { slug, label: c.label, demo: !!c.demo, demoBadge: c.demoBadge !== false, from: c.demo ? c.demo.from : slug, scale: c.demo ? c.demo.scale : 1 };
            return true; // a client credential: authenticated, but it never resets the master's counter
          }
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
          if (!clientOwns(r, clientMeta.from)) continue; // a demo clones its source client's rows
          const w = whitelabel(r, clientMeta.label);      // ...under the demo's own label
          if (clientMeta.demo) aaAnonymize(w, clientMeta.scale);
          // tokens are re-HMACed under the CALLER's slug (the demo's, for a demo)
          if (w.member_ref) w.member_ref = await hmacHex16(env.MEMBER_SALT, clientMeta.slug + "|" + w.member_ref);
          out.push(w);
        }
        const { slug, label, demo, demoBadge } = clientMeta;
        return json({ ok: true, generatedAt: new Date().toISOString(), client: { slug, label, demo, demoBadge }, cases: out });
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
