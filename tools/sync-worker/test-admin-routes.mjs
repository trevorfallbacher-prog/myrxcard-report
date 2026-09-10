// test-admin-routes.mjs — offline tests for the reports.myrxcard.com admin
// routes in worker.js. No Cloudflare imports, no network, no real passwords.
//
//   cd tools/sync-worker && node test-admin-routes.mjs
//
// Part 1 unit-tests validateBrand from ../brand-validate.mjs (the module the
// worker, build-clients.mjs and this file all import).
// Part 2 drives the routes through the worker's fetch() with an in-memory
// KV and a stubbed global fetch that serves a config.enc.json sealed with a
// throwaway TEST password — the real master password is never involved.
// Part 3 covers the shared auth surface: the stream-capped body, the
// network-keyed lockout across admin_pw / feed_pw / report_pw, the
// constant-time secret compares and the optional rate-limit binding.
// Part 4 is the reports.avalonsaves.com side: validateBrandAA, aa_brand_get,
// every aa_admin_pw action, the vault lifecycle (absent -> seed -> put /
// reveal / regen / delete -> reseal after a REPORT_PW rotation -> sealed),
// demo scaling / anonymization / HMAC-under-demo-slug, that the "aa"
// lockout scope is separate from the MyRxCard "master" one (and that only the
// MASTER resets it), the whole-word client scoping key, and the failure
// modes that must never write: an unreadable KV ("error", 503), force on an
// open vault (409), and a roster changed in KV behind this isolate's cache.
// Part 5 is "Sign in with company email": the /login + /_auth/* surface on the
// two report hostnames driven with synthetic Access JWTs (an RSA key generated
// here, its JWKS served by the stubbed fetch), the session cookie round trip
// and its rejection cases, open-redirect attempts in `to`, the access.* admin
// actions (public-provider domains refused), the MyRxCard escrow lifecycle
// (missing -> ok -> stale -> ok), the Avalon vault key release with its
// sealed/unreadable degrades, the capped sign-in logs and the "auth:<site>"
// lockout scope that never touches the password routes and only ever counts
// guesses (bad tokens, forged cookies, unmapped emails) — never a bare visit
// to /login or a valid session refused a slug, since the counter is shared by
// everyone behind one office NAT.

import { validateBrand, validateBrandAA } from "../brand-validate.mjs";

let pass = 0, fail = 0;
function check(name, ok, detail) {
  if (ok) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}${detail ? " — " + detail : ""}`); }
}

// ---------------------------------------------------------------- part 1

const PNG_1PX = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
const SVG_MIN = "data:image/svg+xml;base64," + Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>').toString("base64");
const fullBrand = () => ({
  name: "UW Health",
  logo: SVG_MIN, logoDark: PNG_1PX, logoHeight: 32,
  tagline: "Pharmacy savings report", poweredBy: true,
  colors: { primary: "#0F2B5B", secondary: "#c8102e", tertiary: "#3a3a3a", accent: "#e0e7ff", accentBright: "#4f7fff",
    dark: { primary: "#dbe4ff", secondary: "#ff5c6e", tertiary: "#c0c0c0", accent: "#1d2a4a", accentBright: "#7aa2ff" } },
  fonts: { google: "family=Public+Sans:wght@400;500;600;700&family=Merriweather:wght@400;700",
    body: "'Public Sans', system-ui, sans-serif", heading: "Merriweather, Georgia, serif", mono: "'IBM Plex Mono', monospace" },
  headings: { transform: "uppercase", weight: 700, letterSpacing: "0.02em", gate: "Welcome to your report", menuLabel: "REPORTS",
    tabs: { search: "Searches", util: "Utilization" }, titles: { search: "Search performance", util: "Utilization" } },
  layout: { header: "title-first", radius: "8px", density: "compact" },
});
const withPath = (mut) => { const b = fullBrand(); mut(b); return b; };
const expectOk = (name, b) => { const e = validateBrand(b); check(name, e === null, e && `${e.path}: ${e.reason}`); return b; };
const expectErr = (name, b, path, status = 422) => {
  const e = validateBrand(b);
  check(name, e && e.path === path && e.status === status, e ? `got ${e.path} (${e.status}): ${e.reason}` : "validated OK");
};

console.log("validateBrand");
// valid shapes
const clean = expectOk("valid full brand", fullBrand());
check("uppercase hex is lowercased in place", clean.colors.primary === "#0f2b5b");
expectOk("empty object is valid (stock look with a name only)", {});
expectOk("partial brand: colors only", { colors: { secondary: "#c8102e" } });
{ const b = withPath((x) => { x.tagline = "A\u0007B\u001f"; x.headings.gate = "Wel\ncome"; });
  const e = validateBrand(b);
  check("control characters are stripped from text", e === null && b.tagline === "AB" && b.headings.gate === "Welcome", e ? `${e.path}: ${e.reason}` : JSON.stringify([b.tagline, b.headings.gate])); }
{ const b = withPath((x) => { x.tagline = "\u0000" + "x".repeat(80); }); check("length is measured after stripping", validateBrand(b) === null && b.tagline.length === 80); }
expectOk("text at exactly 80 chars", withPath((b) => { b.tagline = "x".repeat(80); }));
expectOk("logoHeight bounds 12 and 80", withPath((b) => { b.logoHeight = 12; b.colors.dark = undefined; delete b.colors.dark; }));
expectOk("logoHeight 80", withPath((b) => { b.logoHeight = 80; }));
expectOk("weight 300 lower bound", withPath((b) => { b.headings.weight = 300; }));
expectOk("weight 900 upper bound", withPath((b) => { b.headings.weight = 900; }));
expectOk("letterSpacing '0'", withPath((b) => { b.headings.letterSpacing = "0"; }));
expectOk("letterSpacing '.05em'", withPath((b) => { b.headings.letterSpacing = ".05em"; }));
expectOk("letterSpacing '-0.015em'", withPath((b) => { b.headings.letterSpacing = "-0.015em"; }));
expectOk("radius 0px", withPath((b) => { b.layout.radius = "0px"; }));
expectOk("radius 24px", withPath((b) => { b.layout.radius = "24px"; }));
expectOk("fonts.google single family", withPath((b) => { b.fonts.google = "family=Lato:wght@400;700"; }));
expectOk("fonts.google four families", withPath((b) => { b.fonts.google = "family=A&family=B&family=C&family=D:wght@400"; }));
expectOk("transform none / capitalize", withPath((b) => { b.headings.transform = "capitalize"; }));
expectOk("poweredBy false", withPath((b) => { b.poweredBy = false; }));
expectOk("webp and jpeg logos", withPath((b) => { b.logo = "data:image/webp;base64,AAAA"; b.logoDark = "data:image/jpeg;base64,/9j/4AAQ"; }));
expectOk("logo exactly 200000 chars", withPath((b) => { b.logo = "data:image/png;base64," + "A".repeat(200000 - 22); }));

// invalid shapes — every field
expectErr("brand must be an object (array)", [], "brand");
expectErr("brand must be an object (string)", "x", "brand");
expectErr("unknown root key", withPath((b) => { b.css = "x"; }), "brand.css");
expectErr("unknown colors key", withPath((b) => { b.colors.background = "#ffffff"; }), "brand.colors.background");
expectErr("unknown colors.dark key", withPath((b) => { b.colors.dark.extra = "#ffffff"; }), "brand.colors.dark.extra");
expectErr("unknown fonts key", withPath((b) => { b.fonts.url = "x"; }), "brand.fonts.url");
expectErr("unknown headings key", withPath((b) => { b.headings.size = 1; }), "brand.headings.size");
expectErr("unknown headings.tabs key", withPath((b) => { b.headings.tabs.fees = "Fees"; }), "brand.headings.tabs.fees");
expectErr("unknown layout key", withPath((b) => { b.layout.sidebar = "x"; }), "brand.layout.sidebar");
expectErr("#abc shorthand rejected (form expands it)", withPath((b) => { b.colors.primary = "#abc"; }), "brand.colors.primary");
expectOk("#aabbcc accepted", withPath((b) => { b.colors.primary = "#aabbcc"; }));
expectErr("8-digit hex rejected", withPath((b) => { b.colors.accent = "#aabbccdd"; }), "brand.colors.accent");
expectErr("named color rejected", withPath((b) => { b.colors.dark.primary = "red"; }), "brand.colors.dark.primary");
expectErr("color not a string", withPath((b) => { b.colors.tertiary = 0x333333; }), "brand.colors.tertiary");
expectErr("colors not an object", withPath((b) => { b.colors = "#fff"; }), "brand.colors");
expectErr("colors.dark not an object", withPath((b) => { b.colors.dark = ["#ffffff"]; }), "brand.colors.dark");
expectErr("logo wrong mime (gif)", withPath((b) => { b.logo = "data:image/gif;base64,R0lGOD"; }), "brand.logo");
expectErr("logo not base64 (utf8 svg)", withPath((b) => { b.logoDark = "data:image/svg+xml;utf8,<svg/>"; }), "brand.logoDark");
expectErr("logo http URL", withPath((b) => { b.logo = "https://example.com/logo.png"; }), "brand.logo");
expectErr("oversize logo -> 413", withPath((b) => { b.logo = "data:image/png;base64," + "A".repeat(200001); }), "brand.logo", 413);
expectErr("logoHeight 11", withPath((b) => { b.logoHeight = 11; }), "brand.logoHeight");
expectErr("logoHeight 81", withPath((b) => { b.logoHeight = 81; }), "brand.logoHeight");
expectErr("logoHeight non-integer", withPath((b) => { b.logoHeight = 32.5; }), "brand.logoHeight");
expectErr("logoHeight string", withPath((b) => { b.logoHeight = "32"; }), "brand.logoHeight");
expectErr("tagline too long (81)", withPath((b) => { b.tagline = "x".repeat(81); }), "brand.tagline");
expectErr("tagline contains <", withPath((b) => { b.tagline = "a <b> c"; }), "brand.tagline");
expectErr("name contains >", withPath((b) => { b.name = "x > y"; }), "brand.name");
expectErr("name not a string", withPath((b) => { b.name = 42; }), "brand.name");
expectErr("poweredBy not boolean", withPath((b) => { b.poweredBy = "yes"; }), "brand.poweredBy");
expectErr("fonts.google with display= param", withPath((b) => { b.fonts.google = "family=Lato&display=swap"; }), "brand.fonts.google");
expectErr("fonts.google five families", withPath((b) => { b.fonts.google = "family=A&family=B&family=C&family=D&family=E"; }), "brand.fonts.google");
expectErr("fonts.google missing family=", withPath((b) => { b.fonts.google = "Lato:wght@400"; }), "brand.fonts.google");
expectErr("fonts.google with URL chars", withPath((b) => { b.fonts.google = "family=Lato/../x"; }), "brand.fonts.google");
expectErr("fonts.body with CSS breakout", withPath((b) => { b.fonts.body = "x; } body { display:none"; }), "brand.fonts.body");
expectErr("fonts.heading too long", withPath((b) => { b.fonts.heading = "a".repeat(121); }), "brand.fonts.heading");
expectErr("fonts.mono empty", withPath((b) => { b.fonts.mono = ""; }), "brand.fonts.mono");
expectErr("transform enum", withPath((b) => { b.headings.transform = "lowercase"; }), "brand.headings.transform");
expectErr("weight 250", withPath((b) => { b.headings.weight = 250; }), "brand.headings.weight");
expectErr("weight 950", withPath((b) => { b.headings.weight = 950; }), "brand.headings.weight");
expectErr("weight as string", withPath((b) => { b.headings.weight = "700"; }), "brand.headings.weight");
expectErr("letterSpacing px", withPath((b) => { b.headings.letterSpacing = "1px"; }), "brand.headings.letterSpacing");
expectErr("letterSpacing 1em", withPath((b) => { b.headings.letterSpacing = "1em"; }), "brand.headings.letterSpacing");
expectErr("letterSpacing 0em", withPath((b) => { b.headings.letterSpacing = "0em"; }), "brand.headings.letterSpacing");
expectErr("letterSpacing 4 decimals", withPath((b) => { b.headings.letterSpacing = "0.1234em"; }), "brand.headings.letterSpacing");
expectErr("headings.gate with <script", withPath((b) => { b.headings.gate = "<script>alert(1)</script>"; }), "brand.headings.gate");
expectErr("headings.menuLabel too long", withPath((b) => { b.headings.menuLabel = "m".repeat(81); }), "brand.headings.menuLabel");
expectErr("headings.tabs.util not a string", withPath((b) => { b.headings.tabs.util = null; }), "brand.headings.tabs.util");
expectErr("headings.titles.search with >", withPath((b) => { b.headings.titles.search = "a>b"; }), "brand.headings.titles.search");
expectErr("headings.titles not an object", withPath((b) => { b.headings.titles = "x"; }), "brand.headings.titles");
expectErr("headings not an object", withPath((b) => { b.headings = []; }), "brand.headings");
expectErr("layout.header enum", withPath((b) => { b.layout.header = "logo-first"; }), "brand.layout.header");
expectErr("layout.radius 25px", withPath((b) => { b.layout.radius = "25px"; }), "brand.layout.radius");
expectErr("layout.radius rem", withPath((b) => { b.layout.radius = "1rem"; }), "brand.layout.radius");
expectErr("layout.radius 08px (leading zero)", withPath((b) => { b.layout.radius = "08px"; }), "brand.layout.radius");
expectErr("layout.density enum", withPath((b) => { b.layout.density = "cozy"; }), "brand.layout.density");
expectErr("layout not an object", withPath((b) => { b.layout = null; }), "brand.layout");
expectErr("whole doc > 600000 chars -> 413", withPath((b) => { b.logo = "data:image/png;base64," + "A".repeat(199000); b.logoDark = b.logo; b.tagline = "x"; b.extra = "A".repeat(210000); }), "brand", 413);
expectErr("path names the first offender in order", withPath((b) => { b.colors.dark.accentBright = "bad"; b.layout.radius = "99px"; }), "brand.colors.dark.accentBright");

// ---------------------------------------------------------------- part 2
console.log("routes (worker.fetch with mock KV + stubbed network)");
const TEST_MASTER = "test-master-" + Math.random().toString(36).slice(2);
async function encryptJSON(obj, password) { // same scheme as tools/store.mjs
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" }, baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc.encode(JSON.stringify(obj)));
  const b64 = (buf) => Buffer.from(buf).toString("base64");
  return { salt: b64(salt), iv: b64(iv), data: b64(data) };
}
const fakeRootBlob = await encryptJSON({ v: 1, test: true }, TEST_MASTER);
const partnerBlob = await encryptJSON({ v: 1, partner: true }, "partner-pw-not-master");
// fake case rows (Xano shape, incl. id/created_at which the read route strips).
// Two belong to "vault" (client_name substring), one to "marpai" (tpa).
const AA_ROWS = [
  { id: 1, created_at: 1, case_key: "c1", assist_number: "AA-1001", client_name: "Vault Health", tpa: "", group_number: "G77", source: "MedsDirect", status: "Completed", closed_reason: "",
    medication_name: "Drug A", ndc: "12345678901", medication_type: "Brand", month: "2026-01", created_date: "2026-01-05", closed_date: "2026-01-20",
    awp: 100, aa_price: 40, aa_savings: 60, avalon_savings: 55, avalon_fee: 10, myrxcard_pricing: 70, medsdirect_pricing: 65, member_ref: "abcd1234abcd1234", member_age: 47 },
  { id: 2, created_at: 2, case_key: "c2", assist_number: "AA-1002", client_name: "Vault Health", tpa: "", group_number: "G77", source: "Direct", status: "Open", closed_reason: "",
    medication_name: "Drug B", ndc: "", medication_type: "Generic", month: "2026-02", created_date: "2026-02-05", closed_date: "",
    awp: 33.333, aa_price: 12.5, aa_savings: 20.833, avalon_savings: 19, avalon_fee: 3, member_ref: "", member_age: 30 },
  { id: 3, created_at: 3, case_key: "c3", assist_number: "AA-2001", client_name: "Other Co", tpa: "Marpai TPA", group_number: "M1", source: "Mystery", status: "Completed", closed_reason: "",
    medication_name: "Drug C", ndc: "", medication_type: "Brand", month: "2026-01", created_date: "2026-01-09", closed_date: "",
    awp: 200, aa_price: 80, aa_savings: 120, avalon_savings: 110, avalon_fee: 20, member_ref: "ffff0000ffff0000", member_age: 64 },
];
const realFetch = globalThis.fetch;
globalThis.fetch = async (url) => {
  const u = String(url);
  if (u === "https://reports.myrxcard.com/config.enc.json") return new Response(JSON.stringify(fakeRootBlob), { status: 200 });
  if (/^https:\/\/reports\.myrxcard\.com\/[a-z0-9-]+\/utilization\.enc\.json$/.test(u)) return new Response(JSON.stringify(partnerBlob), { status: 200 });
  // a stand-in Xano for the routes that read after authenticating (parts 3, 4):
  // the cases table (12) serves AA_ROWS; everything else is empty
  if (u.startsWith("https://xano.test/")) {
    if (u.includes("/table?page=")) return new Response(JSON.stringify([{ id: 99, name: "search_events" }]), { status: 200 });
    if (u.endsWith("/table/12/content/search")) return new Response(JSON.stringify({ items: AA_ROWS.map((r) => ({ ...r })) }), { status: 200 });
    return new Response(JSON.stringify({ items: [] }), { status: 200 });
  }
  throw new Error("unexpected network call: " + u);
};
function mockKV() {
  const store = new Map();
  return {
    store,
    async get(key, opts) { const v = store.get(key); if (v === undefined) return null; return opts && opts.type === "json" ? JSON.parse(v) : v; },
    async put(key, val) { store.set(key, String(val)); },
    async delete(key) { store.delete(key); },
    async list({ prefix, limit }) { const keys = [...store.keys()].filter((k) => k.startsWith(prefix || "")).slice(0, limit || 1000).map((name) => ({ name })); return { keys, list_complete: true }; },
  };
}
const worker = (await import("./worker.js")).default;
const kv = mockKV();
const env = { AAPS_DATA: kv }; // deliberately NO Xano vars: admin routes must work without them
let ipCounter = 0;
const call = async (body, { ip = "203.0.113.7", contentLength, raw, env: envOverride } = {}) => {
  const text = raw !== undefined ? raw : JSON.stringify(body);
  const headers = { "content-type": "application/json", "cf-connecting-ip": ip };
  if (contentLength !== undefined) headers["content-length"] = String(contentLength);
  const req = new Request("https://myrxcard-sync.example/", { method: "POST", headers, body: text });
  const res = await worker.fetch(req, envOverride || env);
  let out = null;
  try { out = await res.json(); } catch {}
  return { status: res.status, out, cors: res.headers.get("access-control-allow-origin") };
};
const freshIp = () => `198.51.100.${++ipCounter}`;

let r;
r = await call(null, { raw: "null" }); check("null body -> 400 bad json", r.status === 400 && r.out.error === "bad json");
r = await call(null, { raw: "[1,2]" }); check("array body -> 400 bad json", r.status === 400 && r.out.error === "bad json");
r = await call(null, { raw: "{" }); check("unparseable -> 400 bad json", r.status === 400);
r = await call({ brand_get: "uwhc" }, { contentLength: 1000001 }); check("Content-Length > 1 MB -> 413 before parse", r.status === 413 && r.out.error === "too large");
r = await call(null, { raw: JSON.stringify({ brand_get: "uwhc", pad: "x".repeat(1000100) }) }); check("1 MB+ body WITHOUT Content-Length (chunked) -> 413 from the stream cap", r.status === 413 && r.out.error === "too large", JSON.stringify(r.out));
r = await call(null, { raw: JSON.stringify({ brand_get: "uwhc", pad: "x".repeat(1000100) }), contentLength: 10 }); check("lying Content-Length (10) does not lift the cap", r.status === 413);
r = await call({ brand_get: "uwhc" }, { contentLength: "abc" }); check("non-numeric Content-Length -> 400", r.status === 400 && r.out.error === "bad json");
r = await call(null, { raw: JSON.stringify({ brand_get: "uwhc", pad: "x".repeat(990000) }) }); check("990 KB body under the cap still served", r.status === 200 && r.out.found === false);
r = await call({ brand_get: "uwhc" }); check("brand_get unseeded -> found:false", r.status === 200 && r.out.ok && r.out.found === false && r.out.doc === null && r.cors === "*");
r = await call({ brand_get: "UWHC" }); check("brand_get lowercases slug", r.status === 200 && r.out.found === false);
r = await call({ brand_get: "bad slug!" }); check("brand_get bad slug -> 400 bad site", r.status === 400 && r.out.error === "bad site");
r = await call({ brand_get: "" }); check("brand_get empty slug -> 400", r.status === 400);
r = await worker.fetch(new Request("https://x/", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ brand_get: "uwhc" }) }), {});
check("brand_get without KV binding -> 500", r.status === 500 && (await r.json()).error === "KV not bound");
r = await call({}); check("empty body still falls to the Xano guard (existing behavior)", r.status === 500 && /Xano/.test(r.out.error));

// auth
r = await call({ admin_pw: "wrong-password", action: "ping" }); check("wrong master -> 403 bad password", r.status === 403 && r.out.error === "bad password");
r = await call({ admin_pw: "partner-pw-not-master", action: "ping" }); check("a PARTNER password is not master -> 403", r.status === 403);
r = await call({ admin_pw: TEST_MASTER, action: "ping" }); check("ping with master -> {ok, kv:true}", r.status === 200 && r.out.ok === true && r.out.kv === true);
r = await call({ admin_pw: TEST_MASTER, action: "nope" }); check("unknown action -> 400 bad action", r.status === 400 && r.out.error === "bad action");
r = await call({ admin_pw: TEST_MASTER, action: "ping" }, { ip: "10.0.0.1" });
check("cached master: second verify is instant", r.status === 200);

// lockout: 5 failures then 429, checked before PBKDF2
{
  const ip = freshIp();
  let last;
  for (let i = 0; i < 5; i++) last = await call({ admin_pw: "guess-" + i, action: "ping" }, { ip });
  check("first five failures -> 403", last.status === 403);
  const t0 = Date.now();
  r = await call({ admin_pw: TEST_MASTER, action: "ping" }, { ip });
  const dt = Date.now() - t0;
  check("locked IP -> 429 even with the right password", r.status === 429 && r.out.error === "locked" && r.out.retryAfter > 0 && r.out.retryAfter <= 600, JSON.stringify(r.out));
  check("lockout answered before the PBKDF2 (fast)", dt < 50, `${dt} ms`);
  r = await call({ admin_pw: TEST_MASTER, action: "ping" }, { ip: freshIp() });
  check("lockout is per IP", r.status === 200);
}
{
  const ip = freshIp();
  for (let i = 0; i < 4; i++) await call({ admin_pw: "guess-" + i, action: "ping" }, { ip });
  r = await call({ admin_pw: TEST_MASTER, action: "ping" }, { ip });
  check("4 failures then success -> allowed and counter reset", r.status === 200);
  for (let i = 0; i < 4; i++) await call({ admin_pw: "again-" + i, action: "ping" }, { ip });
  r = await call({ admin_pw: TEST_MASTER, action: "ping" }, { ip });
  check("  reset: 4 more failures still not locked", r.status === 200);
}

// brands.list / brand.put
r = await call({ admin_pw: TEST_MASTER, action: "brands.list" }); check("brands.list empty -> []", r.status === 200 && Array.isArray(r.out.clients) && r.out.clients.length === 0);
r = await call({ admin_pw: TEST_MASTER, action: "brand.put", slug: "Bad Slug", name: "x", brand: null }); check("brand.put bad slug -> 400", r.status === 400 && r.out.error === "bad slug");
r = await call({ admin_pw: TEST_MASTER, action: "brand.put", slug: "uwhc", name: "", brand: null }); check("brand.put empty name -> 422 path name", r.status === 422 && r.out.path === "name");
r = await call({ admin_pw: TEST_MASTER, action: "brand.put", slug: "uwhc", name: "UW <Health>", brand: null }); check("brand.put name with <> -> 422", r.status === 422 && r.out.path === "name");
r = await call({ admin_pw: TEST_MASTER, action: "brand.put", slug: "uwhc", name: "UW Health" }); check("brand.put missing brand -> 422", r.status === 422 && r.out.path === "brand");
r = await call({ admin_pw: TEST_MASTER, action: "brand.put", slug: "uwhc", name: "UW Health", brand: [] }); check("brand.put array brand -> 422", r.status === 422 && r.out.path === "brand");
r = await call({ admin_pw: TEST_MASTER, action: "brand.put", slug: "uwhc", name: "UW Health", brand: withPath((b) => { b.colors.dark.primary = "#12"; }) });
check("brand.put invalid field -> 422 with path", r.status === 422 && r.out.path === "brand.colors.dark.primary" && r.out.error.startsWith("brand.colors.dark.primary: "), JSON.stringify(r.out));
r = await call({ admin_pw: TEST_MASTER, action: "brand.put", slug: "uwhc", name: "UW Health", brand: withPath((b) => { b.logo = "data:image/png;base64," + "A".repeat(200001); }) });
check("brand.put oversize logo -> 413 too large", r.status === 413 && r.out.error === "too large", JSON.stringify(r.out));
r = await call({ admin_pw: TEST_MASTER, action: "brand.put", slug: "UWHC", name: "  UW Health ", brand: withPath((b) => { b.name = "ignored"; b.colors.primary = "#0F2B5B"; }) });
check("brand.put valid -> 200 doc", r.status === 200 && r.out.ok && r.out.doc && r.out.doc.slug === "uwhc", JSON.stringify(r.out).slice(0, 200));
if (r.out && r.out.doc) {
  const d = r.out.doc;
  check("  doc shape v/type/demo/updatedFrom", d.v === 1 && d.type === "pharmacy" && d.demo === false && d.updatedFrom === "admin" && /^\d{4}-\d\d-\d\dT/.test(d.updatedAt));
  check("  name trimmed and copied into brand.name", d.name === "UW Health" && d.brand.name === "UW Health");
  check("  colors lowercased", d.brand.colors.primary === "#0f2b5b");
  check("  stored under myrx:brand:uwhc", kv.store.has("myrx:brand:uwhc") && JSON.parse(kv.store.get("myrx:brand:uwhc")).slug === "uwhc");
}
// the seed script's body: type / demo / updatedFrom are honored on a fresh key
r = await call({ admin_pw: TEST_MASTER, action: "brand.put", slug: "aurora", name: "Aurora", brand: null, type: "pharmacy", demo: true, updatedFrom: "seed" });
check("brand.put seed body -> demo:true, updatedFrom:seed", r.status === 200 && r.out.doc.demo === true && r.out.doc.updatedFrom === "seed" && r.out.doc.type === "pharmacy", JSON.stringify(r.out));
r = await call({ admin_pw: TEST_MASTER, action: "brand.put", slug: "seedx", name: "X", brand: null, type: "Bad Type!", demo: "yes", updatedFrom: "build" });
check("brand.put ill-typed seed fields fall back (type pharmacy, demo false, admin)", r.status === 200 && r.out.doc.type === "pharmacy" && r.out.doc.demo === false && r.out.doc.updatedFrom === "admin", JSON.stringify(r.out));
kv.store.delete("myrx:brand:seedx");
// ...and the admin page's body (no such fields) preserves them from the existing doc
kv.store.set("myrx:brand:aurora", JSON.stringify({ v: 1, slug: "aurora", name: "Aurora", type: "pharmacy", demo: true, brand: null, updatedAt: "2026-01-01T00:00:00.000Z", updatedFrom: "seed" }));
r = await call({ admin_pw: TEST_MASTER, action: "brand.put", slug: "aurora", name: "Aurora Pharmacy", brand: { colors: { secondary: "#ABCDEF" } } });
check("brand.put preserves demo:true from existing doc", r.status === 200 && r.out.doc.demo === true && r.out.doc.updatedFrom === "admin" && r.out.doc.name === "Aurora Pharmacy");
r = await call({ admin_pw: TEST_MASTER, action: "brand.put", slug: "aurora", name: "Aurora Pharmacy", brand: null });
check("brand.put brand:null (revert to stock) -> 200 brand null", r.status === 200 && r.out.doc.brand === null && r.out.doc.demo === true);
r = await call({ brand_get: "uwhc" }); check("brand_get after put -> found:true with the doc", r.status === 200 && r.out.found === true && r.out.doc.name === "UW Health" && r.out.doc.brand.colors.primary === "#0f2b5b");
kv.store.set("myrx:brand:zeta", JSON.stringify({ v: 1, slug: "zeta", name: "Alpha Pharmacy", type: "pharmacy", demo: false, brand: null, updatedAt: "2026-01-01T00:00:00.000Z", updatedFrom: "seed" }));
kv.store.set("myrx:pws", "{}"); kv.store.set("pricing_data.json", "{}"); kv.store.set("myrx:brand:broken", "not json{");
kv.get = (function (orig) { return async function (k, o) { try { return await orig.call(this, k, o); } catch { return null; } }; })(kv.get); // Workers KV returns null for unparseable type:"json"
r = await call({ admin_pw: TEST_MASTER, action: "brands.list" });
check("brands.list returns only myrx:brand:* docs sorted by name", r.status === 200 && r.out.clients.map((c) => c.slug).join(",") === "zeta,aurora,uwhc", r.out && JSON.stringify(r.out.clients && r.out.clients.map((c) => c.slug)));
check("  brands.list never includes foreign keys", !(r.out.clients || []).some((c) => !c.slug));

// pws.get / pws.put
kv.store.delete("myrx:pws");
r = await call({ admin_pw: TEST_MASTER, action: "pws.get" }); check("pws.get unseeded -> 404 not seeded", r.status === 404 && r.out.error === "not seeded");
r = await call({ admin_pw: TEST_MASTER, action: "pws.put", enc: { salt: "abc", iv: "abc" } }); check("pws.put missing data -> 422", r.status === 422 && r.out.path === "enc.data");
r = await call({ admin_pw: TEST_MASTER, action: "pws.put", enc: { salt: "abc", iv: "abc", data: "not base64!" } }); check("pws.put non-base64 -> 422", r.status === 422 && r.out.path === "enc.data");
r = await call({ admin_pw: TEST_MASTER, action: "pws.put", enc: { salt: "abc", iv: "abc", data: "abc", extra: 1 } }); check("pws.put unknown key -> 422", r.status === 422 && r.out.path === "enc.extra");
r = await call({ admin_pw: TEST_MASTER, action: "pws.put", enc: { salt: "abcd", iv: "abcd", data: "A".repeat(100000) } }); check("pws.put > 100000 chars -> 413", r.status === 413);
r = await call({ admin_pw: TEST_MASTER, action: "pws.put", enc: "x" }); check("pws.put enc not object -> 422", r.status === 422 && r.out.path === "enc");
const vault = await encryptJSON({ v: 1, updatedAt: "x", passwords: { uwhc: "fake-partner-pw" } }, TEST_MASTER);
r = await call({ admin_pw: TEST_MASTER, action: "pws.put", enc: vault }); check("pws.put valid -> {ok, updatedAt}", r.status === 200 && r.out.ok && typeof r.out.updatedAt === "string");
const stored = JSON.parse(kv.store.get("myrx:pws"));
check("  stored as {v:1, updatedAt, enc} ciphertext only", stored.v === 1 && stored.enc.data === vault.data && !JSON.stringify(stored).includes("fake-partner-pw"));
r = await call({ admin_pw: TEST_MASTER, action: "pws.get" }); check("pws.get -> enc exactly as stored", r.status === 200 && r.out.ok && r.out.enc.salt === vault.salt && r.out.enc.iv === vault.iv && r.out.enc.data === vault.data && r.out.updatedAt === stored.updatedAt);
check("  pws.get response carries no plaintext", !JSON.stringify(r.out).includes("fake-partner-pw"));
r = await call({ admin_pw: "wrong", action: "pws.get" }, { ip: freshIp() }); check("pws.get without master -> 403", r.status === 403);
r = await call({ admin_pw: "wrong", action: "pws.put", enc: vault }, { ip: freshIp() }); check("pws.put without master -> 403", r.status === 403);

// ---------------------------------------------------------------- part 3
console.log("shared auth surface (feed_pw / report_pw / secret / lockout keys)");
const TEST_REPORT_PW = "report-pw-" + Math.random().toString(36).slice(2); // stands in for REPORT_PW (the Avalon Assist master; NOT the MyRxCard master)
const TEST_SYNC_SECRET = "sync-" + Math.random().toString(36).slice(2);
const env2 = { AAPS_DATA: kv, XANO_META_TOKEN: "t", XANO_CONTENT_URL: "https://xano.test/api:meta/workspace/1/table/12/content",
  REPORT_PW: TEST_REPORT_PW, CLIENT_PWS: JSON.stringify({ acme: { pw: "client-acme-pw", label: "Acme" } }), SYNC_SECRET: TEST_SYNC_SECRET };
const call2 = async (body, opts = {}) => {
  const headers = { "content-type": "application/json", "cf-connecting-ip": opts.ip || "203.0.113.7" };
  const req = new Request("https://myrxcard-sync.example/", { method: "POST", headers, body: JSON.stringify(body) });
  const res = await worker.fetch(req, opts.env || env2);
  let out = null; try { out = await res.json(); } catch {}
  return { status: res.status, out };
};
// feed_pw with site "" is the master check — same counter as admin_pw
{
  const ip = freshIp();
  let last;
  for (let i = 0; i < 5; i++) last = await call2({ feed_pw: "guess-" + i, site: "" }, { ip });
  check("feed_pw site '' wrong -> 403", last.status === 403 && last.out.error === "bad password");
  r = await call2({ feed_pw: TEST_MASTER, site: "" }, { ip }); check("feed_pw site '' locked after 5 -> 429", r.status === 429 && r.out.error === "locked");
  r = await call({ admin_pw: TEST_MASTER, action: "ping" }, { ip }); check("  ...and admin_pw from the same IP is locked too (one master surface)", r.status === 429);
  r = await call2({ report_pw: TEST_REPORT_PW }, { ip }); check("  ...but report_pw from the same IP is NOT (scope \"aa\", a different master)", r.status === 200, `status ${r.status}`);
  r = await call2({ feed_pw: "x", site: "uwhc" }, { ip }); check("  partner-site feed guesses have their own counter (403 not 429)", r.status === 403);
}
{
  const ip = freshIp();
  for (let i = 0; i < 5; i++) await call2({ feed_pw: "guess-" + i, site: "uwhc" }, { ip });
  r = await call2({ feed_pw: "partner-pw-not-master", site: "uwhc" }, { ip }); check("5 partner-site failures lock that site's counter", r.status === 429);
  r = await call({ admin_pw: TEST_MASTER, action: "ping" }, { ip }); check("  ...without touching the master counter", r.status === 200);
}
r = await call2({ feed_pw: TEST_MASTER, site: "" }, { ip: freshIp() }); check("feed_pw with the master -> feed served", r.status === 200 && r.out.ok && Array.isArray(r.out.events), JSON.stringify(r.out).slice(0, 120));
// report_pw: constant-time compares, same lockout scope
r = await call2({ report_pw: TEST_REPORT_PW }, { ip: freshIp() }); check("report_pw with REPORT_PW -> master view", r.status === 200 && r.out.ok && Array.isArray(r.out.cases) && !r.out.client, JSON.stringify(r.out).slice(0, 120));
r = await call2({ report_pw: "client-acme-pw" }, { ip: freshIp() }); check("report_pw with a CLIENT_PWS password -> client view", r.status === 200 && r.out.client && r.out.client.slug === "acme", JSON.stringify(r.out).slice(0, 120));
r = await call2({ report_pw: "client-acme-pw", dataset: "pricing" }, { ip: freshIp() }); check("client password cannot read the pricing dataset", r.status === 403);
r = await call2({ report_pw: 12345 }, { ip: freshIp() }); check("report_pw non-string -> 403", r.status === 403);
r = await call2({ report_pw: TEST_REPORT_PW }, { ip: freshIp(), env: { ...env2, REPORT_PW: "" } }); check("empty REPORT_PW secret never matches", r.status === 403);
r = await call2({ report_pw: TEST_REPORT_PW.slice(0, -1) }, { ip: freshIp() }); check("report_pw off by one char -> 403", r.status === 403);
{
  const ip = freshIp();
  for (let i = 0; i < 5; i++) await call2({ report_pw: "guess-" + i }, { ip });
  r = await call2({ report_pw: TEST_REPORT_PW }, { ip }); check("5 report_pw failures -> 429 even with the right password", r.status === 429 && r.out.retryAfter > 0);
  r = await call({ admin_pw: TEST_MASTER, action: "ping" }, { ip }); check("  ...without locking admin_pw for that IP (MyRx master has its own counter)", r.status === 200, `status ${r.status}`);
  r = await call2({ aa_admin_pw: TEST_REPORT_PW, action: "ping" }, { ip }); check("  ...while aa_admin_pw IS locked (shares scope \"aa\" with report_pw)", r.status === 429, `status ${r.status}`);
}
{
  const ip = freshIp();
  for (let i = 0; i < 4; i++) await call2({ report_pw: "guess-" + i }, { ip });
  r = await call2({ report_pw: TEST_REPORT_PW }, { ip }); check("4 report_pw failures then success -> 200 and reset", r.status === 200);
  for (let i = 0; i < 4; i++) await call2({ report_pw: "again-" + i }, { ip });
  r = await call2({ report_pw: TEST_REPORT_PW }, { ip }); check("  reset: 4 more still not locked", r.status === 200);
}
// SYNC_SECRET: constant-time, then the existing rows[] contract
r = await call2({ secret: "nope", rows: [] }, { ip: freshIp() }); check("wrong SYNC_SECRET -> 403 bad secret", r.status === 403 && r.out.error === "bad secret");
r = await call2({ secret: { toString: () => TEST_SYNC_SECRET }, rows: [] }, { ip: freshIp() }); check("non-string secret -> 403", r.status === 403);
r = await call2({ secret: TEST_SYNC_SECRET, rows: [] }, { ip: freshIp() }); check("right SYNC_SECRET -> reaches the rows[] check (400)", r.status === 400 && /rows/.test(r.out.error));
r = await call2({ secret: TEST_SYNC_SECRET, rows: [] }, { ip: freshIp(), env: { ...env2, SYNC_SECRET: "" } }); check("unset SYNC_SECRET never matches", r.status === 403);
// IPv6: one counter per /64, whatever the interface id
{
  const a = "2001:db8:abcd:1234::1", b = "2001:DB8:abcd:1234:ffff:0:0:2", other = "2001:db8:abcd:1235::1";
  for (let i = 0; i < 3; i++) await call2({ report_pw: "g" + i }, { ip: a });
  for (let i = 0; i < 2; i++) await call2({ report_pw: "h" + i }, { ip: b });
  r = await call2({ report_pw: TEST_REPORT_PW }, { ip: a }); check("IPv6: 3 failures from ::1 + 2 from ::2 in one /64 -> locked", r.status === 429);
  r = await call2({ report_pw: TEST_REPORT_PW }, { ip: "2001:0db8:abcd:1234:dead:beef:0:9" }); check("  every address in that /64 is locked", r.status === 429);
  r = await call2({ report_pw: TEST_REPORT_PW }, { ip: other }); check("  the neighbouring /64 is not", r.status === 200);
}
// eviction: a flood of new keys must NOT flush an active lock (the old clear() did)
{
  const victim = freshIp();
  for (let i = 0; i < 5; i++) await call2({ report_pw: "g" + i }, { ip: victim });
  r = await call2({ report_pw: TEST_REPORT_PW }, { ip: victim }); check("eviction setup: victim locked", r.status === 429);
  for (let i = 0; i < 2100; i++) await call2({ report_pw: "flood" }, { ip: `10.${Math.floor(i / 250)}.0.${i % 250}` });
  r = await call2({ report_pw: TEST_REPORT_PW }, { ip: victim }); check("2100 fresh addresses failing once each leave the victim's lock in place", r.status === 429, `status ${r.status}`);
}
// optional Rate Limiting binding: consulted before the PBKDF2, key = network|scope
{
  const seen = [];
  const rl = (success) => ({ limit: async ({ key }) => { seen.push(key); return { success }; } });
  r = await call({ admin_pw: TEST_MASTER, action: "ping" }, { ip: freshIp(), env: { AAPS_DATA: kv, ADMIN_RL: rl(false) } });
  check("ADMIN_RL says no -> 429 locked, retryAfter 60", r.status === 429 && r.out.error === "locked" && r.out.retryAfter === 60, JSON.stringify(r.out));
  check("  limiter key is network|master", seen.length === 1 && /^[0-9.]+\|master$/.test(seen[0]), seen[0]);
  r = await call({ admin_pw: TEST_MASTER, action: "ping" }, { ip: freshIp(), env: { AAPS_DATA: kv, ADMIN_RL: rl(true) } });
  check("ADMIN_RL says yes -> normal auth", r.status === 200);
  r = await call({ admin_pw: TEST_MASTER, action: "ping" }, { ip: freshIp(), env: { AAPS_DATA: kv, ADMIN_RL: { limit: async () => { throw new Error("boom"); } } } });
  check("ADMIN_RL failure never blocks auth (in-memory lockout still applies)", r.status === 200);
}

// ---------------------------------------------------------------- part 4
console.log("validateBrandAA (Avalon Assist profile)");
const aaBrand = () => ({
  name: "Acme", logo: SVG_MIN, logoDark: PNG_1PX, logoHeight: 40, tagline: "Assist report", gateHeading: "Welcome, Acme", poweredBy: true,
  colors: { navy: "#0F2B5B", teal: "#1C80B8", green: "#8fa93e", blue: "#abb9d4", dark: { navy: "#7fb0de", teal: "#4ba8dc", green: "#afc96a", blue: "#8fa0c4" } },
  fonts: { google: "family=Lato:wght@400;700", body: "Lato, sans-serif", heading: "Lato, sans-serif" },
  headings: { transform: "uppercase", weight: 700, letterSpacing: "0.02em" },
  layout: { radius: "8px", density: "compact" },
});
const aaWith = (mut) => { const b = aaBrand(); mut(b); return b; };
const aaOk = (name, b) => { const e = validateBrandAA(b); check(name, e === null, e && `${e.path}: ${e.reason}`); return b; };
const aaErr = (name, b, path, status = 422) => { const e = validateBrandAA(b); check(name, e && e.path === path && e.status === status, e ? `got ${e.path} (${e.status}): ${e.reason}` : "validated OK"); };
{ const b = aaOk("AA full brand valid", aaBrand()); check("  AA colors lowercased in place", b.colors.navy === "#0f2b5b" && b.colors.teal === "#1c80b8"); }
aaOk("AA empty object valid", {});
aaOk("AA colors-only brand", { colors: { navy: "#315280" } });
{ const b = aaWith((x) => { x.gateHeading = "Welcome"; }); check("AA gateHeading control chars stripped", validateBrandAA(b) === null && b.gateHeading === "Welcome"); }
aaErr("AA gateHeading with <", aaWith((b) => { b.gateHeading = "<b>hi</b>"; }), "brand.gateHeading");
aaErr("AA gateHeading too long", aaWith((b) => { b.gateHeading = "g".repeat(81); }), "brand.gateHeading");
aaErr("AA rejects myrx color key primary", aaWith((b) => { b.colors.primary = "#000000"; }), "brand.colors.primary");
aaErr("AA rejects dark.accentBright", aaWith((b) => { b.colors.dark.accentBright = "#000000"; }), "brand.colors.dark.accentBright");
aaErr("AA rejects headings.gate (unknown key)", aaWith((b) => { b.headings.gate = "x"; }), "brand.headings.gate");
aaErr("AA rejects headings.tabs", aaWith((b) => { b.headings.tabs = { util: "x" }; }), "brand.headings.tabs");
aaErr("AA rejects layout.header", aaWith((b) => { b.layout.header = "title-first"; }), "brand.layout.header");
aaErr("AA rejects fonts.mono", aaWith((b) => { b.fonts.mono = "monospace"; }), "brand.fonts.mono");
aaErr("AA bad navy hex", aaWith((b) => { b.colors.navy = "#12"; }), "brand.colors.navy");
aaErr("AA dark.blue named color", aaWith((b) => { b.colors.dark.blue = "blue"; }), "brand.colors.dark.blue");
aaErr("AA transform enum", aaWith((b) => { b.headings.transform = "lowercase"; }), "brand.headings.transform");
aaErr("AA density enum", aaWith((b) => { b.layout.density = "cozy"; }), "brand.layout.density");
aaErr("AA radius 25px", aaWith((b) => { b.layout.radius = "25px"; }), "brand.layout.radius");
aaErr("AA oversize logo -> 413", aaWith((b) => { b.logoDark = "data:image/png;base64," + "A".repeat(200001); }), "brand.logoDark", 413);
aaErr("AA unknown root key", aaWith((b) => { b.type = "pharmacy"; }), "brand.type");
// the two profiles do not leak into each other
check("myrx validateBrand still rejects navy", (() => { const e = validateBrand({ colors: { navy: "#315280" } }); return e && e.path === "brand.colors.navy"; })());
check("myrx validateBrand still accepts headings.gate", validateBrand({ headings: { gate: "Hi" } }) === null);
check("myrx validateBrand rejects gateHeading", (() => { const e = validateBrand({ gateHeading: "Hi" }); return e && e.path === "brand.gateHeading"; })());

console.log("reports.avalonsaves.com routes (aa_brand_get / aa_admin_pw / report_pw clients)");
const AA_SALT = "member-salt-" + Math.random().toString(36).slice(2);
const AA_CLIENT_PWS = { vault: { pw: "client-vault-pw", label: "Vault" }, marpai: { pw: "client-marpai-pw", label: "Marpai" } };
const envA = { AAPS_DATA: kv, XANO_META_TOKEN: "t", XANO_CONTENT_URL: "https://xano.test/api:meta/workspace/1/table/12/content",
  REPORT_PW: TEST_REPORT_PW, CLIENT_PWS: JSON.stringify(AA_CLIENT_PWS), MEMBER_SALT: AA_SALT, SYNC_SECRET: TEST_SYNC_SECRET };
const aa = (body, opts = {}) => call2(body, { ip: opts.ip || freshIp(), env: opts.env || envA });
const admin = (action, extra = {}, opts = {}) => aa({ aa_admin_pw: TEST_REPORT_PW, action, ...extra }, opts);
const hasPw = (o) => /"pw"/.test(JSON.stringify(o)) || JSON.stringify(o).includes("client-vault-pw") || JSON.stringify(o).includes("client-marpai-pw");
const GEN_PW_RE = /^[a-hj-kmnp-z2-9]{4}-[a-hj-kmnp-z2-9]{4}-[a-hj-kmnp-z2-9]{4}$/;
const CLIENT_KEYS = new Set(["case_key","assist_number","group_number","source","status","closed_reason","medication_name","ndc","medication_type","month","created_date","closed_date","awp","aa_price","aa_savings","avalon_savings","member_ref","member_age","client_name"]);
async function hmac16(secret, msg) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return Buffer.from(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg))).subarray(0, 8).toString("hex");
}

// aa_brand_get (public)
r = await aa({ aa_brand_get: "vault" }); check("aa_brand_get unseeded -> found:false", r.status === 200 && r.out.ok && r.out.found === false && r.out.doc === null);
r = await aa({ aa_brand_get: "VAULT" }); check("aa_brand_get lowercases slug", r.status === 200 && r.out.found === false);
r = await aa({ aa_brand_get: "bad slug!" }); check("aa_brand_get bad slug -> 400 bad site", r.status === 400 && r.out.error === "bad site");
r = await aa({ aa_brand_get: "" }); check("aa_brand_get empty slug -> 400", r.status === 400);
r = await aa({ aa_brand_get: "vault" }, { env: { ...envA, AAPS_DATA: undefined } }); check("aa_brand_get without KV -> 500 KV not bound", r.status === 500 && r.out.error === "KV not bound");
r = await aa({ aa_brand_get: "uwhc" }); check("aa_brand_get never sees myrx:brand:* docs (uwhc exists there)", r.status === 200 && r.out.found === false);
kv.store.set("aa:brand:leaky", JSON.stringify({ v: 1, slug: "leaky", name: "Leaky", demo: true, demoBadge: false, brand: { colors: { navy: "#000000" } }, pw: "should-not-leak", from: "vault", scale: 0.5, updatedAt: "2026-01-01T00:00:00.000Z", updatedFrom: "seed" }));
r = await aa({ aa_brand_get: "leaky" });
check("aa_brand_get projects the doc (pw/from/scale stripped, flags kept)", r.status === 200 && r.out.found === true && r.out.doc.pw === undefined && r.out.doc.from === undefined && r.out.doc.scale === undefined
  && r.out.doc.demo === true && r.out.doc.demoBadge === false && r.out.doc.brand.colors.navy === "#000000" && r.out.doc.updatedFrom === "seed" && !JSON.stringify(r.out).includes("should-not-leak"), JSON.stringify(r.out));
r = await call({ brand_get: "leaky" }); check("myrx brand_get never sees aa:brand:* docs", r.status === 200 && r.out.found === false);
kv.store.delete("aa:brand:leaky");

// auth + scope
r = await aa({ aa_admin_pw: "wrong", action: "ping" }); check("aa_admin_pw wrong -> 403 bad password", r.status === 403 && r.out.error === "bad password");
r = await aa({ aa_admin_pw: TEST_MASTER, action: "ping" }); check("the MyRx master is not the AA master -> 403", r.status === 403);
r = await aa({ aa_admin_pw: "client-vault-pw", action: "ping" }); check("a client password is not the AA master -> 403", r.status === 403);
r = await aa({ aa_admin_pw: 12345, action: "ping" }); check("aa_admin_pw non-string -> 403", r.status === 403);
r = await aa({ aa_admin_pw: TEST_REPORT_PW, action: "ping" }, { env: { ...envA, REPORT_PW: "" } }); check("empty REPORT_PW never matches", r.status === 403);
r = await admin("ping"); check("ping -> {ok, kv:true, vault:'absent'}", r.status === 200 && r.out.ok === true && r.out.kv === true && r.out.vault === "absent", JSON.stringify(r.out));
r = await admin("ping", {}, { env: { ...envA, AAPS_DATA: undefined } }); check("ping without KV -> kv:false vault:absent", r.status === 200 && r.out.kv === false && r.out.vault === "absent");
r = await admin("clients.list", {}, { env: { ...envA, AAPS_DATA: undefined } }); check("clients.list without KV -> 500", r.status === 500 && r.out.error === "KV not bound");
r = await admin("nope"); check("unknown action -> 400 bad action", r.status === 400 && r.out.error === "bad action");
r = await admin(""); check("missing action -> 400 bad action", r.status === 400);
{
  const ip = freshIp();
  let last;
  for (let i = 0; i < 5; i++) last = await aa({ aa_admin_pw: "guess-" + i, action: "ping" }, { ip });
  check("5 aa_admin_pw failures -> 403 then", last.status === 403);
  r = await aa({ aa_admin_pw: TEST_REPORT_PW, action: "ping" }, { ip }); check("  6th aa_admin_pw -> 429 locked even with the right password", r.status === 429 && r.out.error === "locked" && r.out.retryAfter > 0);
  r = await aa({ report_pw: TEST_REPORT_PW }, { ip }); check("  report_pw from that IP is locked too (same scope \"aa\")", r.status === 429);
  r = await call({ admin_pw: TEST_MASTER, action: "ping" }, { ip }); check("  MyRx admin_pw from that IP is NOT locked", r.status === 200, `status ${r.status}`);
  r = await call2({ feed_pw: TEST_MASTER, site: "" }, { ip }); check("  MyRx feed_pw site '' from that IP is NOT locked", r.status === 200, `status ${r.status}`);
}
{
  const ip = freshIp();
  for (let i = 0; i < 5; i++) await call({ admin_pw: "guess-" + i, action: "ping" }, { ip });
  r = await call({ admin_pw: TEST_MASTER, action: "ping" }, { ip }); check("5 MyRx admin_pw failures lock admin_pw", r.status === 429);
  r = await aa({ aa_admin_pw: TEST_REPORT_PW, action: "ping" }, { ip }); check("  ...but not aa_admin_pw from the same IP", r.status === 200, `status ${r.status}`);
}
// a CLIENT password proving itself under "aa" never clears the counter that protects the master
{
  const ip = freshIp();
  for (let i = 0; i < 4; i++) await aa({ aa_admin_pw: "guess-" + i, action: "ping" }, { ip });
  r = await aa({ report_pw: "client-vault-pw" }, { ip }); check("4 aa_admin_pw failures, then a CLIENT password unlocks the read route", r.status === 200 && r.out.client && r.out.client.slug === "vault", `status ${r.status}`);
  r = await aa({ aa_admin_pw: "guess-5", action: "ping" }, { ip }); check("  the client success did NOT reset the counter: the 5th failure locks", r.status === 403);
  r = await aa({ aa_admin_pw: TEST_REPORT_PW, action: "ping" }, { ip }); check("  -> 429 (a handed-out demo password cannot launder guesses at the master)", r.status === 429 && r.out.error === "locked", `status ${r.status}`);
}
{
  const ip = freshIp();
  for (let i = 0; i < 4; i++) await aa({ aa_admin_pw: "guess-" + i, action: "ping" }, { ip });
  r = await aa({ aa_admin_pw: TEST_REPORT_PW, action: "ping" }, { ip }); check("4 aa_admin_pw failures then the MASTER -> 200 and reset", r.status === 200);
  for (let i = 0; i < 4; i++) await aa({ aa_admin_pw: "again-" + i, action: "ping" }, { ip });
  r = await aa({ report_pw: TEST_REPORT_PW }, { ip }); check("  reset: 4 more still not locked (report_pw with the master, same scope)", r.status === 200, `status ${r.status}`);
}
{
  const seen = [];
  r = await admin("ping", {}, { env: { ...envA, ADMIN_RL: { limit: async ({ key }) => { seen.push(key); return { success: true }; } } } });
  check("ADMIN_RL key for aa_admin_pw is network|aa", r.status === 200 && seen.length === 1 && /^[0-9.]+\|aa$/.test(seen[0]), seen[0]);
}

// before the seed: the roster is CLIENT_PWS (no passwords in clients.list)
r = await admin("clients.list");
check("clients.list before seed -> vault:false, CLIENT_PWS roster sorted by label", r.status === 200 && r.out.ok && r.out.vault === false && r.out.updatedAt === null && r.out.clients.map((c) => c.slug).join(",") === "marpai,vault", JSON.stringify(r.out));
check("  entries: label, demo null, demoBadge true, doc null, NO pw", r.out.clients.every((c) => typeof c.label === "string" && c.demo === null && c.demoBadge === true && c.doc === null) && !hasPw(r.out));
r = await admin("client.reveal", { slug: "vault" }); check("client.reveal before seed -> the CLIENT_PWS password", r.status === 200 && r.out.ok && r.out.slug === "vault" && r.out.pw === "client-vault-pw");
r = await admin("client.reveal", { slug: "nobody" }); check("client.reveal unknown -> 404 unknown client", r.status === 404 && r.out.error === "unknown client");
r = await admin("client.reveal", { slug: "constructor" }); check("client.reveal 'constructor' -> 404 (own-property lookup)", r.status === 404);
r = await admin("client.reveal", { slug: "Bad Slug" }); check("client.reveal bad slug -> 404", r.status === 404);
r = await admin("client.delete", { slug: "nobody" }); check("client.delete unknown -> 404", r.status === 404 && r.out.error === "unknown client");
r = await admin("clients.reseal", { oldPw: "whatever" }); check("clients.reseal with no vault -> 404 not seeded", r.status === 404);
r = await admin("clients.reseal", {}); check("clients.reseal without oldPw -> 422", r.status === 422 && r.out.path === "oldPw");
r = await aa({ report_pw: "client-vault-pw" });
check("report_pw before seed: CLIENT_PWS client view, demo:false", r.status === 200 && r.out.client && r.out.client.slug === "vault" && r.out.client.label === "Vault" && r.out.client.demo === false && r.out.client.demoBadge === true && r.out.cases.length === 2, JSON.stringify(r.out).slice(0, 200));
const realRow = r.out && r.out.cases && r.out.cases.find((c) => c.case_key === "c1");
check("  real client rows: unscaled, assist/group numbers kept, exact age, only CLIENT_FIELDS + client_name",
  realRow && realRow.awp === 100 && realRow.assist_number === "AA-1001" && realRow.group_number === "G77" && realRow.member_age === 47 && realRow.client_name === "Vault"
  && realRow.avalon_fee === undefined && realRow.myrxcard_pricing === undefined && realRow.tpa === undefined && Object.keys(realRow).every((k) => CLIENT_KEYS.has(k)), JSON.stringify(realRow));
check("  source collapsed (MedsDirect -> International)", realRow && realRow.source === "International");
check("  member_ref = hmac16(MEMBER_SALT, 'vault|token')", realRow && realRow.member_ref === await hmac16(AA_SALT, "vault|abcd1234abcd1234"), realRow && realRow.member_ref);
const realRef = realRow && realRow.member_ref;

// seed
r = await admin("clients.seed");
check("clients.seed -> sealed:true, count 2, slugs sorted", r.status === 200 && r.out.ok && r.out.sealed === true && r.out.count === 2 && r.out.slugs.join(",") === "marpai,vault", JSON.stringify(r.out));
{
  const raw = kv.store.get("aa:clients"); let rec = null; try { rec = JSON.parse(raw); } catch {}
  check("  aa:clients stored as {v:1, updatedAt, enc:{salt, iv, data}} ciphertext only", rec && rec.v === 1 && typeof rec.updatedAt === "string" && rec.enc && Buffer.from(rec.enc.salt, "base64").length === 16 && Buffer.from(rec.enc.iv, "base64").length === 12 && !raw.includes("client-vault-pw") && !raw.includes("Vault"));
  check("  stock docs written for both clients", kv.store.has("aa:brand:vault") && kv.store.has("aa:brand:marpai") && JSON.parse(kv.store.get("aa:brand:vault")).updatedFrom === "seed");
  check("  no myrx key touched by the seed", !kv.store.has("myrx:brand:vault") && !kv.store.has("myrx:brand:marpai"));
  // the vault opens with the same PBKDF2/AES-GCM scheme the harness uses (interop with tools/store.mjs)
  const enc = new TextEncoder(), b64 = (x) => Buffer.from(x, "base64");
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(TEST_REPORT_PW), "PBKDF2", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: b64(rec.enc.salt), iterations: rec.enc.iter === 100000 ? 100000 : 310000, hash: "SHA-256" }, baseKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  let pt = null; try { pt = JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(rec.enc.iv) }, aesKey, b64(rec.enc.data)))); } catch {}
  check("  vault opens under REPORT_PW with WebCrypto PBKDF2-310k/AES-GCM and holds {v:1, clients}", pt && pt.v === 1 && pt.clients && pt.clients.vault && pt.clients.vault.pw === "client-vault-pw" && pt.clients.marpai.label === "Marpai", JSON.stringify(pt && Object.keys(pt)));
}
r = await admin("ping"); check("ping after seed -> vault:'ok'", r.status === 200 && r.out.vault === "ok");
r = await aa({ aa_brand_get: "vault" }); check("aa_brand_get vault after seed -> found:true stock doc, no pw", r.status === 200 && r.out.found === true && r.out.doc.name === "Vault" && r.out.doc.demo === false && r.out.doc.demoBadge === true && r.out.doc.brand === null && r.out.doc.updatedFrom === "seed" && !hasPw(r.out), JSON.stringify(r.out));
r = await admin("clients.seed"); check("second seed -> sealed:false (idempotent), count 2", r.status === 200 && r.out.sealed === false && r.out.count === 2);
{
  const before = kv.store.get("aa:clients");
  r = await admin("clients.seed", { force: true }); check("seed force while the vault is OPEN -> 409 force only recovers a sealed vault", r.status === 409 && r.out.error === "force only recovers a sealed vault" && r.out.hint === "vault is ok", JSON.stringify(r.out));
  check("  ciphertext untouched", kv.store.get("aa:clients") === before);
}
kv.store.delete("aa:brand:marpai");
r = await admin("clients.seed"); check("seed restores a missing doc without resealing", r.status === 200 && r.out.sealed === false && kv.store.has("aa:brand:marpai"));
r = await admin("clients.list");
check("clients.list after seed -> vault:true, updatedAt, docs attached, NO pw", r.status === 200 && r.out.vault === true && typeof r.out.updatedAt === "string" && r.out.clients.length === 2 && r.out.clients.every((c) => c.doc && c.doc.slug === c.slug) && !hasPw(r.out), JSON.stringify(r.out).slice(0, 300));
r = await admin("client.reveal", { slug: "vault" }); check("client.reveal after seed -> the vault's password (same as CLIENT_PWS)", r.status === 200 && r.out.pw === "client-vault-pw");
r = await aa({ report_pw: "client-vault-pw" }); check("report_pw after seed still unlocks the vault client", r.status === 200 && r.out.client && r.out.client.slug === "vault" && r.out.cases.length === 2);

// client.put: create a demo
r = await admin("client.put", { slug: "acme-demo", label: "Acme", demo: { from: "vault", scale: 0.5 }, regenPw: true });
check("client.put create demo -> 200 {client, doc}", r.status === 200 && r.out.ok && r.out.client.slug === "acme-demo" && r.out.client.label === "Acme" && r.out.client.demoBadge === true, JSON.stringify(r.out).slice(0, 300));
const demoPw1 = r.out && r.out.client && r.out.client.pw;
check("  generated password xxxx-xxxx-xxxx from the safe alphabet", GEN_PW_RE.test(demoPw1 || ""), demoPw1 && demoPw1.length);
check("  client.demo {from, scale}", r.out.client.demo && r.out.client.demo.from === "vault" && r.out.client.demo.scale === 0.5);
check("  doc: demo:true, demoBadge:true, brand null, updatedFrom admin, name = label", r.out.doc && r.out.doc.demo === true && r.out.doc.demoBadge === true && r.out.doc.brand === null && r.out.doc.updatedFrom === "admin" && r.out.doc.name === "Acme");
check("  doc stored under aa:brand:acme-demo", kv.store.has("aa:brand:acme-demo"));
r = await aa({ aa_brand_get: "acme-demo" }); check("  aa_brand_get for the demo -> public doc without from/scale/pw", r.status === 200 && r.out.found && r.out.doc.demo === true && r.out.doc.from === undefined && !hasPw(r.out));
r = await aa({ report_pw: demoPw1 });
check("report_pw with the demo password -> demo client view", r.status === 200 && r.out.client && r.out.client.slug === "acme-demo" && r.out.client.label === "Acme" && r.out.client.demo === true && r.out.client.demoBadge === true, JSON.stringify(r.out).slice(0, 200));
check("  response client carries only slug/label/demo/demoBadge", Object.keys(r.out.client).sort().join(",") === "demo,demoBadge,label,slug");
check("  demo clones only the source client's rows", r.out.cases.length === 2 && r.out.cases.every((c) => c.client_name === "Acme"));
{
  const d1 = r.out.cases.find((c) => c.case_key === "c1"), d2 = r.out.cases.find((c) => c.case_key === "c2");
  check("  dollar fields scaled x0.5 (2 dp)", d1 && d1.awp === 50 && d1.aa_price === 20 && d1.aa_savings === 30 && d1.avalon_savings === 27.5 && d2.awp === 16.67 && d2.aa_savings === 10.42, JSON.stringify(d1));
  check("  assist_number / group_number removed", d1 && d1.assist_number === undefined && d1.group_number === undefined && !("assist_number" in d1));
  check("  member_age -> bottom of its 5-year band (47 -> 45, 30 -> 30)", d1 && d1.member_age === 45 && d2.member_age === 30);
  check("  fee / supplier pricing / tpa never reach a demo", d1 && d1.avalon_fee === undefined && d1.myrxcard_pricing === undefined && d1.medsdirect_pricing === undefined && d1.tpa === undefined && Object.keys(d1).every((k) => CLIENT_KEYS.has(k)));
  check("  member_ref HMACed under the DEMO slug (16 hex, differs from the source client's token)", d1 && /^[0-9a-f]{16}$/.test(d1.member_ref) && d1.member_ref !== realRef && d1.member_ref === await hmac16(AA_SALT, "acme-demo|abcd1234abcd1234"), d1 && d1.member_ref);
  check("  empty member_ref stays empty", d2 && d2.member_ref === "");
  check("  source label never appears in demo rows", !JSON.stringify(r.out.cases).includes("Vault"));
}
r = await aa({ report_pw: demoPw1, dataset: "pricing" }); check("demo password cannot read the pricing dataset", r.status === 403);

// client.put validation
const put = (extra) => admin("client.put", extra);
r = await put({ slug: "Bad Slug", label: "x" }); check("client.put bad slug -> 400 path slug", r.status === 400 && r.out.error === "bad slug" && r.out.path === "slug");
for (const s of ["nash", "tools", "admin", "root", "index", "404", "assets"]) { r = await put({ slug: s, label: "x" }); if (!(r.status === 422 && r.out.error === "slug: reserved" && r.out.path === "slug")) { check(`reserved slug ${s}`, false, JSON.stringify(r.out)); break; } }
check("reserved slugs (nash, tools, admin, root, index, 404, assets) -> 422 slug: reserved", r.status === 422 && r.out.error === "slug: reserved");
r = await put({ slug: "newco" }); check("create without label -> 422 label: required", r.status === 422 && r.out.error === "label: required" && r.out.path === "label");
r = await put({ slug: "newco", label: "" }); check("create with empty label -> 422 label: required", r.status === 422 && r.out.error === "label: required");
r = await put({ slug: "newco", label: "New <Co>" }); check("label with <> -> 422 path label", r.status === 422 && r.out.path === "label" && r.out.error.startsWith("label: "));
r = await put({ slug: "newco", label: "x", pw: "short" }); check("pw too short -> 422 path pw", r.status === 422 && r.out.error === "pw: 8-128 printable characters, no spaces" && r.out.path === "pw");
r = await put({ slug: "newco", label: "x", pw: "has a space" }); check("pw with a space -> 422", r.status === 422 && r.out.path === "pw");
r = await put({ slug: "newco", label: "x", pw: "x".repeat(129) }); check("pw 129 chars -> 422", r.status === 422 && r.out.path === "pw");
r = await put({ slug: "newco", label: "x", pw: 12345678 }); check("pw non-string -> 422", r.status === 422 && r.out.path === "pw");
r = await put({ slug: "newco", label: "x", pw: TEST_REPORT_PW }); check("pw equal to REPORT_PW -> 422 must differ", r.status === 422 && r.out.error === "pw: must differ from the report password" && r.out.path === "pw");
r = await put({ slug: "newco", label: "x", pw: "client-vault-pw" }); check("pw used by another client -> 422 already used", r.status === 422 && r.out.error === "pw: already used by another client");
r = await put({ slug: "newco", label: "x", pw: demoPw1 }); check("pw equal to the demo's generated pw -> 422 already used", r.status === 422 && r.out.error === "pw: already used by another client");
check("  none of the rejected creates touched the vault or KV", !kv.store.has("aa:brand:newco"));
r = await put({ slug: "newco", label: "x", demo: "vault" }); check("demo not an object -> 422 demo", r.status === 422 && r.out.error === "demo: must be {from, scale}" && r.out.path === "demo");
r = await put({ slug: "newco", label: "x", demo: { from: "vault", scale: 1, extra: 1 } }); check("demo with an extra key -> 422 demo", r.status === 422 && r.out.path === "demo");
r = await put({ slug: "newco", label: "x", demo: { from: "nobody", scale: 1 } }); check("demo.from unknown -> 422 demo.from", r.status === 422 && r.out.error === "demo.from: unknown client" && r.out.path === "demo.from");
r = await put({ slug: "newco", label: "x", demo: { from: "acme-demo", scale: 1 } }); check("demo.from pointing at a demo -> 422 demo.from", r.status === 422 && r.out.path === "demo.from");
r = await put({ slug: "newco", label: "x", demo: { from: "vault", scale: 0.01 } }); check("demo.scale 0.01 -> 422 demo.scale", r.status === 422 && r.out.error === "demo.scale: must be a number from 0.05 to 20" && r.out.path === "demo.scale");
r = await put({ slug: "newco", label: "x", demo: { from: "vault", scale: 21 } }); check("demo.scale 21 -> 422", r.status === 422 && r.out.path === "demo.scale");
r = await put({ slug: "newco", label: "x", demo: { from: "vault", scale: "0.8" } }); check("demo.scale as a string -> 422", r.status === 422 && r.out.path === "demo.scale");
r = await put({ slug: "vault", demo: { from: "marpai", scale: 1 } }); check("demo on a real client -> 422 demo: only demo clients", r.status === 422 && r.out.error === "demo: only demo clients" && r.out.path === "demo");
r = await put({ slug: "newco", label: "x", demoBadge: "no" }); check("demoBadge non-boolean -> 422", r.status === 422 && r.out.error === "demoBadge: must be true or false" && r.out.path === "demoBadge");
r = await put({ slug: "newco", label: "x", brand: "x" }); check("brand string -> 422 brand", r.status === 422 && r.out.error === "brand: must be an object or null" && r.out.path === "brand");
r = await put({ slug: "newco", label: "x", brand: [] }); check("brand array -> 422 brand", r.status === 422 && r.out.path === "brand");
r = await put({ slug: "newco", label: "x", brand: { colors: { primary: "#000000" } } }); check("brand with myrx color key -> 422 brand.colors.primary", r.status === 422 && r.out.path === "brand.colors.primary" && r.out.error.startsWith("brand.colors.primary: "));
r = await put({ slug: "newco", label: "x", brand: { headings: { gate: "x" } } }); check("brand with headings.gate -> 422 unknown key", r.status === 422 && r.out.path === "brand.headings.gate");
r = await put({ slug: "newco", label: "x", brand: { logo: "data:image/png;base64," + "A".repeat(200001) } }); check("brand oversize logo -> 413 too large path brand.logo", r.status === 413 && r.out.error === "too large" && r.out.path === "brand.logo");
r = await put({ slug: "newco", label: "x", brand: { logo: "data:image/png;base64," + "A".repeat(199000), logoDark: "data:image/png;base64," + "A".repeat(199000), tagline: "x".repeat(80), extra: "A".repeat(210000) } }); check("brand doc > 600000 -> 413 path brand", r.status === 413 && r.out.path === "brand");
check("  still nothing created", !kv.store.has("aa:brand:newco"));

// client.put: create a REAL client with a custom password and a brand; regenPw is ignored on create
r = await put({ slug: "newco", label: "  NewCo  ", pw: "NewCo-Secret-9", regenPw: true, demoBadge: false, brand: { name: "ignored", gateHeading: "Welcome", colors: { navy: "#0F2B5B", dark: { teal: "#4BA8DC" } } } });
check("create real client with custom pw + brand -> 200", r.status === 200 && r.out.client.slug === "newco" && r.out.client.label === "NewCo" && r.out.client.pw === "NewCo-Secret-9" && r.out.client.demo === null && r.out.client.demoBadge === false, JSON.stringify(r.out).slice(0, 300));
check("  doc: brand validated (colors lowercased), brand.name = label, demo false", r.out.doc.brand.colors.navy === "#0f2b5b" && r.out.doc.brand.colors.dark.teal === "#4ba8dc" && r.out.doc.brand.name === "NewCo" && r.out.doc.brand.gateHeading === "Welcome" && r.out.doc.demo === false && r.out.doc.demoBadge === false);
r = await aa({ report_pw: "NewCo-Secret-9" }); check("  the custom password unlocks (vault is live in this isolate)", r.status === 200 && r.out.client.slug === "newco" && r.out.client.demo === false && r.out.cases.length === 0);
r = await admin("client.reveal", { slug: "newco" }); check("  reveal returns the custom password", r.status === 200 && r.out.pw === "NewCo-Secret-9");
r = await aa({ aa_brand_get: "newco" }); check("  aa_brand_get newco -> brand doc live", r.status === 200 && r.out.found && r.out.doc.brand.colors.navy === "#0f2b5b" && r.out.doc.demoBadge === false);

// a real client's slug is its CRM match key (clientOwns): whole-word, never a bare substring, never too short
r = await put({ slug: "a", label: "Ay" }); check("real client with a 1-char slug -> 422 slug: at least 3 characters", r.status === 422 && r.out.error === "slug: real client slugs need at least 3 characters" && r.out.path === "slug", JSON.stringify(r.out));
r = await put({ slug: "rx", label: "Rx" }); check("  2-char slug -> 422", r.status === 422 && r.out.path === "slug");
check("  nothing created", !kv.store.has("aa:brand:a") && !kv.store.has("aa:brand:rx"));
r = await put({ slug: "ul", label: "Ul", demo: { from: "vault", scale: 1 } }); check("  a DEMO may use a short slug (its rows come from demo.from)", r.status === 200 && r.out.client.demo.from === "vault");
r = await admin("client.delete", { slug: "ul" }); check("  (demo probe deleted)", r.status === 200);
r = await put({ slug: "pai", label: "Pai", pw: "Pai-Secret-99" }); check("real client 'pai' (inside 'Marpai') -> created", r.status === 200 && r.out.client.slug === "pai");
r = await aa({ report_pw: "Pai-Secret-99" }); check("  ...and sees ZERO rows: 'pai' inside 'Marpai TPA' is not a whole-word match", r.status === 200 && r.out.client.slug === "pai" && r.out.cases.length === 0, JSON.stringify(r.out.cases));
r = await put({ slug: "aul", label: "Aul", pw: "Aul-Secret-99" }); r = await aa({ report_pw: "Aul-Secret-99" }); check("  'aul' inside 'Vault Health' -> zero rows", r.status === 200 && r.out.cases.length === 0);
r = await put({ slug: "vault-health", label: "VH", pw: "VH-Secret-99" }); r = await aa({ report_pw: "VH-Secret-99" }); check("  'vault-health' owns 'Vault Health' (a hyphen stands for an optional space)", r.status === 200 && r.out.cases.length === 2 && r.out.cases.every((c) => c.client_name === "VH"), JSON.stringify(r.out.cases && r.out.cases.length));
r = await put({ slug: "vaulthealth", label: "VH2", pw: "VH2-Secret-99" }); r = await aa({ report_pw: "VH2-Secret-99" }); check("  'vaulthealth' does not own 'Vault Health' (whole word: the key has no separator)", r.status === 200 && r.out.cases.length === 0);
r = await aa({ report_pw: "client-marpai-pw" }); check("  'marpai' still owns 'Marpai TPA' (word followed by a space)", r.status === 200 && r.out.cases.length === 1 && r.out.cases[0].case_key === "c3");
for (const sl of ["pai", "aul", "vault-health", "vaulthealth"]) { r = await admin("client.delete", { slug: sl, force: true }); if (r.status !== 200) check(`cleanup ${sl}`, false, JSON.stringify(r.out)); }
r = await admin("clients.list"); check("  (scoping probes cleaned up)", r.out.clients.map((c) => c.slug).sort().join(",") === "acme-demo,marpai,newco,vault", JSON.stringify(r.out.clients && r.out.clients.map((c) => c.slug)));

// client.put: updates
r = await put({ slug: "acme-demo", label: "Acme Demo" });
check("update label only -> 200 without pw in the response", r.status === 200 && r.out.client.label === "Acme Demo" && r.out.client.pw === undefined && r.out.doc.name === "Acme Demo" && r.out.doc.brand === null, JSON.stringify(r.out).slice(0, 200));
r = await aa({ report_pw: demoPw1 }); check("  password unchanged by a label edit; rows relabeled", r.status === 200 && r.out.client.label === "Acme Demo" && r.out.cases[0].client_name === "Acme Demo");
r = await put({ slug: "newco", brand: { tagline: "Savings report" } });
check("update brand only -> doc rewritten, vault untouched (label kept, brand.name = label)", r.status === 200 && r.out.client.pw === undefined && r.out.doc.brand.tagline === "Savings report" && r.out.doc.brand.name === "NewCo" && r.out.doc.brand.colors === undefined && r.out.doc.demoBadge === false);
r = await put({ slug: "newco", label: "NewCo Inc" });
check("label change updates the kept brand's name", r.status === 200 && r.out.doc.brand.tagline === "Savings report" && r.out.doc.brand.name === "NewCo Inc");
r = await put({ slug: "newco", brand: null }); check("brand:null -> stock look (doc.brand null)", r.status === 200 && r.out.doc.brand === null);
r = await put({ slug: "acme-demo", demoBadge: false }); check("demoBadge:false on the demo -> 200", r.status === 200 && r.out.client.demoBadge === false && r.out.doc.demoBadge === false);
r = await admin("clients.list"); check("  clients.list shows demoBadge false + demo {from, scale}", r.out.clients.find((c) => c.slug === "acme-demo").demoBadge === false && r.out.clients.find((c) => c.slug === "acme-demo").demo.from === "vault" && !hasPw(r.out));
r = await aa({ aa_brand_get: "acme-demo" }); check("  aa_brand_get doc.demoBadge false", r.out.doc.demoBadge === false);
r = await aa({ report_pw: demoPw1 }); check("  report_pw client.demoBadge false", r.status === 200 && r.out.client.demoBadge === false && r.out.client.demo === true);
r = await put({ slug: "acme-demo", demo: { from: "marpai", scale: 2.0004 } });
check("demo re-pointed at marpai, scale rounded to 3 dp", r.status === 200 && r.out.client.demo.from === "marpai" && r.out.client.demo.scale === 2, JSON.stringify(r.out.client));
r = await aa({ report_pw: demoPw1 }); check("  demo now clones marpai's rows (tpa match), scaled x2", r.status === 200 && r.out.cases.length === 1 && r.out.cases[0].awp === 400 && r.out.cases[0].member_age === 60 && r.out.cases[0].source === "Other" && r.out.cases[0].client_name === "Acme Demo", JSON.stringify(r.out.cases));
r = await put({ slug: "acme-demo", demo: { from: "vault", scale: 0.5 } }); check("  ...and back to vault", r.status === 200 && r.out.client.demo.from === "vault");
// custom password on an existing client, then rotation
r = await put({ slug: "acme-demo", pw: "Demo-Custom-1" }); check("custom pw on an existing client -> 200 with the pw", r.status === 200 && r.out.client.pw === "Demo-Custom-1");
r = await aa({ report_pw: demoPw1 }); check("  the old generated password is dead", r.status === 403);
r = await aa({ report_pw: "Demo-Custom-1" }); check("  the custom password works", r.status === 200 && r.out.client.slug === "acme-demo");
r = await put({ slug: "acme-demo", regenPw: true });
const demoPw2 = r.out && r.out.client && r.out.client.pw;
check("regenPw:true -> a fresh generated password", r.status === 200 && GEN_PW_RE.test(demoPw2 || "") && demoPw2 !== demoPw1 && r.out.client.label === "Acme Demo" && r.out.client.demo.from === "vault", JSON.stringify(r.out.client));
r = await aa({ report_pw: "Demo-Custom-1" }); check("  the custom password is dead after regen", r.status === 403);
r = await aa({ report_pw: demoPw2 }); check("  the regenerated password works", r.status === 200 && r.out.client.slug === "acme-demo");
r = await put({ slug: "acme-demo", pw: "Both-Given-1", regenPw: true }); check("pw + regenPw together -> the supplied pw wins", r.status === 200 && r.out.client.pw === "Both-Given-1");
r = await put({ slug: "acme-demo", pw: demoPw2 }); check("re-using its own previous pw is fine (uniqueness excludes self)", r.status === 200 && r.out.client.pw === demoPw2);
{
  const seen = new Set();
  for (let i = 0; i < 3; i++) { r = await put({ slug: "gen-" + i, label: "Gen " + i, demo: { from: "vault", scale: 1 } }); if (r.status === 200) seen.add(r.out.client.pw); }
  check("3 more generated passwords: all well-formed and distinct", seen.size === 3 && [...seen].every((p) => GEN_PW_RE.test(p)));
  for (let i = 0; i < 3; i++) await admin("client.delete", { slug: "gen-" + i });
}

// client.delete
r = await admin("client.delete", { slug: "vault" }); check("delete a real client referenced by a demo -> 409 referenced by demo acme-demo", r.status === 409 && r.out.error === "referenced by demo acme-demo", JSON.stringify(r.out));
r = await admin("client.delete", { slug: "vault", force: true }); check("  ...even with force", r.status === 409 && r.out.error === "referenced by demo acme-demo");
r = await admin("client.delete", { slug: "marpai" }); check("delete an unreferenced real client without force -> 409 only demo clients can be deleted", r.status === 409 && r.out.error === "only demo clients can be deleted" && r.out.hint === "force");
r = await admin("client.delete", { slug: "marpai", force: "yes" }); check("  force must be boolean true", r.status === 409);
check("  marpai still there", kv.store.has("aa:brand:marpai"));
r = await admin("client.delete", { slug: "marpai", force: true }); check("delete marpai with force -> 200 secretFallback:true (it is in CLIENT_PWS)", r.status === 200 && r.out.ok && r.out.slug === "marpai" && r.out.secretFallback === true, JSON.stringify(r.out));
check("  aa:brand:marpai removed", !kv.store.has("aa:brand:marpai"));
r = await aa({ aa_brand_get: "marpai" }); check("  aa_brand_get marpai -> found:false", r.status === 200 && r.out.found === false);
r = await aa({ report_pw: "client-marpai-pw" }); check("  marpai's CLIENT_PWS password no longer unlocks while the vault is open (vault is authoritative)", r.status === 403);
r = await admin("client.delete", { slug: "newco", force: true }); check("delete newco (real, not in CLIENT_PWS) -> secretFallback:false", r.status === 200 && r.out.secretFallback === false);
r = await aa({ report_pw: "NewCo-Secret-9" }); check("  newco's password is dead", r.status === 403);
r = await admin("clients.list"); check("clients.list -> vault, acme-demo remain", r.out.clients.map((c) => c.slug).sort().join(",") === "acme-demo,vault");

// KV unreadable is "error" — never "absent" (which the writers would paper over with CLIENT_PWS): nothing cached, nothing written
{
  const before = kv.store.get("aa:clients");
  const flaky = { ...kv, get: async (k, o) => { if (k === "aa:clients") throw new Error("kv down"); return kv.get(k, o); } };
  const OTHER_PW = "other-pw-" + Math.random().toString(36).slice(2); // a different REPORT_PW = a cache miss (aaVault is keyed by it)
  const envF = { ...envA, AAPS_DATA: flaky, REPORT_PW: OTHER_PW };
  const adminF = (action, extra = {}, opts = {}) => aa({ aa_admin_pw: OTHER_PW, action, ...extra }, { env: envF, ...opts });
  r = await adminF("ping"); check("KV get throws -> ping vault:'error' (not 'absent')", r.status === 200 && r.out.ok && r.out.vault === "error", JSON.stringify(r.out));
  r = await adminF("ping"); check("  ...and it is not cached: the next ping re-reads and still says 'error'", r.status === 200 && r.out.vault === "error");
  r = await adminF("clients.seed"); check("  clients.seed -> 503 KV read failed", r.status === 503 && r.out.error === "KV read failed", JSON.stringify(r.out));
  r = await adminF("clients.seed", { force: true }); check("  ...force too", r.status === 503);
  r = await adminF("client.put", { slug: "acme-demo", label: "Renamed" }); check("  client.put -> 503", r.status === 503 && r.out.error === "KV read failed");
  r = await adminF("client.put", { slug: "brand-new", label: "Brand New" }); check("  client.put create -> 503 (never seals CLIENT_PWS over the real vault)", r.status === 503);
  r = await adminF("client.delete", { slug: "acme-demo" }); check("  client.delete -> 503", r.status === 503);
  r = await adminF("clients.list"); check("  clients.list -> 503", r.status === 503);
  r = await adminF("client.reveal", { slug: "vault" }); check("  client.reveal -> 503", r.status === 503);
  r = await adminF("clients.reseal", { oldPw: TEST_REPORT_PW }); check("  clients.reseal -> 503 (not 'not seeded')", r.status === 503);
  check("  aa:clients ciphertext unchanged, no doc written or dropped", kv.store.get("aa:clients") === before && !kv.store.has("aa:brand:brand-new") && kv.store.has("aa:brand:acme-demo"));
  const ip = freshIp();
  for (let i = 0; i < 5; i++) r = await aa({ report_pw: "client-marpai-pw" }, { env: envF, ip });
  check("  read route: a client password -> 503, NOT the CLIENT_PWS fallback (marpai was deleted: its secret password stays dead)", r.status === 503 && r.out.error === "KV read failed", JSON.stringify(r.out));
  r = await aa({ report_pw: OTHER_PW }, { env: envF, ip }); check("  the master never touches the vault: master view still served", r.status === 200 && !r.out.client && Array.isArray(r.out.cases));
  r = await aa({ report_pw: demoPw2 }, { ip }); check("  five 503s cost the caller no lockout: the demo password unlocks from that network once KV is back", r.status === 200 && r.out.client.slug === "acme-demo", `status ${r.status}`);
  r = await admin("ping"); check("  ping under the real REPORT_PW -> vault:'ok' again", r.status === 200 && r.out.vault === "ok");
  r = await admin("clients.list"); check("  roster intact: acme-demo, vault", r.status === 200 && r.out.clients.map((c) => c.slug).sort().join(",") === "acme-demo,vault");
}

// REPORT_PW rotation: the vault is now sealed under the OLD password
const ROTATED_PW = "rotated-pw-" + Math.random().toString(36).slice(2);
const envB = { ...envA, REPORT_PW: ROTATED_PW };
const adminB = (action, extra = {}) => aa({ aa_admin_pw: ROTATED_PW, action, ...extra }, { env: envB });
r = await aa({ aa_admin_pw: TEST_REPORT_PW, action: "ping" }, { env: envB }); check("after rotation the old master is refused", r.status === 403);
r = await adminB("ping"); check("ping under the new REPORT_PW -> vault:'sealed'", r.status === 200 && r.out.ok && r.out.vault === "sealed", JSON.stringify(r.out));
r = await adminB("clients.list"); check("clients.list while sealed -> 500 vault sealed with a different password", r.status === 500 && r.out.error === "vault sealed with a different password");
r = await adminB("client.reveal", { slug: "vault" }); check("client.reveal while sealed -> 500", r.status === 500 && r.out.error === "vault sealed with a different password");
r = await adminB("client.put", { slug: "x", label: "x" }); check("client.put while sealed -> 500", r.status === 500);
r = await adminB("client.delete", { slug: "acme-demo" }); check("client.delete while sealed -> 500", r.status === 500);
r = await adminB("clients.seed"); check("clients.seed while sealed -> 409 with hint force", r.status === 409 && r.out.error === "vault sealed with a different password" && r.out.hint === "force");
r = await aa({ report_pw: demoPw2 }, { env: envB }); check("read route while sealed: vault-only demo password is refused (falls back to CLIENT_PWS)", r.status === 403);
r = await aa({ report_pw: "client-marpai-pw" }, { env: envB }); check("  ...and a deleted client's CLIENT_PWS password works again (the secretFallback caveat)", r.status === 200 && r.out.client.slug === "marpai" && r.out.client.demo === false);
r = await aa({ report_pw: "client-vault-pw" }, { env: envB }); check("  ...and the real client still unlocks (degradation, not lockout)", r.status === 200 && r.out.client.slug === "vault");
r = await aa({ report_pw: ROTATED_PW }, { env: envB }); check("  the new master unlocks the master view", r.status === 200 && !r.out.client && Array.isArray(r.out.cases));
r = await aa({ aa_brand_get: "acme-demo" }, { env: envB }); check("aa_brand_get is unaffected by the sealed vault", r.status === 200 && r.out.found === true);
r = await adminB("clients.reseal", { oldPw: "not-the-old-password" }); check("clients.reseal with the wrong old password -> 409", r.status === 409 && r.out.error === "vault sealed with a different password");
r = await adminB("clients.reseal", { oldPw: TEST_REPORT_PW }); check("clients.reseal with the old REPORT_PW -> 200 count 2", r.status === 200 && r.out.ok && r.out.count === 2, JSON.stringify(r.out));
r = await adminB("ping"); check("  ping -> vault:'ok' under the new password", r.out.vault === "ok");
r = await adminB("clients.list"); check("  clients.list -> both clients survived the re-key", r.status === 200 && r.out.vault === true && r.out.clients.map((c) => c.slug).sort().join(",") === "acme-demo,vault" && !hasPw(r.out));
r = await adminB("client.reveal", { slug: "acme-demo" }); check("  demo password preserved through the re-key", r.status === 200 && r.out.pw === demoPw2);
r = await aa({ report_pw: demoPw2 }, { env: envB }); check("  demo password unlocks again", r.status === 200 && r.out.client.slug === "acme-demo" && r.out.cases[0].awp === 50);
r = await aa({ report_pw: "client-marpai-pw" }, { env: envB }); check("  marpai's fallback password is dead again", r.status === 403);
r = await admin("ping"); check("the OLD password's isolate view now sees the vault as sealed (cache keyed by REPORT_PW)", r.status === 200 && r.out.vault === "sealed", JSON.stringify(r.out));
r = await admin("clients.reseal", { oldPw: ROTATED_PW }); check("rotate back for the rest of the run", r.status === 200 && r.out.count === 2);
r = await admin("ping"); check("  ping -> ok again", r.out.vault === "ok");

// delete the demo, then the (now unreferenced) real client
r = await admin("client.delete", { slug: "acme-demo" }); check("client.delete demo -> 200 secretFallback:false", r.status === 200 && r.out.slug === "acme-demo" && r.out.secretFallback === false);
r = await aa({ report_pw: demoPw2 }); check("  the demo password is dead", r.status === 403);
r = await aa({ aa_brand_get: "acme-demo" }); check("  aa_brand_get acme-demo -> found:false", r.status === 200 && r.out.found === false);
r = await admin("client.delete", { slug: "vault", force: true }); check("delete vault with force once unreferenced -> 200", r.status === 200 && r.out.secretFallback === true);
r = await admin("clients.list"); check("clients.list -> empty vault (vault:true)", r.status === 200 && r.out.vault === true && r.out.clients.length === 0);
r = await aa({ report_pw: "client-vault-pw" }); check("  no client password unlocks against an empty vault", r.status === 403);
{
  const before = kv.store.get("aa:clients");
  r = await admin("clients.seed", { force: true }); check("clients.seed force on an open (empty) vault -> 409, never a reset to CLIENT_PWS", r.status === 409 && r.out.error === "force only recovers a sealed vault", JSON.stringify(r.out));
  check("  ciphertext unchanged", kv.store.get("aa:clients") === before);
  r = await admin("clients.seed"); check("  plain seed on the open empty vault -> sealed:false, count 0", r.status === 200 && r.out.sealed === false && r.out.count === 0, JSON.stringify(r.out));
  kv.store.delete("aa:clients"); // the record vanishes from KV behind a warm cache
  r = await admin("clients.seed"); check("seed re-reads KV (not the 60 s cache): absent -> re-sealed from CLIENT_PWS", r.status === 200 && r.out.sealed === true && r.out.count === 2 && r.out.slugs.join(",") === "marpai,vault", JSON.stringify(r.out));
}
r = await aa({ report_pw: "client-vault-pw" }); check("  vault client unlocks again", r.status === 200 && r.out.client.slug === "vault");
// a corrupted vault record reads as sealed; force seed recovers
{
  const envC = { ...envA, REPORT_PW: "third-pw-" + Math.random().toString(36).slice(2) };
  kv.store.set("aa:clients", "not json{");
  r = await aa({ aa_admin_pw: envC.REPORT_PW, action: "ping" }, { env: envC }); check("garbage aa:clients -> vault:'sealed' (never a crash)", r.status === 200 && r.out.vault === "sealed");
  r = await aa({ report_pw: "client-vault-pw" }, { env: envC }); check("  read route falls back to CLIENT_PWS", r.status === 200 && r.out.client.slug === "vault");
  r = await aa({ aa_admin_pw: envC.REPORT_PW, action: "clients.reseal", oldPw: TEST_REPORT_PW }, { env: envC }); check("  reseal cannot open garbage -> 409", r.status === 409);
  r = await aa({ aa_admin_pw: envC.REPORT_PW, action: "clients.seed", force: true }, { env: envC }); check("  seed force recovers", r.status === 200 && r.out.sealed === true && r.out.count === 2);
  kv.store.delete("aa:clients");
  r = await admin("clients.seed"); check("cleanup: vault reseeded under the test REPORT_PW", r.status === 200 && r.out.sealed === true);
}
// cross-isolate: KV changed behind this isolate's warm cache (a client created elsewhere) — the next write here must not undo it
{
  r = await admin("ping"); check("lost-update setup: cache warm (vault ok)", r.status === 200 && r.out.vault === "ok");
  const encx = await encryptJSON({ v: 1, clients: { ...AA_CLIENT_PWS, elsewhere: { pw: "elsewhere-pw-1", label: "Elsewhere", demo: { from: "vault", scale: 1 } } } }, TEST_REPORT_PW);
  kv.store.set("aa:clients", JSON.stringify({ v: 1, updatedAt: "2026-06-01T00:00:00.000Z", enc: encx }));
  r = await admin("client.put", { slug: "vault", label: "Vault Health" }); check("client.put re-reads KV before sealing -> 200", r.status === 200 && r.out.client.label === "Vault Health", JSON.stringify(r.out).slice(0, 200));
  r = await admin("clients.list"); check("  the entry written elsewhere survived the reseal: elsewhere, marpai, vault", r.status === 200 && r.out.clients.map((c) => c.slug).sort().join(",") === "elsewhere,marpai,vault", JSON.stringify(r.out.clients && r.out.clients.map((c) => c.slug)));
  r = await aa({ report_pw: "elsewhere-pw-1" }); check("  its password unlocks (a demo of vault, relabeled)", r.status === 200 && r.out.client.slug === "elsewhere" && r.out.client.demo === true && r.out.cases.length === 2 && r.out.cases[0].client_name === "Elsewhere", JSON.stringify(r.out).slice(0, 200));
  const enc2 = await encryptJSON({ v: 1, clients: { ...AA_CLIENT_PWS } }, TEST_REPORT_PW); // ...and a deletion made elsewhere
  kv.store.set("aa:clients", JSON.stringify({ v: 1, updatedAt: "2026-06-02T00:00:00.000Z", enc: enc2 }));
  r = await admin("client.put", { slug: "marpai", label: "Marpai" }); check("a client deleted elsewhere is not resurrected by a write here", r.status === 200 && (await admin("clients.list")).out.clients.map((c) => c.slug).sort().join(",") === "marpai,vault");
  r = await aa({ report_pw: "elsewhere-pw-1" }); check("  ...and its password is dead", r.status === 403);
}
// the myrx surface is untouched by all of the above
r = await call({ admin_pw: TEST_MASTER, action: "brands.list" }); check("myrx brands.list still lists only myrx docs", r.status === 200 && r.out.clients.map((c) => c.slug).join(",") === "zeta,aurora,uwhc", JSON.stringify(r.out.clients && r.out.clients.map((c) => c.slug)));
r = await call({ admin_pw: TEST_MASTER, action: "pws.get" }); check("myrx pws.get still serves its own vault", r.status === 200 && r.out.enc && r.out.enc.data === vault.data);
check("no aa:* key ever leaked a plaintext client password into KV", ![...kv.store.entries()].some(([k, v]) => k.startsWith("aa:") && (v.includes("client-vault-pw") || v.includes("client-marpai-pw") || (demoPw2 && v.includes(demoPw2)))));

// ---------------------------------------------------------------- part 5
console.log("email sign-in (Cloudflare Access): /login, /_auth/*, access.* admin actions, escrow, logs");
// Synthetic Access: an RSA key pair signs test JWTs; the stubbed fetch serves
// its public half as the team's JWKS. A second pair stands in for "signed by
// someone else". No real Access team, secret or password is involved.
const RSA = { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
const kp1 = await crypto.subtle.generateKey(RSA, true, ["sign", "verify"]);
const kp2 = await crypto.subtle.generateKey(RSA, true, ["sign", "verify"]);
const pub1 = await crypto.subtle.exportKey("jwk", kp1.publicKey);
const TEST_JWK = { kid: "test-kid-1", kty: "RSA", alg: "RS256", use: "sig", n: pub1.n, e: pub1.e };
let jwksCalls = 0;
const prevFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  const u = String(url);
  if (u === "https://testteam.cloudflareaccess.com/cdn-cgi/access/certs") { jwksCalls++; return new Response(JSON.stringify({ keys: [TEST_JWK] }), { status: 200 }); }
  if (u === "https://downteam.cloudflareaccess.com/cdn-cgi/access/certs") return new Response("down", { status: 503 });
  return prevFetch(url, init);
};
const hex = (n) => Buffer.from(crypto.getRandomValues(new Uint8Array(n))).toString("hex");
const b64u = (x) => Buffer.from(typeof x === "string" ? x : new Uint8Array(x)).toString("base64url");
const TEST_AUD = hex(32), OTHER_AUD = hex(32);
const TEST_SESSION_SECRET = hex(32), TEST_ESCROW_KEY = hex(32);
const envS = { ...envA, SESSION_SECRET: TEST_SESSION_SECRET, ESCROW_KEY: TEST_ESCROW_KEY };
const MYRX = "https://reports.myrxcard.com", AVALON = "https://reports.avalonsaves.com", WORKERS_DEV = "https://myrxcard-sync.example";
const nowS = () => Math.floor(Date.now() / 1000);
async function signJwt(claims, { kid = "test-kid-1", key = kp1.privateKey, alg = "RS256" } = {}) {
  const h = b64u(JSON.stringify({ alg, kid, typ: "JWT" })), p = b64u(JSON.stringify(claims));
  const sig = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, key, new TextEncoder().encode(`${h}.${p}`));
  return `${h}.${p}.${b64u(sig)}`;
}
const claims = (email, extra = {}) => ({ iss: "https://testteam.cloudflareaccess.com", aud: [TEST_AUD], exp: nowS() + 300, iat: nowS(), email, ...extra });
const jwtFor = (email, extra, opts) => signJwt(claims(email, extra), opts);
// one request against the auth surface: returns status, parsed JSON (or the HTML), the reason header and the cookie
async function auth(host, path, { method, body, cookie, jwt, ip, env: e, headers: hx } = {}) {
  const headers = { "cf-connecting-ip": ip || freshIp(), ...(hx || {}) };
  if (cookie) headers.cookie = cookie;
  if (jwt) headers["cf-access-jwt-assertion"] = jwt;
  const init = { method: method || (body !== undefined ? "POST" : "GET"), headers };
  if (body !== undefined) { headers["content-type"] = "application/json"; init.body = typeof body === "string" ? body : JSON.stringify(body); }
  const res = await worker.fetch(new Request(host + path, init), e || envS);
  const text = await res.text();
  let out = null; try { out = JSON.parse(text); } catch {}
  const setCookie = res.headers.get("set-cookie");
  return { status: res.status, out, html: text, headers: res.headers, reason: res.headers.get("x-auth-reason"), setCookie, cookie: setCookie ? setCookie.split(";")[0] : null };
}
const myrxAdmin = (action, extra = {}, opts = {}) => call({ admin_pw: TEST_MASTER, action, ...extra }, { ip: freshIp(), env: envS, ...opts });
const aaAdmin = (action, extra = {}, opts = {}) => aa({ aa_admin_pw: TEST_REPORT_PW, action, ...extra }, { env: envS, ...opts });
const parseCookie = (c) => { const [pv, sig] = c.split("=")[1].split("."); return { payload: JSON.parse(Buffer.from(pv, "base64url").toString()), payloadB64: pv, sig }; };
async function forgeCookie(payload, secret = TEST_SESSION_SECRET) { // the contract's cookie format, built here so a tampered/expired one can be tested
  const pv = b64u(JSON.stringify(payload));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return `__Host-report_session=${pv}.${b64u(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(pv)))}`;
}
const SECRET_STRINGS = ["fake-partner-pw", "client-vault-pw", "client-marpai-pw", TEST_MASTER, TEST_REPORT_PW];
const leaks = (s) => SECRET_STRINGS.some((x) => s.includes(x));

// dispatcher + gating
r = await auth(WORKERS_DEV, "/login/"); check("/login on the workers.dev host -> 404 unknown site", r.status === 404 && r.out && r.out.error === "unknown site", r.html.slice(0, 100));
r = await auth(WORKERS_DEV, "/_auth/whoami"); check("/_auth/whoami on the workers.dev host -> 404 unknown site", r.status === 404 && r.out.error === "unknown site");
r = await call({}, { env: { ...envS, XANO_META_TOKEN: undefined } }); check("POST / unchanged: empty body still falls to the Xano guard", r.status === 500 && /Xano/.test(r.out.error));
r = await call({ secret: "nope", rows: [] }, { env: envS }); check("POST / unchanged: the secret route still answers on the workers.dev host", r.status === 403 && r.out.error === "bad secret");
r = await call({ brand_get: "uwhc" }, { env: envS }); check("POST / brand_get unchanged (CORS * still on the JSON API)", r.status === 200 && r.out.found === true && r.cors === "*");
r = await auth(MYRX, "/_auth/whoami", { env: envA }); check("no SESSION_SECRET -> 503 email sign-in not configured", r.status === 503 && r.out.error === "email sign-in not configured", r.html);
r = await auth(MYRX, "/login/", { env: envA }); check("  /login without SESSION_SECRET -> 503 HTML, reason not-configured", r.status === 503 && r.reason === "not-configured" && r.headers.get("content-type").startsWith("text/html"));
r = await auth(MYRX, "/_auth/key", { body: { site: "" }, env: envA }); check("  /_auth/key without SESSION_SECRET -> 503", r.status === 503 && r.out.error === "email sign-in not configured");
r = await auth(MYRX, "/_auth/whoami", { env: { ...envS, AAPS_DATA: undefined } }); check("no KV -> 500 KV not bound", r.status === 500 && r.out.error === "KV not bound");
{ // an unreadable access document is state "error": 503, never cached, never "not configured" (checked before any read has warmed the 60 s cache)
  const flakyAccess = (key) => ({ ...envS, AAPS_DATA: { ...kv, get: async (k, o) => { if (k === key) throw new Error("kv down"); return kv.get(k, o); } } });
  r = await auth(MYRX, "/_auth/whoami", { env: flakyAccess("myrx:access") }); check("KV throwing on myrx:access -> whoami 503 KV read failed", r.status === 503 && r.out.error === "KV read failed", r.html);
  r = await auth(MYRX, "/login/", { env: flakyAccess("myrx:access") }); check("  /login -> 503 HTML kv-failed", r.status === 503 && r.reason === "kv-failed" && r.headers.get("content-type").startsWith("text/html"));
  r = await auth(AVALON, "/_auth/whoami", { env: flakyAccess("aa:access") }); check("  aa whoami -> 503 too", r.status === 503 && r.out.error === "KV read failed");
  r = await auth(AVALON, "/_auth/whoami"); check("  ...and the failure was not cached: the next aa whoami answers", r.status === 200 && r.out.ok === true && r.out.configured === false);
}
r = await auth(MYRX, "/_auth/x"); check("unknown /_auth/x -> 404 not found", r.status === 404 && r.out.error === "not found");
r = await auth(MYRX, "/login/extra"); check("/login/extra -> 404 not found", r.status === 404 && r.out.error === "not found");
r = await auth(MYRX, "/_auth/whoami", { method: "POST", body: {} }); check("POST /_auth/whoami -> 405 GET only", r.status === 405 && r.out.error === "GET only");
r = await auth(MYRX, "/_auth/key"); check("GET /_auth/key -> 405 POST only", r.status === 405 && r.out.error === "POST only");
r = await auth(MYRX, "/_auth/logout"); check("GET /_auth/logout -> 405 POST only", r.status === 405 && r.out.error === "POST only");
r = await auth(MYRX, "/login/", { method: "POST", body: {} }); check("POST /login -> 405 GET only", r.status === 405 && r.out.error === "GET only");
r = await auth(MYRX, "/_auth/whoami");
check("whoami unconfigured, no cookie -> {ok, configured:false, signedIn:false}", r.status === 200 && r.out.ok === true && r.out.configured === false && r.out.signedIn === false, r.html);
check("  /_auth/* carries no CORS header, cache-control no-store, vary cookie", r.headers.get("access-control-allow-origin") === null && r.headers.get("cache-control") === "no-store" && r.headers.get("vary") === "cookie");
r = await auth(MYRX, "/login/"); check("/login unconfigured -> 503 HTML not-configured", r.status === 503 && r.reason === "not-configured" && r.html.includes("Email sign-in is not set up for this site yet.") && r.headers.get("cache-control") === "no-store");
r = await auth(MYRX, "/_auth/key", { body: { site: "" } }); check("/_auth/key without a cookie -> 401 not signed in", r.status === 401 && r.out.error === "not signed in");
r = await auth(MYRX, "/_auth/key", { body: { site: "Bad Site!" } }); check("/_auth/key bad site -> 400", r.status === 400 && r.out.error === "bad site");
r = await auth(MYRX, "/_auth/key", { body: "{" }); check("/_auth/key unparseable body -> 400 bad json", r.status === 400 && r.out.error === "bad json");
r = await auth(MYRX, "/_auth/key", { body: JSON.stringify({ site: "", pad: "x".repeat(10100) }) }); check("/_auth/key body > 10000 bytes -> 413", r.status === 413);

// access.get / access.put (myrx)
r = await myrxAdmin("access.get");
check("access.get unseeded -> the empty document, configured:false, secrets flags", r.status === 200 && r.out.ok && r.out.access.v === 1 && r.out.access.teamDomain === "" && r.out.access.aud === "" && Array.isArray(r.out.access.root.domains) && r.out.access.root.emails.length === 0
  && Object.keys(r.out.access.clients).length === 0 && r.out.access.updatedAt === null && r.out.configured === false && r.out.secrets.session === true && r.out.secrets.escrow === true, JSON.stringify(r.out));
check("  myrx access.get carries escrow.state missing", r.out.escrow && r.out.escrow.state === "missing" && r.out.escrow.count === 0 && r.out.escrow.updatedAt === null, JSON.stringify(r.out.escrow));
r = await myrxAdmin("access.get", {}, { env: { ...envS, SESSION_SECRET: undefined, ESCROW_KEY: undefined } }); check("  secrets flags false when the secrets are absent", r.status === 200 && r.out.secrets.session === false && r.out.secrets.escrow === false);
r = await myrxAdmin("access.put", { access: "x" }); check("access.put non-object -> 422 access: must be an object", r.status === 422 && r.out.error === "access: must be an object" && r.out.path === "access");
r = await myrxAdmin("access.put", { access: { teamDomain: "x", extra: 1 } }); check("access.put unknown top-level key -> 422 access.extra", r.status === 422 && r.out.error === "access.extra: unknown key" && r.out.path === "access.extra");
r = await myrxAdmin("access.put", { access: { teamDomain: "a.b" } }); check("teamDomain 'a.b' -> 422 team name only", r.status === 422 && r.out.error === "access.teamDomain: team name only (the part before .cloudflareaccess.com)" && r.out.path === "access.teamDomain");
r = await myrxAdmin("access.put", { access: { teamDomain: 42 } }); check("teamDomain non-string -> 422", r.status === 422 && r.out.path === "access.teamDomain");
r = await myrxAdmin("access.put", { access: { teamDomain: "Avalon" } }); check("teamDomain 'Avalon' -> lowercased", r.status === 200 && r.out.access.teamDomain === "avalon" && r.out.configured === false);
r = await myrxAdmin("access.put", { access: { teamDomain: "https://avalon.cloudflareaccess.com/" } }); check("teamDomain full URL -> 'avalon'", r.status === 200 && r.out.access.teamDomain === "avalon");
r = await myrxAdmin("access.put", { access: { teamDomain: " avalon.cloudflareaccess.com " } }); check("teamDomain with the suffix and spaces -> 'avalon'", r.status === 200 && r.out.access.teamDomain === "avalon");
r = await myrxAdmin("access.put", { access: { aud: TEST_AUD.slice(0, 63) } }); check("aud 63 hex -> 422", r.status === 422 && r.out.error === "access.aud: 64 hex characters (the Access application AUD tag)" && r.out.path === "access.aud");
r = await myrxAdmin("access.put", { access: { aud: TEST_AUD.toUpperCase() } }); check("aud uppercase -> accepted lowercased", r.status === 200 && r.out.access.aud === TEST_AUD);
r = await myrxAdmin("access.put", { access: { root: { domains: ["gmail.com"] } } }); check("public provider as a domain -> 422 exact sentence", r.status === 422 && r.out.error === "access.root.domains[0]: public email providers cannot be allowed as a domain" && r.out.path === "access.root.domains[0]", JSON.stringify(r.out));
r = await myrxAdmin("access.put", { access: { clients: { uwhc: { domains: ["uwhealth.org", "Outlook.com"] } } } }); check("  ...also under a client, case-insensitively, with the index", r.status === 422 && r.out.error === "access.clients.uwhc.domains[1]: public email providers cannot be allowed as a domain");
r = await myrxAdmin("access.put", { access: { root: { emails: ["someone@gmail.com"] } } }); check("gmail.com as a named person is fine", r.status === 200 && r.out.access.root.emails.join() === "someone@gmail.com");
r = await myrxAdmin("access.put", { access: { root: { domains: ["not a domain"] } } }); check("bad domain -> 422 not a domain", r.status === 422 && r.out.error === "access.root.domains[0]: not a domain");
r = await myrxAdmin("access.put", { access: { root: { domains: ["localhost"] } } }); check("single-label domain -> 422", r.status === 422 && r.out.path === "access.root.domains[0]");
r = await myrxAdmin("access.put", { access: { root: { emails: ["nobody"] } } }); check("bad email -> 422 not an email address", r.status === 422 && r.out.error === "access.root.emails[0]: not an email address");
r = await myrxAdmin("access.put", { access: { root: { emails: [123] } } }); check("non-string email -> 422", r.status === 422 && r.out.path === "access.root.emails[0]");
r = await myrxAdmin("access.put", { access: { root: { domains: "uwhealth.org" } } }); check("domains not a list -> 422", r.status === 422 && r.out.path === "access.root.domains");
r = await myrxAdmin("access.put", { access: { root: { people: [] } } }); check("unknown key inside an entry -> 422 access.root.people", r.status === 422 && r.out.error === "access.root.people: unknown key");
r = await myrxAdmin("access.put", { access: { root: [] } }); check("root not an object -> 422", r.status === 422 && r.out.path === "access.root");
r = await myrxAdmin("access.put", { access: { clients: { "Bad Slug": { domains: [] } } } }); check("bad client slug key -> 422 access.clients.Bad Slug: bad slug", r.status === 422 && r.out.error === "access.clients.Bad Slug: bad slug");
r = await myrxAdmin("access.put", { access: { clients: { uwhc: { domains: [], extra: 1 } } } }); check("unknown key inside a client entry -> 422 access.clients.uwhc.extra", r.status === 422 && r.out.error === "access.clients.uwhc.extra: unknown key");
r = await myrxAdmin("access.put", { access: { clients: [] } }); check("clients not an object -> 422", r.status === 422 && r.out.path === "access.clients");
r = await myrxAdmin("access.put", { access: { root: { domains: Array.from({ length: 21 }, (_, i) => `d${i}.example.com`) } } }); check("> 20 domains -> 422 at most 20", r.status === 422 && r.out.error === "access.root.domains: at most 20");
r = await myrxAdmin("access.put", { access: { root: { emails: Array.from({ length: 201 }, (_, i) => `p${i}@example.com`) } } }); check("> 200 emails -> 422 at most 200", r.status === 422 && r.out.error === "access.root.emails: at most 200");
{ const cl = {}; for (let i = 0; i < 101; i++) cl["c" + i] = {}; r = await myrxAdmin("access.put", { access: { clients: cl } }); check("> 100 clients -> 422 at most 100", r.status === 422 && r.out.error === "access.clients: at most 100"); }
r = await myrxAdmin("access.put", { access: { root: { domains: ["Zeta.org", " alpha.org ", "zeta.org"], emails: ["B@X.org", "a@x.org", "b@x.org"] }, clients: { UWHC: { domains: ["UWHealth.org"] } } } });
check("dedupe + sort + lowercase (domains, emails, slug keys)", r.status === 200 && r.out.access.root.domains.join() === "alpha.org,zeta.org" && r.out.access.root.emails.join() === "a@x.org,b@x.org" && Object.keys(r.out.access.clients).join() === "uwhc" && r.out.access.clients.uwhc.domains.join() === "uwhealth.org" && r.out.access.clients.uwhc.emails.length === 0, JSON.stringify(r.out.access));
check("  updatedAt stamped, stored under myrx:access", typeof r.out.access.updatedAt === "string" && kv.store.has("myrx:access") && JSON.parse(kv.store.get("myrx:access")).clients.uwhc.domains[0] === "uwhealth.org");
r = await myrxAdmin("access.put", { access: { v: 1, updatedAt: "ignored", teamDomain: "", aud: "" } }); check("v / updatedAt in the body are ignored, not unknown", r.status === 200 && r.out.access.updatedAt !== "ignored");
r = await myrxAdmin("access.put", { access: { teamDomain: "testteam", aud: TEST_AUD, root: { emails: ["boss@corp.example"] }, clients: { uwhc: { domains: ["uwhealth.org"], emails: ["contractor@gmail.com"] }, aurora: { emails: ["pm@aurora.example"] } } } });
check("access.put full myrx document -> configured:true", r.status === 200 && r.out.configured === true && r.out.access.teamDomain === "testteam", JSON.stringify(r.out));
r = await myrxAdmin("access.get"); check("access.get returns the normalized document + configured:true", r.status === 200 && r.out.configured === true && r.out.access.aud === TEST_AUD && r.out.access.clients.uwhc.domains[0] === "uwhealth.org" && r.out.access.root.emails[0] === "boss@corp.example");
r = await call({ admin_pw: "wrong", action: "access.get" }, { ip: freshIp(), env: envS }); check("access.get without the master -> 403", r.status === 403);
r = await myrxAdmin("access.get", {}, { env: { ...envS, AAPS_DATA: undefined } }); check("access.get without KV -> 500 KV not bound", r.status === 500 && r.out.error === "KV not bound");
// aa side: same shape, no escrow
r = await aaAdmin("access.get"); check("aa access.get unseeded -> empty document, no escrow key, secrets.session only", r.status === 200 && r.out.ok && r.out.configured === false && r.out.access.teamDomain === "" && r.out.escrow === undefined && r.out.secrets.session === true && r.out.secrets.escrow === undefined, JSON.stringify(r.out));
r = await aaAdmin("access.put", { access: { root: { domains: ["yahoo.com"] } } }); check("aa access.put public domain -> 422", r.status === 422 && r.out.error === "access.root.domains[0]: public email providers cannot be allowed as a domain");
r = await aaAdmin("access.put", { access: { teamDomain: "testteam", aud: TEST_AUD, root: { domains: ["avalon.example"] }, clients: { vault: { domains: ["vault.example"] }, ghost: { emails: ["g@ghost.example"] } } } });
check("aa access.put full document -> configured:true, stored under aa:access", r.status === 200 && r.out.configured === true && kv.store.has("aa:access") && !kv.store.has("aa:access-log"), JSON.stringify(r.out));
r = await myrxAdmin("access.get"); check("  the myrx document is untouched by the aa write", r.out.access.root.emails[0] === "boss@corp.example" && r.out.access.clients.vault === undefined);
r = await aa({ aa_admin_pw: "wrong", action: "access.get" }, { env: envS }); check("aa access.get without the master -> 403", r.status === 403);

// /login
r = await auth(MYRX, "/login/"); check("configured, no Access header -> 401 no-token with the sign-in-required copy", r.status === 401 && r.reason === "no-token" && r.html.includes("Sign-in required") && r.html.includes("Sign in with company email"), r.reason);
r = await auth(MYRX, "/login/?to=%2Fuwhc%2F", { jwt: await jwtFor("Nurse@UWHealth.org") });
check("valid JWT + mapped domain -> 302 Location /uwhc/", r.status === 302 && r.headers.get("location") === "/uwhc/" && r.reason === "ok" && r.headers.get("cache-control") === "no-store", `${r.status} ${r.reason} ${r.headers.get("location")}`);
const uwhcCookie = r.cookie;
check("  Set-Cookie: __Host- name, Path=/, Secure, HttpOnly, SameSite=Lax, Max-Age=43200", !!r.setCookie && r.setCookie.startsWith("__Host-report_session=") && /; Path=\//.test(r.setCookie) && /; Secure/.test(r.setCookie) && /; HttpOnly/.test(r.setCookie) && /; SameSite=Lax/.test(r.setCookie) && /; Max-Age=43200/.test(r.setCookie) && !/Domain=/.test(r.setCookie), r.setCookie);
{
  const c = parseCookie(uwhcCookie);
  check("  cookie payload {v:1, site, email (lowercased), root:false, slugs:[uwhc], iat, exp=iat+12h, nonce}", c.payload.v === 1 && c.payload.site === "myrx" && c.payload.email === "nurse@uwhealth.org" && c.payload.root === false && c.payload.slugs.join() === "uwhc" && c.payload.exp === c.payload.iat + 43200 && /^[0-9a-f]{32}$/.test(c.payload.nonce), JSON.stringify(c.payload));
  check("  signature = base64url HMAC-SHA256(SESSION_SECRET, payloadB64)", (await forgeCookie(c.payload)) === uwhcCookie);
  check("  body empty; no password in the response", r.html === "" && !leaks(r.html));
}
{
  const rec = JSON.parse(kv.store.get("myrx:access-log"));
  check("  login logged under myrx:access-log {t, email, slug:null, action:login, net}", rec && rec.v === 1 && rec.entries.length === 1 && rec.entries[0].action === "login" && rec.entries[0].email === "nurse@uwhealth.org" && rec.entries[0].slug === null && /^\d{4}-/.test(rec.entries[0].t) && /^198\.51\.100\.\d+$/.test(rec.entries[0].net), JSON.stringify(rec));
}
// `to` sanitization
for (const [to, want] of [["//evil.com", "/"], ["https://x", "/"], ["/login/x", "/"], ["/_auth/key", "/"], ["", "/"], ["/a b", "/"], ["/x\\y", "/"], ["/uwhc/?period=Q", "/uwhc/?period=Q"], ["/\\evil.com", "/"], ["/x\ny", "/"], ["/" + "a".repeat(501), "/"], ["/aurora/", "/aurora/"]]) {
  r = await auth(MYRX, "/login/?to=" + encodeURIComponent(to), { jwt: await jwtFor("nurse@uwhealth.org") });
  if (!(r.status === 302 && r.headers.get("location") === want)) { check(`to=${JSON.stringify(to)} -> ${want}`, false, `${r.status} ${r.headers.get("location")}`); break; }
}
check("`to` open-redirect attempts -> /; same-host paths with a query kept", r.status === 302 && r.headers.get("location") === "/aurora/");
r = await auth(MYRX, "/login", { jwt: await jwtFor("nurse@uwhealth.org") }); check("/login without a trailing slash or `to` -> 302 /", r.status === 302 && r.headers.get("location") === "/");
check("JWKS fetched once across all those logins (1 h cache)", jwksCalls === 1, `${jwksCalls} calls`);
// token failures — each with its reason, none with a cookie
const bad = async (name, jwt, reason, ip) => { const x = await auth(MYRX, "/login/", { jwt, ip }); check(`${name} -> 401 ${reason}`, x.status === 401 && x.reason === reason && x.setCookie === null && x.html.includes("Sign-in could not be verified"), `${x.status} ${x.reason}`); return x; };
await bad("wrong signing key", await jwtFor("nurse@uwhealth.org", {}, { key: kp2.privateKey }), "bad-signature");
await bad("unknown kid (JWKS just fetched: no refetch)", await jwtFor("nurse@uwhealth.org", {}, { kid: "rotated-kid" }), "bad-signature");
await bad("wrong issuer", await jwtFor("nurse@uwhealth.org", { iss: "https://evil.cloudflareaccess.com" }), "bad-issuer");
await bad("wrong audience", await jwtFor("nurse@uwhealth.org", { aud: [OTHER_AUD] }), "bad-audience");
await bad("aud as a string that is not ours", await jwtFor("nurse@uwhealth.org", { aud: OTHER_AUD }), "bad-audience");
await bad("expired", await jwtFor("nurse@uwhealth.org", { exp: nowS() - 5 }), "expired");
await bad("exp missing", await jwtFor("nurse@uwhealth.org", { exp: undefined }), "expired");
await bad("nbf in the future", await jwtFor("nurse@uwhealth.org", { nbf: nowS() + 600 }), "expired");
await bad("iat far in the future", await jwtFor("nurse@uwhealth.org", { iat: nowS() + 900 }), "expired");
await bad("alg none", await jwtFor("nurse@uwhealth.org", {}, { alg: "none" }), "bad-token");
await bad("alg HS256 header", await jwtFor("nurse@uwhealth.org", {}, { alg: "HS256" }), "bad-token");
await bad("two segments", "abc.def", "bad-token");
await bad("garbage segments", "!!!.@@@.###", "bad-token");
await bad("no email claim", await jwtFor(undefined), "no-email");
await bad("email not an address", await jwtFor("not-an-email"), "no-email");
r = await auth(MYRX, "/login/", { jwt: await jwtFor("nurse@uwhealth.org", { aud: TEST_AUD }) }); check("aud as a plain string -> accepted", r.status === 302);
r = await auth(MYRX, "/login/", { jwt: await jwtFor("  Nurse@UWHealth.org  ", { nbf: nowS() + 30 }) }); check("email trimmed/lowercased; nbf within 60 s skew accepted", r.status === 302 && parseCookie(r.cookie).payload.email === "nurse@uwhealth.org");
// JWKS unavailable: an aa document pointing at the down team
r = await aaAdmin("access.put", { access: { teamDomain: "downteam", aud: TEST_AUD, root: { domains: ["avalon.example"] } } });
r = await auth(AVALON, "/login/", { jwt: await signJwt({ ...claims("x@avalon.example"), iss: "https://downteam.cloudflareaccess.com" }) });
check("JWKS endpoint down -> 401 jwks-unavailable, no cookie", r.status === 401 && r.reason === "jwks-unavailable" && r.setCookie === null, r.reason);
{
  const ip = freshIp();
  for (let i = 0; i < 6; i++) r = await auth(AVALON, "/login/", { ip, jwt: await signJwt({ ...claims("x@avalon.example"), iss: "https://downteam.cloudflareaccess.com" }) });
  check("  a JWKS outage never locks the caller out (not their guess)", r.status === 401 && r.reason === "jwks-unavailable");
}
r = await aaAdmin("access.put", { access: { teamDomain: "testteam", aud: TEST_AUD, root: { domains: ["avalon.example"] }, clients: { vault: { domains: ["vault.example"] }, ghost: { emails: ["g@ghost.example"] } } } });
check("  (aa document restored)", r.status === 200 && r.out.configured === true);
// unmapped email
r = await auth(MYRX, "/login/?to=%2Fuwhc%2F", { jwt: await jwtFor("stranger@nowhere.example") });
check("valid JWT, unmapped email -> 403 unmapped, no Set-Cookie", r.status === 403 && r.reason === "unmapped" && r.setCookie === null, `${r.status} ${r.reason}`);
check("  denial page: exact heading, the email (escaped), default contact line, both links", r.html.includes("<h1>This email is not authorized for a report on this site</h1>") && r.html.includes("<p>You signed in as <b>stranger@nowhere.example</b>.</p>")
  && r.html.includes("<p>Contact your report administrator to request access.</p>") && r.html.includes('<a href="/cdn-cgi/access/logout">Use a different email</a>') && r.html.includes('<a href="/">Back to the report</a>'), r.html.slice(-400));
r = await auth(MYRX, "/login/", { jwt: await jwtFor("stranger@nowhere.example"), env: { ...envS, ACCESS_CONTACT: "support@myrxcard.example" } }); check("  ACCESS_CONTACT var replaces the contact line", r.html.includes("<p>Contact support@myrxcard.example to request access.</p>"));
r = await auth(MYRX, "/login/", { jwt: await jwtFor("x'y@nowhere.example"), env: { ...envS, ACCESS_CONTACT: "IT <helpdesk>" } }); check("  email and contact line are HTML-escaped on the denial page", r.status === 403 && r.html.includes("<b>x&#39;y@nowhere.example</b>") && r.html.includes("Contact IT &lt;helpdesk&gt; to request access") && !r.html.includes("<helpdesk>"), r.reason);
{
  const rec = JSON.parse(kv.store.get("myrx:access-log"));
  const last = rec.entries[rec.entries.length - 1];
  check("  denied entries logged {action:denied, slug:null}", rec.entries.filter((e) => e.action === "denied").length === 3 && last.action === "denied" && last.email === "x'y@nowhere.example" && last.slug === null, JSON.stringify(last));
}
// lockout: scope auth:<site>, separate from the password routes
{
  const ip = freshIp();
  let last;
  for (let i = 0; i < 5; i++) last = await auth(MYRX, "/login/", { ip, jwt: await jwtFor("nurse@uwhealth.org", {}, { key: kp2.privateKey }) });
  check("5 bad tokens -> 401 then", last.status === 401);
  r = await auth(MYRX, "/login/", { ip, jwt: await jwtFor("nurse@uwhealth.org") }); check("  6th /login -> 429 HTML locked even with a good token", r.status === 429 && r.reason === "locked" && /Too many attempts — try again in \d+ minutes/.test(r.html) && r.setCookie === null, `${r.status} ${r.reason}`);
  r = await auth(MYRX, "/_auth/key", { ip, cookie: uwhcCookie, body: { site: "uwhc" } }); check("  /_auth/key from that network -> 429 JSON locked", r.status === 429 && r.out.error === "locked" && r.out.retryAfter > 0);
  r = await auth(MYRX, "/_auth/whoami", { ip, cookie: uwhcCookie }); check("  whoami has no lockout accounting (still answers)", r.status === 200 && r.out.signedIn === true);
  r = await call({ admin_pw: TEST_MASTER, action: "ping" }, { ip, env: envS }); check("  the 'master' scope is untouched", r.status === 200, `status ${r.status}`);
  r = await aa({ report_pw: TEST_REPORT_PW }, { ip, env: envS }); check("  the 'aa' scope is untouched", r.status === 200, `status ${r.status}`);
  r = await auth(AVALON, "/login/", { ip, jwt: await jwtFor("x@avalon.example") }); check("  the other site's auth scope is untouched", r.status === 302, `${r.status} ${r.reason}`);
}
// what is NOT a guess never feeds the shared per-network counter (an office NAT must not lock itself out)
{
  const ip = freshIp();
  for (let i = 0; i < 5; i++) r = await auth(MYRX, "/login/", { ip });
  check("5 bare visits to /login (no Access header) -> 401 no-token each, and", r.status === 401 && r.reason === "no-token", `${r.status} ${r.reason}`);
  r = await auth(MYRX, "/login/", { ip, jwt: await jwtFor("nurse@uwhealth.org") }); check("  a good login from that network still answers 302 (no-token is not a guess)", r.status === 302, `${r.status} ${r.reason}`);
}
{
  const ip = freshIp();
  for (let i = 0; i < 5; i++) r = await auth(MYRX, "/_auth/key", { ip, cookie: "__Host-report_session=eyJ2IjoxfQ.forged", body: { site: "uwhc" } });
  check("5 forged-cookie key requests -> 401 not signed in each, then", r.status === 401 && r.out.error === "not signed in", JSON.stringify(r.out));
  r = await auth(MYRX, "/_auth/key", { ip, cookie: uwhcCookie, body: { site: "uwhc" } }); check("  the 6th from that network -> 429 (a forged cookie IS a guess)", r.status === 429 && r.out.error === "locked", `status ${r.status}`);
  r = await auth(MYRX, "/login/", { ip, jwt: await jwtFor("nurse@uwhealth.org") }); check("  ...and /login from that network is locked too", r.status === 429 && r.reason === "locked", `${r.status} ${r.reason}`);
}
{
  const ip = freshIp();
  for (let i = 0; i < 4; i++) await auth(MYRX, "/login/", { ip, jwt: "a.b.c" });
  r = await auth(MYRX, "/login/", { ip, jwt: await jwtFor("nurse@uwhealth.org") }); check("4 failures then a good login -> 302 and the counter resets", r.status === 302);
  for (let i = 0; i < 4; i++) await auth(MYRX, "/login/", { ip, jwt: "a.b.c" });
  r = await auth(MYRX, "/login/", { ip, jwt: await jwtFor("nurse@uwhealth.org") }); check("  reset: 4 more still not locked", r.status === 302);
}
{
  const seen = [];
  const rl = (success) => ({ limit: async ({ key }) => { seen.push(key); return { success }; } });
  r = await auth(MYRX, "/_auth/key", { cookie: uwhcCookie, body: { site: "uwhc" }, env: { ...envS, ADMIN_RL: rl(false) } });
  check("ADMIN_RL says no -> /_auth/key 429 locked, key is network|auth:myrx", r.status === 429 && r.out.error === "locked" && seen.length === 1 && /^[0-9.]+\|auth:myrx$/.test(seen[0]), seen[0]);
  r = await auth(MYRX, "/login/", { jwt: await jwtFor("nurse@uwhealth.org"), env: { ...envS, ADMIN_RL: rl(false) } }); check("  ...and /login 429 locked", r.status === 429 && r.reason === "locked");
  r = await auth(MYRX, "/login/", { jwt: await jwtFor("nurse@uwhealth.org"), env: { ...envS, ADMIN_RL: { limit: async () => { throw new Error("boom"); } } } }); check("  limiter failure never blocks a login", r.status === 302);
}

// cookie / whoami
r = await auth(MYRX, "/_auth/whoami", { cookie: uwhcCookie });
check("whoami with the cookie -> signedIn, email, root:false, slugs [uwhc]", r.status === 200 && r.out.ok && r.out.configured === true && r.out.signedIn === true && r.out.email === "nurse@uwhealth.org" && r.out.root === false && r.out.slugs.join() === "uwhc", JSON.stringify(r.out));
r = await auth(MYRX, "/_auth/whoami", { cookie: "other=1; " + uwhcCookie + "; z=2" }); check("  cookie found among others", r.out.signedIn === true);
r = await auth(MYRX, "/_auth/whoami", { cookie: uwhcCookie.slice(0, -1) + (uwhcCookie.endsWith("A") ? "B" : "A") }); check("tampered signature -> signedIn:false", r.status === 200 && r.out.signedIn === false);
{
  const c = parseCookie(uwhcCookie);
  const forgedPayload = b64u(JSON.stringify({ ...c.payload, root: true }));
  r = await auth(MYRX, "/_auth/whoami", { cookie: `__Host-report_session=${forgedPayload}.${c.sig}` }); check("tampered payload (root:true) with the old signature -> signedIn:false", r.out.signedIn === false);
  r = await auth(MYRX, "/_auth/whoami", { cookie: await forgeCookie({ ...c.payload, root: true }, "not-the-secret") }); check("signed under another secret -> signedIn:false", r.out.signedIn === false);
  r = await auth(MYRX, "/_auth/whoami", { cookie: await forgeCookie({ ...c.payload, exp: nowS() - 1 }) }); check("expired cookie -> signedIn:false", r.out.signedIn === false);
  r = await auth(MYRX, "/_auth/whoami", { cookie: await forgeCookie({ ...c.payload, iat: nowS() + 600 }) }); check("iat in the future -> signedIn:false", r.out.signedIn === false);
  r = await auth(MYRX, "/_auth/whoami", { cookie: await forgeCookie({ ...c.payload, v: 2 }) }); check("v:2 -> signedIn:false", r.out.signedIn === false);
  r = await auth(MYRX, "/_auth/whoami", { cookie: await forgeCookie({ ...c.payload, slugs: "uwhc" }) }); check("slugs not an array -> signedIn:false", r.out.signedIn === false);
  r = await auth(MYRX, "/_auth/whoami", { cookie: await forgeCookie({ ...c.payload, root: "yes" }) }); check("root not boolean -> signedIn:false", r.out.signedIn === false);
  r = await auth(MYRX, "/_auth/whoami", { cookie: "__Host-report_session=" + b64u("[1]") + "." + c.sig }); check("payload not an object -> signedIn:false", r.out.signedIn === false);
  r = await auth(MYRX, "/_auth/whoami", { cookie: "__Host-report_session=nodot" }); check("no dot -> signedIn:false", r.out.signedIn === false);
  r = await auth(MYRX, "/_auth/whoami", { cookie: "__Host-report_session=" + "a".repeat(4100) + ".b" }); check("> 4096 chars -> signedIn:false", r.out.signedIn === false);
  r = await auth(MYRX, "/_auth/whoami", { cookie: await forgeCookie(c.payload) }); check("a re-signed identical payload is accepted (format check)", r.out.signedIn === true);
}
r = await auth(AVALON, "/_auth/whoami", { cookie: uwhcCookie }); check("myrx cookie on the aa host -> signedIn:false", r.status === 200 && r.out.signedIn === false && r.out.configured === true);
r = await auth(MYRX, "/_auth/whoami", { cookie: uwhcCookie, env: { ...envS, SESSION_SECRET: hex(32) } }); check("SESSION_SECRET rotated -> every cookie is dead", r.out.signedIn === false);
// revocation with a still-valid cookie: whoami/key re-resolve against the live document
r = await myrxAdmin("access.put", { access: { teamDomain: "testteam", aud: TEST_AUD, root: { emails: ["boss@corp.example"] }, clients: { uwhc: { emails: ["other@uwhealth.org"] }, aurora: { emails: ["pm@aurora.example"] } } } });
r = await auth(MYRX, "/_auth/whoami", { cookie: uwhcCookie }); check("after access.put removed the domain: whoami signedIn:true, slugs []", r.status === 200 && r.out.signedIn === true && r.out.slugs.length === 0 && r.out.root === false, JSON.stringify(r.out));
r = await auth(MYRX, "/_auth/key", { cookie: uwhcCookie, body: { site: "uwhc" } }); check("  /_auth/key -> 403 not authorized", r.status === 403 && r.out.error === "not authorized");
{
  const rec = JSON.parse(kv.store.get("myrx:access-log")), last = rec.entries[rec.entries.length - 1];
  check("  denied key request logged with the slug", last.action === "denied" && last.slug === "uwhc" && last.email === "nurse@uwhealth.org", JSON.stringify(last));
}
r = await myrxAdmin("access.put", { access: { teamDomain: "testteam", aud: TEST_AUD, root: { emails: ["boss@corp.example"] }, clients: { uwhc: { domains: ["uwhealth.org"], emails: ["contractor@gmail.com"] }, aurora: { emails: ["pm@aurora.example"] } } } });
check("  (myrx document restored)", r.status === 200);
r = await auth(MYRX, "/_auth/whoami", { cookie: uwhcCookie }); check("  whoami sees the restored mapping immediately (writer primed the cache)", r.out.slugs.join() === "uwhc");

// /_auth/key (myrx): the escrow
r = await auth(MYRX, "/_auth/key", { cookie: uwhcCookie, body: { site: "uwhc" } }); check("myrx key before any escrow -> 409 keys not escrowed yet", r.status === 409 && r.out.error === "keys not escrowed yet", JSON.stringify(r.out));
r = await auth(MYRX, "/_auth/key", { cookie: uwhcCookie, body: { site: "uwhc" }, env: { ...envS, ESCROW_KEY: undefined } }); check("myrx key without ESCROW_KEY -> 503 email sign-in not configured", r.status === 503 && r.out.error === "email sign-in not configured");
r = await auth(MYRX, "/_auth/whoami", { cookie: uwhcCookie, env: { ...envS, ESCROW_KEY: undefined } }); check("  whoami still works without ESCROW_KEY", r.status === 200 && r.out.signedIn === true);
r = await auth(MYRX, "/login/", { jwt: await jwtFor("nurse@uwhealth.org"), env: { ...envS, ESCROW_KEY: undefined } }); check("  login still works without ESCROW_KEY", r.status === 302);
r = await auth(MYRX, "/_auth/key", { cookie: uwhcCookie, body: { site: "" } }); check("root '' with a non-root session -> 403 not authorized", r.status === 403 && r.out.error === "not authorized");
r = await auth(MYRX, "/_auth/key", { cookie: uwhcCookie, body: { site: "aurora" } }); check("another client's slug -> 403", r.status === 403);
// pws.escrow validation
r = await myrxAdmin("pws.escrow", { passwords: { uwhc: "fake-partner-pw" }, root: TEST_MASTER }, { env: { ...envS, ESCROW_KEY: undefined } }); check("pws.escrow without ESCROW_KEY -> 503", r.status === 503 && r.out.error === "email sign-in not configured");
r = await myrxAdmin("pws.escrow", { passwords: [], root: TEST_MASTER }); check("pws.escrow passwords not an object -> 422", r.status === 422 && r.out.error === "passwords: must be an object" && r.out.path === "passwords");
r = await myrxAdmin("pws.escrow", { passwords: { "Bad Slug": "x" }, root: TEST_MASTER }); check("pws.escrow bad slug -> 422 passwords.Bad Slug: bad slug", r.status === 422 && r.out.error === "passwords.Bad Slug: bad slug");
r = await myrxAdmin("pws.escrow", { passwords: { uwhc: "" }, root: TEST_MASTER }); check("pws.escrow empty password -> 422 bad password", r.status === 422 && r.out.error === "passwords.uwhc: bad password");
r = await myrxAdmin("pws.escrow", { passwords: { uwhc: "x".repeat(201) }, root: TEST_MASTER }); check("pws.escrow 201-char password -> 422", r.status === 422 && r.out.path === "passwords.uwhc");
r = await myrxAdmin("pws.escrow", { passwords: { uwhc: 123 }, root: TEST_MASTER }); check("pws.escrow non-string password -> 422", r.status === 422 && r.out.path === "passwords.uwhc");
{ const many = {}; for (let i = 0; i < 201; i++) many["s" + i] = "pw"; r = await myrxAdmin("pws.escrow", { passwords: many, root: TEST_MASTER }); check("pws.escrow > 200 entries -> 422 at most 200", r.status === 422 && r.out.error === "passwords: at most 200"); }
r = await myrxAdmin("pws.escrow", { passwords: { uwhc: "fake-partner-pw" }, root: "not-the-master" }); check("pws.escrow root mismatch -> 422 root: must be the master password", r.status === 422 && r.out.error === "root: must be the master password" && r.out.path === "root");
r = await myrxAdmin("pws.escrow", { passwords: { uwhc: "fake-partner-pw" } }); check("pws.escrow root missing -> 422", r.status === 422 && r.out.path === "root");
check("  nothing escrowed by the rejected calls", !kv.store.has("myrx:pws-escrow"));
r = await call({ admin_pw: "wrong", action: "pws.escrow", passwords: {}, root: "wrong" }, { ip: freshIp(), env: envS }); check("pws.escrow without the master -> 403", r.status === 403);
r = await myrxAdmin("pws.escrow", { passwords: { UWHC: "fake-partner-pw", aurora: "aurora-partner-pw" }, root: TEST_MASTER });
check("pws.escrow valid -> {ok, updatedAt, count:2}", r.status === 200 && r.out.ok && typeof r.out.updatedAt === "string" && r.out.count === 2 && !leaks(JSON.stringify(r.out)), JSON.stringify(r.out));
{
  const raw = kv.store.get("myrx:pws-escrow"), rec = JSON.parse(raw);
  check("  myrx:pws-escrow = {v:1, updatedAt, pwsUpdatedAt (= myrx:pws.updatedAt), count, enc:{salt 16, iv 12, data}}", rec.v === 1 && rec.count === 2 && rec.pwsUpdatedAt === JSON.parse(kv.store.get("myrx:pws")).updatedAt && Buffer.from(rec.enc.salt, "base64").length === 16 && Buffer.from(rec.enc.iv, "base64").length === 12 && typeof rec.enc.data === "string", JSON.stringify(Object.keys(rec)));
  check("  ciphertext contains neither a partner password nor the master", !raw.includes("fake-partner-pw") && !raw.includes("aurora-partner-pw") && !raw.includes(TEST_MASTER));
  // the record opens with the documented scheme: key = SHA-256(ESCROW_KEY || salt)
  const material = Buffer.concat([Buffer.from(TEST_ESCROW_KEY), Buffer.from(rec.enc.salt, "base64")]);
  const key = await crypto.subtle.importKey("raw", await crypto.subtle.digest("SHA-256", material), { name: "AES-GCM" }, false, ["decrypt"]);
  let pt = null; try { pt = JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: Buffer.from(rec.enc.iv, "base64") }, key, Buffer.from(rec.enc.data, "base64")))); } catch {}
  check("  opens under SHA-256(ESCROW_KEY||salt) as {v:1, passwords (slugs lowercased), root}", pt && pt.v === 1 && pt.passwords.uwhc === "fake-partner-pw" && pt.passwords.aurora === "aurora-partner-pw" && pt.root === TEST_MASTER, JSON.stringify(pt && Object.keys(pt)));
}
r = await auth(MYRX, "/_auth/key", { cookie: uwhcCookie, body: { site: "UWHC" } }); check("myrx key after escrow -> {ok, site:uwhc, pw}", r.status === 200 && r.out.ok === true && r.out.site === "uwhc" && r.out.pw === "fake-partner-pw", JSON.stringify(r.out));
check("  key response: no CORS, no-store", r.headers.get("access-control-allow-origin") === null && r.headers.get("cache-control") === "no-store");
{ // a VALID session refused a slug: logged, never counted (the root page asks for site "" on every load)
  const ip = freshIp();
  for (let i = 0; i < 5; i++) r = await auth(MYRX, "/_auth/key", { ip, cookie: uwhcCookie, body: { site: "" } });
  check("5 root-page key requests from a client-only session -> 403 not authorized each, and", r.status === 403 && r.out.error === "not authorized", JSON.stringify(r.out));
  r = await auth(MYRX, "/_auth/key", { ip, cookie: uwhcCookie, body: { site: "uwhc" } }); check("  the session's own slug from that network still serves (a 403 with a valid cookie is not a guess)", r.status === 200 && r.out.pw === "fake-partner-pw", `status ${r.status}`);
  r = await auth(MYRX, "/login/", { ip, jwt: await jwtFor("nurse@uwhealth.org") }); check("  ...and /login from that network is not locked either", r.status === 302, `${r.status} ${r.reason}`);
  const rec = JSON.parse(kv.store.get("myrx:access-log"));
  check("  every refusal is still in the sign-in log as denied {slug:\"\"}", rec.entries.filter((e) => e.action === "denied" && e.slug === "" && e.email === "nurse@uwhealth.org").length >= 5);
}
r = await auth(MYRX, "/login/?to=%2F", { jwt: await jwtFor("boss@corp.example") });
const rootCookie = r.cookie;
check("root email login -> cookie root:true, slugs [] (root implies every client)", r.status === 302 && parseCookie(rootCookie).payload.root === true && parseCookie(rootCookie).payload.slugs.length === 0);
r = await auth(MYRX, "/_auth/key", { cookie: rootCookie, body: { site: "" } }); check("root session, site '' -> the master password", r.status === 200 && r.out.site === "" && r.out.pw === TEST_MASTER);
r = await auth(MYRX, "/_auth/key", { cookie: rootCookie, body: {} }); check("  site absent = root", r.status === 200 && r.out.pw === TEST_MASTER);
r = await auth(MYRX, "/_auth/key", { cookie: rootCookie, body: { site: "aurora" } }); check("root session opens a client too", r.status === 200 && r.out.pw === "aurora-partner-pw");
r = await auth(MYRX, "/_auth/key", { cookie: rootCookie, body: { site: "zeta" } }); check("root session, slug with no escrowed key -> 404 no key for this site", r.status === 404 && r.out.error === "no key for this site");
r = await auth(MYRX, "/_auth/key", { cookie: rootCookie, body: { site: "constructor" } }); check("  'constructor' -> 404 (own-property lookup)", r.status === 404);
r = await auth(MYRX, "/_auth/whoami", { cookie: rootCookie }); check("whoami for the root session -> root:true", r.out.signedIn === true && r.out.root === true && r.out.email === "boss@corp.example");
r = await auth(MYRX, "/_auth/key", { cookie: uwhcCookie, body: { site: "uwhc" }, env: { ...envS, ESCROW_KEY: hex(32) } }); check("a different ESCROW_KEY cannot open the escrow -> 409 keys not escrowed yet", r.status === 409 && r.out.error === "keys not escrowed yet");
r = await auth(MYRX, "/_auth/key", { cookie: uwhcCookie, body: { site: "uwhc" }, env: { ...envS, AAPS_DATA: { ...kv, get: async (k, o) => { if (k === "myrx:pws-escrow") throw new Error("kv down"); return kv.get(k, o); } }, ESCROW_KEY: hex(32) } }); check("KV throwing on the escrow -> 503 KV read failed", r.status === 503 && r.out.error === "KV read failed");
r = await auth(MYRX, "/_auth/key", { cookie: uwhcCookie, body: { site: "uwhc" } }); check("  ...and the real key still serves afterwards", r.status === 200 && r.out.pw === "fake-partner-pw");
// escrow state: ok -> stale after a vault write -> ok after a re-escrow
r = await myrxAdmin("access.get"); check("access.get escrow.state ok after the escrow", r.status === 200 && r.out.escrow.state === "ok" && r.out.escrow.count === 2 && typeof r.out.escrow.updatedAt === "string" && r.out.escrow.pwsUpdatedAt === JSON.parse(kv.store.get("myrx:pws")).updatedAt, JSON.stringify(r.out.escrow));
r = await myrxAdmin("pws.put", { enc: await encryptJSON({ v: 1, passwords: { uwhc: "rotated-partner-pw" } }, TEST_MASTER) }); check("  pws.put rotates the vault", r.status === 200);
r = await myrxAdmin("access.get"); check("  -> escrow.state stale", r.out.escrow.state === "stale", JSON.stringify(r.out.escrow));
r = await auth(MYRX, "/_auth/key", { cookie: uwhcCookie, body: { site: "uwhc" } }); check("  a stale escrow still serves the OLD password (the page must re-escrow)", r.status === 200 && r.out.pw === "fake-partner-pw");
r = await myrxAdmin("pws.escrow", { passwords: { uwhc: "rotated-partner-pw" }, root: TEST_MASTER }); check("  pws.escrow again -> count 1", r.status === 200 && r.out.count === 1);
r = await myrxAdmin("access.get"); check("  -> escrow.state ok", r.out.escrow.state === "ok" && r.out.escrow.count === 1);
r = await auth(MYRX, "/_auth/key", { cookie: uwhcCookie, body: { site: "uwhc" } }); check("  key serves the rotated password (cache re-keyed on ciphertext change)", r.status === 200 && r.out.pw === "rotated-partner-pw");
r = await auth(MYRX, "/_auth/key", { cookie: rootCookie, body: { site: "aurora" } }); check("  aurora dropped from the escrow -> 404", r.status === 404);
kv.store.set("myrx:pws-escrow", "not json{");
r = await auth(MYRX, "/_auth/key", { cookie: uwhcCookie, body: { site: "uwhc" }, env: { ...envS, ESCROW_KEY: TEST_ESCROW_KEY + "x" } }); check("garbage escrow record -> 409 (never a crash)", r.status === 409);
r = await myrxAdmin("pws.escrow", { passwords: { uwhc: "rotated-partner-pw" }, root: TEST_MASTER }); check("  (escrow restored)", r.status === 200);

// /_auth/key (aa): the vault the worker already opens
r = await auth(AVALON, "/login/?to=%2Fvault%2F", { jwt: await jwtFor("cfo@vault.example") });
const vaultCookie = r.cookie;
check("aa login for a client domain -> 302 /vault/, cookie site:aa slugs [vault]", r.status === 302 && r.headers.get("location") === "/vault/" && parseCookie(vaultCookie).payload.site === "aa" && parseCookie(vaultCookie).payload.slugs.join() === "vault", `${r.status} ${r.reason}`);
r = await auth(AVALON, "/_auth/key", { cookie: vaultCookie, body: { site: "vault" } }); check("aa key for a vault client -> its password", r.status === 200 && r.out.site === "vault" && r.out.pw === "client-vault-pw", JSON.stringify(r.out));
r = await auth(AVALON, "/_auth/key", { cookie: vaultCookie, body: { site: "" } }); check("aa root '' with a client session -> 403", r.status === 403 && r.out.error === "not authorized");
r = await auth(AVALON, "/_auth/key", { cookie: vaultCookie, body: { site: "marpai" } }); check("aa another client's slug -> 403", r.status === 403);
{
  const ip = freshIp();
  for (let i = 0; i < 5; i++) r = await auth(AVALON, "/_auth/key", { ip, cookie: vaultCookie, body: { site: "" } });
  r = await auth(AVALON, "/_auth/key", { ip, cookie: vaultCookie, body: { site: "vault" } }); check("  aa: five root-page refusals of a client session never lock the network", r.status === 200 && r.out.pw === "client-vault-pw", `status ${r.status}`);
}
r = await auth(MYRX, "/_auth/key", { cookie: vaultCookie, body: { site: "vault" } }); check("aa cookie on the myrx host -> 401 not signed in", r.status === 401 && r.out.error === "not signed in");
r = await auth(AVALON, "/login/", { jwt: await jwtFor("admin@avalon.example") });
const aaRootCookie = r.cookie;
check("aa root domain login -> root:true", r.status === 302 && parseCookie(aaRootCookie).payload.root === true);
r = await auth(AVALON, "/_auth/key", { cookie: aaRootCookie, body: { site: "" } }); check("aa root '' -> REPORT_PW", r.status === 200 && r.out.pw === TEST_REPORT_PW);
r = await auth(AVALON, "/_auth/key", { cookie: aaRootCookie, body: { site: "" }, env: { ...envS, REPORT_PW: "" } }); check("aa root '' with REPORT_PW unset -> 500 REPORT_PW not set", r.status === 500 && r.out.error === "REPORT_PW not set");
r = await auth(AVALON, "/_auth/key", { cookie: aaRootCookie, body: { site: "ghost" } }); check("aa mapped slug with no vault entry -> 404 no key for this site", r.status === 404 && r.out.error === "no key for this site");
{
  const OTHER = "sealed-pw-" + Math.random().toString(36).slice(2); // a different REPORT_PW: the vault reads as sealed (and the aaVault cache misses)
  r = await auth(AVALON, "/_auth/key", { cookie: vaultCookie, body: { site: "vault" }, env: { ...envS, REPORT_PW: OTHER } }); check("aa sealed vault -> CLIENT_PWS fallback password", r.status === 200 && r.out.pw === "client-vault-pw");
  const flaky = { ...kv, get: async (k, o) => { if (k === "aa:clients") throw new Error("kv down"); return kv.get(k, o); } };
  r = await auth(AVALON, "/_auth/key", { cookie: vaultCookie, body: { site: "vault" }, env: { ...envS, AAPS_DATA: flaky, REPORT_PW: OTHER + "2" } }); check("aa KV throwing on the vault -> 503 KV read failed (no CLIENT_PWS fallback)", r.status === 503 && r.out.error === "KV read failed", JSON.stringify(r.out));
  r = await auth(AVALON, "/_auth/key", { cookie: aaRootCookie, body: { site: "" }, env: { ...envS, AAPS_DATA: flaky, REPORT_PW: OTHER + "2" } }); check("  root '' never touches the vault -> 200", r.status === 200 && r.out.pw === OTHER + "2");
}
r = await auth(AVALON, "/_auth/whoami", { cookie: vaultCookie }); check("aa whoami -> email, root:false, slugs [vault]", r.status === 200 && r.out.signedIn === true && r.out.email === "cfo@vault.example" && r.out.root === false && r.out.slugs.join() === "vault", JSON.stringify(r.out));
{
  const rec = JSON.parse(kv.store.get("aa:access-log")), keys = rec.entries.filter((e) => e.action === "key");
  const k = keys[0];
  check("aa log: key entries {t, email, slug, action:key, net}", keys.length >= 2 && k.email === "cfo@vault.example" && k.slug === "vault" && k.action === "key" && /^\d{4}-\d\d-\d\dT/.test(k.t) && typeof k.net === "string" && Object.keys(k).sort().join() === "action,email,net,slug,t", JSON.stringify(k));
  check("  a root key entry carries slug ''", rec.entries.some((e) => e.action === "key" && e.slug === "" && e.email === "admin@avalon.example"));
  check("  no log entry ever contains a password value", !leaks(kv.store.get("aa:access-log")) && !leaks(kv.store.get("myrx:access-log")));
}
r = await aaAdmin("access.log"); check("aa access.log -> entries newest first", r.status === 200 && r.out.ok && r.out.entries.length >= 3 && r.out.entries[0].t >= r.out.entries[r.out.entries.length - 1].t && r.out.entries[0].action === "key", JSON.stringify(r.out.entries.slice(0, 2)));
r = await myrxAdmin("access.log"); check("myrx access.log -> its own entries (login / denied / key)", r.status === 200 && r.out.entries.some((e) => e.action === "login") && r.out.entries.some((e) => e.action === "denied") && r.out.entries.every((e) => !e.email.includes("avalon")), JSON.stringify(r.out.entries.length));
// cap: 500 in KV, 100 through the admin view
{
  const rec = JSON.parse(kv.store.get("myrx:access-log"));
  const filler = Array.from({ length: 519 - rec.entries.length }, (_, i) => ({ t: new Date(1700000000000 + i * 1000).toISOString(), email: "old@uwhealth.org", slug: null, action: "login", net: "203.0.113.9" }));
  kv.store.set("myrx:access-log", JSON.stringify({ v: 1, entries: [...filler, ...rec.entries] }));
  r = await auth(MYRX, "/_auth/key", { cookie: uwhcCookie, body: { site: "uwhc" } });
  const after = JSON.parse(kv.store.get("myrx:access-log"));
  check("KV record capped at 500 after the 520th append (oldest dropped, newest kept)", r.status === 200 && after.entries.length === 500 && after.entries[499].action === "key" && after.entries[499].slug === "uwhc" && after.entries[0].email !== undefined, `${after.entries.length}`);
  r = await myrxAdmin("access.log"); check("  access.log view -> 100 entries, newest first", r.status === 200 && r.out.entries.length === 100 && r.out.entries[0].action === "key" && r.out.entries[0].slug === "uwhc");
  r = await myrxAdmin("access.log", {}, { env: { ...envS, AAPS_DATA: { ...kv, get: async (k, o) => { if (k === "myrx:access-log") throw new Error("kv down"); return kv.get(k, o); } } } }); check("  access.log with KV throwing -> 503", r.status === 503 && r.out.error === "KV read failed");
  kv.store.set("myrx:access-log", "garbage{");
  r = await auth(MYRX, "/_auth/key", { cookie: uwhcCookie, body: { site: "uwhc" } }); check("a garbage log record never fails the request (best effort)", r.status === 200 && r.out.pw === "rotated-partner-pw");
  r = await myrxAdmin("access.log"); check("  ...and the log restarted from that entry", r.status === 200 && r.out.entries.length === 1 && r.out.entries[0].action === "key");
  r = await auth(MYRX, "/_auth/key", { cookie: uwhcCookie, body: { site: "uwhc" }, env: { ...envS, AAPS_DATA: { ...kv, put: async (k, v) => { if (k === "myrx:access-log") throw new Error("kv down"); return kv.put(k, v); } } } }); check("a log write failure never fails the key request", r.status === 200 && r.out.pw === "rotated-partner-pw");
}

// logout
r = await auth(MYRX, "/_auth/logout", { method: "POST", cookie: uwhcCookie }); check("logout -> {ok} with a clearing Set-Cookie (Max-Age=0)", r.status === 200 && r.out.ok === true && r.setCookie === "__Host-report_session=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0", r.setCookie);
r = await auth(MYRX, "/_auth/whoami", { cookie: r.cookie }); check("  whoami with the cleared cookie -> signedIn:false", r.status === 200 && r.out.signedIn === false);
r = await auth(MYRX, "/_auth/logout", { method: "POST" }); check("logout without a session -> still 200 + clearing cookie", r.status === 200 && /Max-Age=0/.test(r.setCookie));
check("no myrx:/aa: key ever held a partner password, client password or master in clear",
  ![...kv.store.entries()].some(([k, v]) => (k.startsWith("myrx:") || k.startsWith("aa:")) && (v.includes("fake-partner-pw") || v.includes("rotated-partner-pw") || v.includes("client-vault-pw") || v.includes(TEST_MASTER) || v.includes(TEST_REPORT_PW))));
r = await call({ admin_pw: TEST_MASTER, action: "brands.list" }, { env: envS }); check("the JSON API is untouched by part 5 (brands.list)", r.status === 200 && r.out.clients.map((c) => c.slug).join(",") === "zeta,aurora,uwhc");


globalThis.fetch = realFetch;
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
