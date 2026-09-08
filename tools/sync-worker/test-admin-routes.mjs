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

globalThis.fetch = realFetch;
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
