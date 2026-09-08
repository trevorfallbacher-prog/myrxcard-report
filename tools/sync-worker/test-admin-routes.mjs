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

import { validateBrand } from "../brand-validate.mjs";

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
const realFetch = globalThis.fetch;
globalThis.fetch = async (url) => {
  const u = String(url);
  if (u === "https://reports.myrxcard.com/config.enc.json") return new Response(JSON.stringify(fakeRootBlob), { status: 200 });
  if (/^https:\/\/reports\.myrxcard\.com\/[a-z0-9-]+\/utilization\.enc\.json$/.test(u)) return new Response(JSON.stringify(partnerBlob), { status: 200 });
  // a stand-in Xano for the routes that read after authenticating (part 3)
  if (u.startsWith("https://xano.test/")) {
    if (u.includes("/table?page=")) return new Response(JSON.stringify([{ id: 99, name: "search_events" }]), { status: 200 });
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
const TEST_REPORT_PW = "report-pw-" + Math.random().toString(36).slice(2); // stands in for REPORT_PW (= the master in production)
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
  r = await call2({ report_pw: TEST_REPORT_PW }, { ip }); check("  ...and report_pw from the same IP is locked too", r.status === 429);
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
  r = await call({ admin_pw: TEST_MASTER, action: "ping" }, { ip }); check("  ...and locks admin_pw for that IP (shared master counter)", r.status === 429);
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

globalThis.fetch = realFetch;
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
