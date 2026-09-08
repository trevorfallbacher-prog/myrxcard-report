// brand-validate.mjs — the partner-brand schema check shared by the sync
// worker (brand.put), build-clients.mjs (before a KV doc is baked into a
// committed <slug>/index.html) and test-admin-routes.mjs. The page mirrors
// the same rules in checkBrand as defense in depth.
//
// The worker imports this file relatively; wrangler bundles it on deploy.
// No Cloudflare or Node imports here — plain ESM so it runs anywhere.

// ---- partner brand validation (reports.myrxcard.com admin) ----
// The partner page's applyBrand interpolates several of these strings into a
// <style> block and the Google Fonts URL, so every field is whitelisted and
// pattern-checked here (and mirrored in the page as defense in depth).
// Unknown keys are rejected at every level. Returns null when valid — after
// normalizing in place (colors lowercased, control characters stripped) — or
// { path: "brand.colors.dark.primary", reason, status } naming the offender.
export const BRAND_TEXT_MAX = 80;
export const BRAND_LOGO_MAX = 200000;
export const BRAND_DOC_MAX = 600000;
export const BRAND_HEX_RE = /^#[0-9a-f]{6}$/;
export const BRAND_LOGO_RE = /^data:image\/(svg\+xml|png|webp|jpeg);base64,[A-Za-z0-9+/=]+$/;
export const BRAND_FONT_GOOGLE_RE = /^family=[A-Za-z0-9+:;@,.\-]{1,200}(&family=[A-Za-z0-9+:;@,.\-]{1,200}){0,3}$/;
export const BRAND_FONT_STACK_RE = /^[A-Za-z0-9 ,'"\-]{1,120}$/;
export const BRAND_LETTER_SPACING_RE = /^-?0?\.\d{1,3}em$|^0$/;
export const BRAND_RADIUS_RE = /^([0-9]|1[0-9]|2[0-4])px$/;
export const BRAND_COLOR_KEYS = ["primary", "secondary", "tertiary", "accent", "accentBright"];
export const BRAND_KEYS = {
  root: ["name", "logo", "logoDark", "logoHeight", "tagline", "poweredBy", "colors", "fonts", "headings", "layout"],
  colors: [...BRAND_COLOR_KEYS, "dark"],
  fonts: ["google", "body", "heading", "mono"],
  headings: ["transform", "weight", "letterSpacing", "gate", "menuLabel", "tabs", "titles"],
  headingsPair: ["search", "util"],
  layout: ["header", "radius", "density"],
};
export const BRAND_ENUMS = {
  transform: ["none", "uppercase", "capitalize"],
  header: ["view-first", "title-first"],
  density: ["comfortable", "compact"],
};
export const isPlainObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
export function validateBrand(b) {
  const fail = (path, reason, status) => ({ path, reason, status: status || 422 });
  if (!isPlainObject(b)) return fail("brand", "must be an object");
  if (JSON.stringify(b).length > BRAND_DOC_MAX) return fail("brand", "too large", 413);
  // helpers: each checks one key of `obj`, normalizes in place, returns an error or null
  const unknown = (obj, allowed, path) => {
    for (const k of Object.keys(obj)) if (!allowed.includes(k)) return fail(`${path}.${k}`, "unknown key");
    return null;
  };
  const text = (obj, k, path) => {
    const v = obj[k];
    if (v === undefined) return null;
    if (typeof v !== "string") return fail(path, "must be a string");
    const s = v.replace(/[\x00-\x1f\x7f]/g, "");
    if (s.length > BRAND_TEXT_MAX) return fail(path, `too long (max ${BRAND_TEXT_MAX} characters)`);
    if (/[<>]/.test(s)) return fail(path, "must not contain < or >");
    obj[k] = s;
    return null;
  };
  const color = (obj, k, path) => {
    const v = obj[k];
    if (v === undefined) return null;
    if (typeof v !== "string") return fail(path, "must be a string");
    const s = v.toLowerCase();
    if (!BRAND_HEX_RE.test(s)) return fail(path, "must be a 6-digit hex color like #1a2b3c");
    obj[k] = s;
    return null;
  };
  const pattern = (obj, k, path, re, why) => {
    const v = obj[k];
    if (v === undefined) return null;
    if (typeof v !== "string") return fail(path, "must be a string");
    if (!re.test(v)) return fail(path, why);
    return null;
  };
  const oneOf = (obj, k, path, list) => {
    const v = obj[k];
    if (v === undefined) return null;
    if (!list.includes(v)) return fail(path, `must be one of ${list.join(", ")}`);
    return null;
  };
  const intRange = (obj, k, path, lo, hi) => {
    const v = obj[k];
    if (v === undefined) return null;
    if (!Number.isInteger(v) || v < lo || v > hi) return fail(path, `must be a whole number from ${lo} to ${hi}`);
    return null;
  };
  const logo = (obj, k, path) => {
    const v = obj[k];
    if (v === undefined) return null;
    if (typeof v !== "string") return fail(path, "must be a string");
    if (v.length > BRAND_LOGO_MAX) return fail(path, `too large (max ${BRAND_LOGO_MAX} characters)`, 413);
    if (!BRAND_LOGO_RE.test(v)) return fail(path, "must be a base64 data URI of type svg+xml, png, webp or jpeg");
    return null;
  };
  const colorSet = (obj, path) => {
    for (const k of BRAND_COLOR_KEYS) { const e = color(obj, k, `${path}.${k}`); if (e) return e; }
    return null;
  };
  let e;
  if ((e = unknown(b, BRAND_KEYS.root, "brand"))) return e;
  if ((e = text(b, "name", "brand.name"))) return e;
  if ((e = logo(b, "logo", "brand.logo"))) return e;
  if ((e = logo(b, "logoDark", "brand.logoDark"))) return e;
  if ((e = intRange(b, "logoHeight", "brand.logoHeight", 12, 80))) return e;
  if ((e = text(b, "tagline", "brand.tagline"))) return e;
  if (b.poweredBy !== undefined && typeof b.poweredBy !== "boolean") return fail("brand.poweredBy", "must be true or false");
  if (b.colors !== undefined) {
    if (!isPlainObject(b.colors)) return fail("brand.colors", "must be an object");
    if ((e = unknown(b.colors, BRAND_KEYS.colors, "brand.colors"))) return e;
    if ((e = colorSet(b.colors, "brand.colors"))) return e;
    if (b.colors.dark !== undefined) {
      if (!isPlainObject(b.colors.dark)) return fail("brand.colors.dark", "must be an object");
      if ((e = unknown(b.colors.dark, BRAND_COLOR_KEYS, "brand.colors.dark"))) return e;
      if ((e = colorSet(b.colors.dark, "brand.colors.dark"))) return e;
    }
  }
  if (b.fonts !== undefined) {
    if (!isPlainObject(b.fonts)) return fail("brand.fonts", "must be an object");
    if ((e = unknown(b.fonts, BRAND_KEYS.fonts, "brand.fonts"))) return e;
    if ((e = pattern(b.fonts, "google", "brand.fonts.google", BRAND_FONT_GOOGLE_RE, "must be Google Fonts family= parameters only (up to 4 families)"))) return e;
    for (const k of ["body", "heading", "mono"]) {
      if ((e = pattern(b.fonts, k, `brand.fonts.${k}`, BRAND_FONT_STACK_RE, "must be a font-family list (letters, digits, spaces, commas, quotes, hyphens; max 120)"))) return e;
    }
  }
  if (b.headings !== undefined) {
    const h = b.headings;
    if (!isPlainObject(h)) return fail("brand.headings", "must be an object");
    if ((e = unknown(h, BRAND_KEYS.headings, "brand.headings"))) return e;
    if ((e = oneOf(h, "transform", "brand.headings.transform", BRAND_ENUMS.transform))) return e;
    if ((e = intRange(h, "weight", "brand.headings.weight", 300, 900))) return e;
    if ((e = pattern(h, "letterSpacing", "brand.headings.letterSpacing", BRAND_LETTER_SPACING_RE, "must be an em value like 0.02em or -0.01em (or 0)"))) return e;
    if ((e = text(h, "gate", "brand.headings.gate"))) return e;
    if ((e = text(h, "menuLabel", "brand.headings.menuLabel"))) return e;
    for (const grp of ["tabs", "titles"]) {
      if (h[grp] === undefined) continue;
      if (!isPlainObject(h[grp])) return fail(`brand.headings.${grp}`, "must be an object");
      if ((e = unknown(h[grp], BRAND_KEYS.headingsPair, `brand.headings.${grp}`))) return e;
      for (const k of BRAND_KEYS.headingsPair) if ((e = text(h[grp], k, `brand.headings.${grp}.${k}`))) return e;
    }
  }
  if (b.layout !== undefined) {
    const l = b.layout;
    if (!isPlainObject(l)) return fail("brand.layout", "must be an object");
    if ((e = unknown(l, BRAND_KEYS.layout, "brand.layout"))) return e;
    if ((e = oneOf(l, "header", "brand.layout.header", BRAND_ENUMS.header))) return e;
    if ((e = pattern(l, "radius", "brand.layout.radius", BRAND_RADIUS_RE, "must be a whole pixel value from 0px to 24px"))) return e;
    if ((e = oneOf(l, "density", "brand.layout.density", BRAND_ENUMS.density))) return e;
  }
  return null;
}

// The client display name follows the same text rules as brand strings and
// must be present. Returns { name } (control characters stripped, trimmed)
// or { error } naming the reason.
export function validateName(v) {
  if (typeof v !== "string") return { error: "must be a string" };
  const name = v.replace(/[\x00-\x1f\x7f]/g, "").trim();
  if (!name) return { error: "required" };
  if (name.length > BRAND_TEXT_MAX) return { error: `too long (max ${BRAND_TEXT_MAX} characters)` };
  if (/[<>]/.test(name)) return { error: "must not contain < or >" };
  return { name };
}
