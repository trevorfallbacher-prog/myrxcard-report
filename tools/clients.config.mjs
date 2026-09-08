// clients.config.mjs — the partner roster shared by build-clients.mjs (site
// builder) and sync-admin-kv.mjs (KV seed / password vault). One list, one
// source of truth for slug, display name, claims matcher, code-default brand
// and demo settings.
//
// Brand blocks here are the LAST-RESORT fallback: once a client has a
// "myrx:brand:<slug>" doc in KV (seeded from this file, then edited from the
// root dashboard's Clients tab) that doc wins, both at runtime on the partner
// page and in build-clients when it bakes the marker.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// slug -> which "Pharmacy Group" values (uppercased) belong to the client
export const CLIENTS = [
  { slug: "uwhc", name: "UW Health (UWHC)", type: "pharmacy", match: (g) => g === "UWHC PHARMACIES",
    brand: {
      logo: "brands/uwhc.svg", logoHeight: 26, tagline: "Pharmacy services report",
      colors: { primary: "#c5050c", secondary: "#9b0407", tertiary: "#d9484d", accent: "#065dba", accentBright: "#2b7ddb",
        dark: { primary: "#ff7075", secondary: "#ff9094", tertiary: "#d9484d", accent: "#6ea9ff", accentBright: "#8fbcff" } },
      fonts: { google: "family=Public+Sans:wght@400;500;600;700", body: "'Public Sans', 'Helvetica Neue', Arial, sans-serif", heading: "'Public Sans', 'Helvetica Neue', Arial, sans-serif" },
      headings: { transform: "uppercase", weight: 700, letterSpacing: "0.04em", gate: "UW Health", menuLabel: "REPORTS",
        tabs: { search: "Website searches", util: "Claims utilization" }, titles: { search: "Website searches", util: "Claims utilization" } },
      layout: { header: "view-first", radius: "6px", density: "compact" }, poweredBy: true } },
  { slug: "marshfield", name: "Marshfield Clinic", type: "pharmacy", match: (g) => g === "MARSHFIELD PHARMACIES" },
  { slug: "brookshire", name: "Brookshire Brothers", type: "pharmacy", match: (g) => g === "BROOKSHIRE BROTHERS PHARMACY" },
  { slug: "rrh", name: "Rochester Regional Health", type: "pharmacy", match: (g) => g.startsWith("RRH"),
    brand: {
      logo: "brands/rrh.svg", logoDark: "brands/rrh-dark.svg", logoHeight: 30, tagline: "Pharmacy savings report",
      colors: { primary: "#0077c8", secondary: "#005b99", tertiary: "#3a97d8", accent: "#e8a317", accentBright: "#f7b733",
        dark: { primary: "#5fb2f5", secondary: "#8ac8ff", tertiary: "#3a97d8", accent: "#f0b43c", accentBright: "#ffc95e" } },
      fonts: { google: "family=Source+Sans+3:wght@400;500;600;700", body: "'Source Sans 3', 'Helvetica Neue', Arial, sans-serif", heading: "'Source Sans 3', 'Helvetica Neue', Arial, sans-serif" },
      headings: { weight: 700, letterSpacing: "-0.01em", gate: "Rochester Regional Health", menuLabel: "REPORTS",
        tabs: { search: "Website searches", util: "Claims utilization" }, titles: { search: "Website searches", util: "Claims utilization" } },
      layout: { header: "title-first", radius: "8px", density: "comfortable" }, poweredBy: true } },
  { slug: "sunlife", name: "Sun Life Pharmacies", type: "pharmacy", match: (g) => g === "SUN LIFE PHARMACIES" },
  { slug: "altscripts", name: "AltScripts Specialty Pharmacy", type: "pharmacy", match: (g) => g === "ALTSCRIPTS SPECIALTY PHARMACY" },
  { slug: "ryan", name: "Ryan Pharmacy", type: "pharmacy", match: (g) => g === "RYAN PHARMACY" },
  { slug: "candc", name: "C & C Pharmacy", type: "pharmacy", match: (g) => g === "C & C PHARMACY" },
  { slug: "communitymarkets", name: "Community Markets", type: "pharmacy", match: (g) => g === "COMMUNITY MARKETS" },
  { slug: "greatscot", name: "Great Scot Pharmacies", type: "pharmacy", match: (g) => g === "GREAT SCOT PHARMACIES" },
  // ---- DEMO sites: a prospect sees the full report on anonymized, scaled claims
  // cloned from an existing partner's slice (pharmacies renamed and relocated,
  // NPIs replaced, dollars scaled). `from` names the source Pharmacy Group; the
  // page relabels the source microsite's search activity the same way.
  { slug: "aurora", name: "Aurora Health Care", type: "pharmacy", match: (g) => g === "UWHC PHARMACIES",
    demo: { from: "uwhc", scale: 0.82, groupName: "AURORA PHARMACY", note: "Demo data: anonymized, scaled sample. Not Aurora Health Care's claims.",
      locations: [
        ["Aurora Pharmacy - Saint Luke Medical Center", "2900 W Oklahoma Ave", "Milwaukee", "WI", "53215"],
        ["Aurora Pharmacy - Sinai Medical Center", "945 N 12th St", "Milwaukee", "WI", "53233"],
        ["Aurora Pharmacy - West Allis Medical Center", "8901 W Lincoln Ave", "West Allis", "WI", "53227"],
        ["Aurora Pharmacy - Grafton Medical Center", "975 Port Washington Rd", "Grafton", "WI", "53024"],
        ["Aurora Pharmacy - Summit Medical Center", "36500 Aurora Dr", "Summit", "WI", "53066"],
        ["Aurora Pharmacy - Kenosha Medical Center", "10400 75th St", "Kenosha", "WI", "53142"],
        ["Aurora Pharmacy - BayCare Medical Center", "2845 Greenbrier Rd", "Green Bay", "WI", "54311"],
        ["Aurora Pharmacy - Sheboygan Memorial", "2629 N 7th St", "Sheboygan", "WI", "53083"],
        ["Aurora Pharmacy - Oshkosh Medical Center", "855 N Westhaven Dr", "Oshkosh", "WI", "54904"],
        ["Aurora Pharmacy - Burlington Memorial", "252 McHenry St", "Burlington", "WI", "53105"],
        ["Aurora Pharmacy - Two Rivers Medical Center", "5000 Memorial Dr", "Two Rivers", "WI", "54241"],
        ["Aurora Pharmacy - Hartford Medical Center", "1032 E Sumner St", "Hartford", "WI", "53027"],
        ["Aurora Pharmacy - Mount Pleasant", "10200 Washington Ave", "Mount Pleasant", "WI", "53406"],
        ["Aurora Pharmacy - Waukesha Health Center", "1101 Delafield St", "Waukesha", "WI", "53188"],
        ["Aurora Pharmacy - Lakeland Medical Center", "W3985 County Rd NN", "Elkhorn", "WI", "53121"],
        ["Aurora Pharmacy - Marinette", "1505 Main St", "Marinette", "WI", "54143"],
        ["Aurora Pharmacy - Kaukauna", "2600 Lawe St", "Kaukauna", "WI", "54130"],
        ["Aurora Pharmacy - Fond du Lac", "210 Wisconsin American Dr", "Fond du Lac", "WI", "54937"],
      ] },
    brand: {
      logo: "brands/aurora.png", logoDark: "brands/aurora-footer.webp", logoHeight: 22, tagline: "Pharmacy performance demo",
      colors: { primary: "#00805f", secondary: "#005f47", tertiary: "#2ea083", accent: "#814fa0", accentBright: "#9d6bc0",
        dark: { primary: "#3fbf95", secondary: "#6fd6b3", tertiary: "#2ea083", accent: "#b48ad4", accentBright: "#c9a6e3" } },
      fonts: { google: "family=Montserrat:wght@400;500;600;700", body: "'Montserrat', 'Helvetica Neue', Arial, sans-serif", heading: "'Montserrat', 'Helvetica Neue', Arial, sans-serif" },
      headings: { weight: 700, letterSpacing: "-0.01em", gate: "Aurora Health Care", menuLabel: "REPORTS",
        tabs: { search: "Website searches", util: "Claims utilization" }, titles: { search: "Website searches", util: "Claims utilization" } },
      layout: { header: "title-first", radius: "10px", density: "comfortable" }, poweredBy: true } },
];

// Inline a logo file (path relative to tools/, e.g. "brands/uwhc.svg") as a
// data URI so the page needs no extra assets. undefined in -> undefined out.
export function inlineImg(rel) {
  if (!rel) return undefined;
  const buf = readFileSync(join(__dirname, rel));
  const mime = rel.endsWith(".svg") ? "image/svg+xml" : rel.endsWith(".png") ? "image/png" : rel.endsWith(".webp") ? "image/webp" : "image/jpeg";
  return `data:${mime};base64,${buf.toString("base64")}`;
}

// The code-default brand for a client with logos inlined and `name` copied in
// (exactly the shape the page's applyBrand and the worker's validateBrand
// expect), or undefined for a stock-look client.
export function codeBrand(client) {
  if (!client.brand) return undefined;
  return { ...client.brand, name: client.name, logo: inlineImg(client.brand.logo), logoDark: inlineImg(client.brand.logoDark) };
}
