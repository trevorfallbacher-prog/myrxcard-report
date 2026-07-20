// build-utilization.mjs — one-shot: aggregate one or more .xlsx files into
// utilization.json. Optionally push. Useful for backfilling past quarters.
//
//   node build-utilization.mjs "C:\path\to\MyRx Avalon Claims Q2-2026.xlsx" [more.xlsx ...] [--push]
import { mergeFile, writeStore, loadStore, publish } from "./store.mjs";

const args = process.argv.slice(2);
const doPush = args.includes("--push");
const files = args.filter((a) => !a.startsWith("--"));

if (!files.length) {
  console.error('Usage: node build-utilization.mjs "<file.xlsx>" [more.xlsx ...] [--push]');
  process.exit(1);
}

let store = loadStore();
for (const f of files) {
  const res = mergeFile(f, store);
  store = res.store;
  const m = res.period.money, c = res.period.claims;
  console.log(`✓ ${res.key}  ${res.period.periodLabel}`);
  console.log(`   Paid $${m.paid.toLocaleString()} · Reversed $${m.reversed.toLocaleString()} · Collected $${m.collected.toLocaleString()} (${(m.reversedPct * 100).toFixed(1)}% reversed)`);
  console.log(`   Paid ${c.paid.toLocaleString()} claims · ${res.period.pharmacies.length} pharmacies`);
}
const password = process.env.REPORT_PW || "";
const { encrypted } = await writeStore(store, password);
console.log(`\nWrote utilization.json${encrypted ? " + utilization.enc.json (encrypted)" : ""} — latest = ${store.latest}`);
if (!encrypted) console.log("Note: set REPORT_PW to also write the encrypted utilization.enc.json that the site reads.");

if (doPush) {
  if (!encrypted) { console.error("Refusing to publish plaintext. Set REPORT_PW to encrypt, then --push."); process.exit(1); }
  const r = publish(`data: utilization ${store.latest}`, { encrypted });
  console.log(r.ok ? `Published: ${r.msg}` : `Publish failed: ${r.msg}`);
}
