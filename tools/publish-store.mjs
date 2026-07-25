// publish-store.mjs — encrypt the existing local utilization.json and push it.
// Use after a rebuild when the store is already current and you only need to
// produce/publish the encrypted utilization.enc.json the site reads.
//
//   REPORT_PW='<report password>' node publish-store.mjs [--no-push]
//
// REPORT_PW must be the same password the report gate uses — the site
// decrypts config.enc.json and utilization.enc.json with one passphrase.
import { loadStore, writeStore, publish } from "./store.mjs";

const password = process.env.REPORT_PW || "";
if (!password) { console.error("Set REPORT_PW (the report gate password)."); process.exit(1); }

const store = loadStore();
if (!store.latest) { console.error("No local utilization.json — run build-utilization.mjs first."); process.exit(1); }

const { encrypted } = await writeStore(store, password);
console.log(`Encrypted utilization.enc.json (latest = ${store.latest})`);

if (!process.argv.includes("--no-push")) {
  const r = publish(`data: utilization ${store.latest} (admin fees)`, { encrypted });
  console.log(r.ok ? `Published: ${r.msg}` : `Publish failed: ${r.msg}`);
}
