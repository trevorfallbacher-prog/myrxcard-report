// watch-utilization.mjs — watch the Avalon Reports folder for quarterly claims
// .xlsx files. On each new/updated file: aggregate → merge into utilization.json
// → commit & push so the report site's Utilization tab updates.
//
//   node watch-utilization.mjs                 (uses default folder below)
//   node watch-utilization.mjs "C:\some\folder"
//   WATCH_DIR="C:\some\folder" node watch-utilization.mjs
//
// Set PUSH=0 to update utilization.json locally without pushing.
import chokidar from "chokidar";
import { basename } from "node:path";
import { mergeFile, writeStore, loadStore, publish } from "./store.mjs";

const WATCH_DIR = process.argv[2] || process.env.WATCH_DIR ||
  "C:\\Users\\trevo\\iCloudDrive\\Desktop\\Avalon Reports";
const DO_PUSH = process.env.PUSH !== "0";
const PASSWORD = process.env.REPORT_PW || ""; // required to publish (encrypts utilization.enc.json)

const isReport = (p) => {
  const b = basename(p).toLowerCase();
  return b.endsWith(".xlsx") && !b.startsWith("~$"); // ignore Excel lock files
};

const stamp = () => new Date().toLocaleTimeString("en-US");
const log = (...a) => console.log(`[${stamp()}]`, ...a);

// Serialize processing so two quick file events can't race on the store/git.
let queue = Promise.resolve();
const seen = new Map(); // path -> last size, to debounce partial copies

function handle(path) {
  if (!isReport(path)) return;
  queue = queue.then(() => process(path)).catch((e) => log("ERROR:", e.message));
}

async function process(path) {
  log(`Detected ${basename(path)} — aggregating…`);
  let res;
  try {
    res = mergeFile(path, loadStore());
  } catch (e) {
    log(`Could not parse ${basename(path)}: ${e.message}`);
    return;
  }
  const { encrypted } = await writeStore(res.store, PASSWORD);
  const m = res.period.money;
  log(`Merged ${res.key} (${res.period.periodLabel}) — Paid $${m.paid.toLocaleString()}, Collected $${m.collected.toLocaleString()}, ${res.period.pharmacies.length} pharmacies.`);

  if (!DO_PUSH) { log("PUSH=0 — store updated locally, not pushed."); return; }
  if (!encrypted) { log("Not published: set REPORT_PW so the store can be encrypted before pushing."); return; }
  const r = publish(`data: utilization ${res.key} (${res.period.sourceFile})`, { encrypted });
  log(r.ok ? `Published → reports.myrxcard.com will update shortly (${r.msg}).` : `Publish failed: ${r.msg}`);
}

console.log("──────────────────────────────────────────────");
console.log(" MyRxCard · Utilization watcher");
console.log(" Watching:", WATCH_DIR);
console.log(" Push:    ", DO_PUSH ? "on (git commit + push)" : "off (local only)");
console.log(" Encrypt: ", PASSWORD ? "on (utilization.enc.json)" : "OFF — set REPORT_PW to publish");
console.log(" Drop a quarterly 'MyRx …Claims….xlsx' here to update the report.");
console.log("──────────────────────────────────────────────");

chokidar
  .watch(WATCH_DIR, {
    ignoreInitial: false,           // process any file already sitting in the folder
    awaitWriteFinish: { stabilityThreshold: 2500, pollInterval: 300 }, // wait for copy to finish
    depth: 0,
  })
  .on("add", handle)
  .on("change", handle)
  .on("error", (e) => log("Watcher error:", e.message))
  .on("ready", () => log("Ready. Watching for .xlsx drops…"));
