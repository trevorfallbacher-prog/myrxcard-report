# Utilization tooling

Turns the quarterly **MyRx … Claims … .xlsx** exports into the **Utilization** tab
on reports.myrxcard.com.

```
Drop  MyRx Avalon Claims Q2-2026.xlsx  →  Avalon Reports folder
      │
      ▼  watch-utilization.mjs  (aggregate.mjs → store.mjs)
utilization.json  (committed & pushed)
      │
      ▼  GitHub Pages redeploys
Utilization tab reads utilization.json
```

## One-time setup

```
cd tools
npm install
```

Set `REPORT_PW` to the **same passphrase that unlocks the report** — the tooling
uses it to encrypt `utilization.enc.json` (the only file it publishes). Without
it, the store is written locally but nothing is pushed.

## Run the watcher (the "folder that watches")

```
cd tools
set REPORT_PW=your-report-passphrase   &  npm run watch      (cmd.exe)
$env:REPORT_PW="your-report-passphrase"; npm run watch       (PowerShell)
```

Leave it running. It watches
`C:\Users\trevo\iCloudDrive\Desktop\Avalon Reports`.
Drop a quarterly workbook in there and it will:

1. parse it and aggregate the P (paid) / R (reversed) claim lines,
2. merge that quarter into `../utilization.json` (keyed by quarter, e.g. `2026-Q2`),
3. `git commit` + `git push` so the site updates in ~1 minute.

Options:

- `npm run watch -- "D:\some\other\folder"` — watch a different folder
- `WATCH_DIR="D:\folder" npm run watch` — same, via env var
- `PUSH=0 npm run watch` — update `utilization.json` locally but don't push

To make it start automatically at login, register `npm run watch` with Task
Scheduler (Trigger: *At log on*; Action: `cmd /c "cd /d <repo>\tools && npm run watch"`).

## Backfill past quarters manually

```
cd tools
set REPORT_PW=your-report-passphrase
node build-utilization.mjs "C:\path\Q1 file.xlsx" "C:\path\Q2 file.xlsx" --push
```

Each file becomes/updates a quarter in the period dropdown; `--push` publishes
the encrypted `utilization.enc.json`. (Publishing is refused without `REPORT_PW`.)

## The aggregation (what the numbers mean)

| Metric | How it's computed |
| --- | --- |
| Paid $ | Σ `PlanGrossAmount` over `ClaimType = P` rows |
| Reversed $ | \|Σ `PlanGrossAmount` over `ClaimType = R` rows\| |
| Collected $ | Paid $ − Reversed $ (= Σ `PlanGrossAmount` over all rows) |
| Reversed % $ | Reversed $ ÷ Paid $ |
| Paid / Reversed / Collected Claims | the same split on row counts |
| Collected $ by pharmacy | net `PlanGrossAmount` grouped by `PharmacyName`, desc |

Period label + key come from the `ProcessDate` span in the file.

## Visibility / encryption

Only `utilization.enc.json` is published, encrypted with the report passphrase
(same PBKDF2 → AES-GCM scheme as the search feed's `config.enc.json`). The
plaintext `utilization.json` stays on your machine (gitignored). The Utilization
tab decrypts it in the browser using the passphrase you enter at the gate — no
separate password.
