# Zoho → Xano sync (Avalon processes, aggregates only)

PHI posture: records never leave Zoho. A CRM workflow recomputes the touched
aggregate bucket (process × pharmacy × month) inside Zoho and pushes the
rollup to the `myrxcard-sync` worker, which enforces a strict field whitelist
plus PHI tripwires (SSN/DOB/email/phone patterns) and upserts into Xano.
One bad row rejects the whole batch.

## Setup order

1. **Secrets** (Terminal, in this folder):
   ```sh
   openssl rand -hex 24            # this is your SYNC_SECRET — copy it
   printf '%s' 'THE-SECRET' | npx wrangler secret put SYNC_SECRET
   printf '%s' 'https://…xano.io/api:…/avalon_upsert' | npx wrangler secret put XANO_ENDPOINT
   printf '%s' 'THE-XANO-KEY' | npx wrangler secret put XANO_API_KEY   # optional
   ```
2. **Xano**: Add table `avalon_processes` with fields matching the worker
   whitelist (bucket_key text unique, process, pharmacy_name, pharmacy_npi,
   state, month, record_count, open_count, completed_count, amount,
   amount_secondary). Add POST endpoint `avalon_upsert`: for each row in
   input `rows[]`, upsert by `bucket_key` (Query one → exists ? Edit : Add).
   Require an API key if you set XANO_API_KEY.
3. **Zoho CRM**: Settings → Automation → Workflow Rules → on Create/Edit of
   the Avalon process module → run Function. Paste
   `zoho-deluge-template.txt`, fill the placeholders (module + field API
   names), paste the same SYNC_SECRET.
4. Deploy/redeploy worker: `npx wrangler deploy` — then re-run one
   `wrangler secret put` (this account drops secret bindings on deploy).

Reports then read `avalon_processes` from Xano exactly like `search_events`.
