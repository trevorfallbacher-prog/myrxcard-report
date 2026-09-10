# "Sign in with company email" — operator setup

Cloudflare Access (one-time email code now, Google / Microsoft SSO later)
lets a client open their report on reports.myrxcard.com or
reports.avalonsaves.com without the password. The password gates keep
working unchanged; email sign-in is a second option on the same gate.

How it fits together (all code is in `worker.js`, tests in
`test-admin-routes.mjs` part 5):

- Access protects ONLY `/login*` on each report hostname. Everything else
  stays public exactly as today.
- Two Worker Routes per hostname (`/login*`, `/_auth/*`) send those paths to
  this worker, so the `/login` handler receives Access's identity header
  (`Cf-Access-Jwt-Assertion`), verifies it against the team's JWKS, and sets
  a first-party session cookie (`__Host-report_session`, 12 h, HMAC-signed
  under `SESSION_SECRET`).
- The page then calls `/_auth/whoami` and `/_auth/key` on its own hostname;
  the worker hands back that site's password only to an email the admin
  mapped to it (`myrx:access` / `aa:access` in KV, edited from the Clients
  tab). Avalon passwords come from the `aa:clients` vault the worker already
  opens; MyRxCard passwords come from an escrow copy of `myrx:pws` that the
  admin page seals through `pws.escrow` (encrypted under `ESCROW_KEY`).
- Until the secrets, routes and Access apps exist, nothing changes:
  `/_auth/*` answers `503 {"error":"email sign-in not configured"}`, the
  pages hide the button, and the JSON API on the workers.dev hostname is
  untouched.

Do the steps in order. Steps 1 and 6 are the only ones that touch this repo's
tooling; the rest is Cloudflare dashboard work.

## 1. Worker secrets

In `tools/sync-worker`:

```sh
openssl rand -hex 32 | tr -d '\n' | npx wrangler secret put SESSION_SECRET
openssl rand -hex 32 | tr -d '\n' | npx wrangler secret put ESCROW_KEY
```

- `SESSION_SECRET` signs the session cookie. Rotating it signs everyone out.
- `ESCROW_KEY` seals the MyRxCard password escrow. Rotating it makes the
  escrow unreadable ("keys not escrowed yet") until you click UPDATE in the
  Clients tab again.
- Optional: a contact line for the "not authorized" page. Add under
  `[vars]` in `wrangler.toml`: `ACCESS_CONTACT = "support@myrxcard.com"`.
  Default text is "your report administrator".

Remember this account drops secret bindings on `wrangler deploy` — after
every deploy re-run one `wrangler secret put` (any secret) to re-bind them,
then confirm with `npx wrangler secret list` that SESSION_SECRET, ESCROW_KEY,
REPORT_PW, SYNC_SECRET, XANO_META_TOKEN, MEMBER_SALT and CLIENT_PWS are all
present.

## 2. DNS

Move both zones (myrxcard.com, avalonsaves.com) to Cloudflare. For each:

- CNAME `reports` → the GitHub Pages target (`<org>.github.io`), proxied
  (orange cloud). Worker Routes and Access only work on proxied records.
- SSL/TLS → Overview → mode **Full** (GitHub Pages serves a valid cert).
- Keep the `CNAME` file in each site repo and the custom domain + "Enforce
  HTTPS" setting on GitHub Pages as they are.

Check: the reports still load, `https://reports.myrxcard.com/_auth/whoami`
returns the GitHub Pages 404 page (no route yet) — that is expected.

## 3. Worker Routes

Workers & Pages → `myrxcard-sync` → Settings → Domains & Routes → Add → Route.
Add four routes (zone = the matching zone, failure mode "Fail closed"):

| Route                                   | Zone            |
| --------------------------------------- | --------------- |
| `reports.myrxcard.com/login*`           | myrxcard.com    |
| `reports.myrxcard.com/_auth/*`          | myrxcard.com    |
| `reports.avalonsaves.com/login*`        | avalonsaves.com |
| `reports.avalonsaves.com/_auth/*`       | avalonsaves.com |

Everything else on those hostnames keeps going to GitHub Pages.

Check: `https://reports.myrxcard.com/_auth/whoami` now returns
`{"ok":true,"configured":false,"signedIn":false}` (or the 503 "not
configured" JSON if step 1 was skipped).

## 4. Zero Trust team + login method

Zero Trust dashboard (one.dash.cloudflare.com):

- Settings → Custom Pages: note the **team domain**,
  `<team>.cloudflareaccess.com`. The `<team>` part (letters, digits, hyphens,
  no dots) is what goes in the admin box in step 6.
- Settings → Authentication → Login methods → Add new → **One-time PIN**.
  Google / Microsoft (or any SAML/OIDC IdP) can be added here later with no
  worker change: the worker only ever sees the verified email.

## 5. Access applications (one per site)

Access → Applications → Add an application → **Self-hosted**:

- Name: `MyRxCard reports sign-in`
- Application domain: `reports.myrxcard.com`, path `login`
  (this protects `/login` and everything under it, nothing else).
- Session duration: 24 h (the worker's own cookie lasts 12 h regardless).
- Identity providers: One-time PIN (and later Google / Microsoft).
- Policy: name `Allow`, action Allow, Include → **Everyone**. The worker
  enforces the email → client mapping, so an unmapped email gets the "not
  authorized" page rather than a report. For defence in depth you may
  instead use Include → "Emails ending in" → the client domains you will map
  in step 6 (then remember to keep both lists in sync).
- Save, open the application's overview and copy the **Application Audience
  (AUD) tag** — 64 hex characters.

Repeat for `reports.avalonsaves.com` (`Avalon reports sign-in`).

Optional but recommended: Settings → Authentication → App Launcher off, and
in each app's Settings → "Cookie settings" leave defaults (HttpOnly, Secure).

## 6. Admin pages: team name, AUD, who may open what

Open each report's Clients tab (master password) → the **Email sign-in** box:

1. Team name (the `<team>` from step 4) and the site's AUD tag (step 5) →
   SAVE. The status pill turns **configured**. ("worker secrets missing"
   means step 1 is not done or the bindings were dropped by a deploy.)
2. Master access: company domains and/or named people who may open the
   full dashboard. Public email providers (gmail.com, outlook.com,
   hotmail.com, yahoo.com, icloud.com, proton.me, protonmail.com, aol.com)
   are refused as domains — add such people by their full address instead.
3. Per client card → Email sign-in: allowed domains (chips) and named people
   (chips). Edits save immediately; the worker validates them again.
4. MyRxCard only: under "Email sign-in keys" click **UPDATE** once. This
   decrypts the partner vault in your browser with the master password and
   seals a copy under ESCROW_KEY so the worker can release partner
   passwords to signed-in emails. Later vault changes (rotate / seed) are
   re-escrowed automatically when the Clients tab is opened; the status line
   shows "up to date" / "stale" / "missing".

Behind the scenes these are the admin actions `access.get`, `access.put`,
`access.log` (both sites) and `pws.escrow` (MyRxCard), all master-only.

## 7. Verify

- `https://reports.myrxcard.com/_auth/whoami` →
  `{"ok":true,"configured":true,"signedIn":false}`.
- Open `https://reports.myrxcard.com/login/?to=/uwhc/` → Access asks for the
  email → one-time code → redirected to `/uwhc/` → the report unlocks and the
  gate (visible after Sign out, or via a private window) shows
  "Signed in as …" with "Sign out" and "Use a password instead".
- An email that is not mapped gets "This email is not authorized for a
  report on this site" with the contact line from step 1.
- Clients tab → SIGN-IN LOG shows the login / key / denied entries
  (`myrx:access-log`, `aa:access-log`, last 500, newest first in the UI).
- Same on reports.avalonsaves.com with a mapped client domain → `/`
  (master) or `/<slug>/`.

Troubleshooting by the `x-auth-reason` response header on `/login`:
`no-token` (Access app not protecting the path), `bad-audience` (AUD tag
mismatch), `bad-issuer` (team name wrong), `jwks-unavailable` (team name
wrong or Access outage), `not-configured` (step 6.1 or step 1 missing),
`unmapped` (email not mapped), `locked` (5 failures from one network in
10 minutes; wait 10 minutes). Only guesses count towards the lock — bad,
forged or mis-addressed tokens and cookies, and unmapped emails. A bare visit
to `/login` (`no-token`), a JWKS outage, and a signed-in user refused a report
they are not mapped to (403 `not authorized`, e.g. a client-only user opening
the root page) are never counted, because the counter is shared by everyone
behind one office network.

## 8. Pages

After editing a root `index.html`, regenerate the client copies and publish
as usual:

- MyRxCard: `node tools/build-clients.mjs --html-only`
- Avalon: `node tools/build-clients.mjs` (also refreshes `404.html`)

## Reference

Routes (same hostname as the report; site chosen by hostname):

| Method | Path            | Answer                                                              |
| ------ | --------------- | ------------------------------------------------------------------- |
| GET    | `/login?to=…`   | 302 to `to` (same-host path only, else `/`) with the session cookie |
| GET    | `/_auth/whoami` | `{ok, configured, signedIn, email?, root?, slugs?}`                 |
| POST   | `/_auth/key`    | body `{site:""|"<slug>"}` → `{ok, site, pw}`                        |
| POST   | `/_auth/logout` | `{ok}` and clears the cookie                                        |

Errors: 401 `not signed in`, 403 `not authorized`, 404 `no key for this
site`, 409 `keys not escrowed yet` (MyRxCard, until step 6.4), 429 `locked`,
503 `email sign-in not configured` / `KV read failed`.

KV documents (namespace shared with avalon-aaps; prefixes `myrx:` / `aa:`):

- `<p>:access` — `{v:1, teamDomain, aud, root:{domains,emails},
  clients:{<slug>:{domains,emails}}, updatedAt}`
- `<p>:access-log` — `{v:1, entries:[{t, email, slug, action, net}]}` (≤500)
- `myrx:pws-escrow` — `{v:1, updatedAt, pwsUpdatedAt, count, enc:{salt,iv,data}}`,
  AES-GCM under SHA-256(ESCROW_KEY ‖ salt); plaintext
  `{v:1, passwords:{slug:pw}, root:<master>}` lives only in worker memory.

Trust note: with the escrow in place the worker CAN open MyRxCard client
reports (it holds the partner passwords and the master, sealed under a
worker secret). That is the deliberate trade accepted for email sign-in;
without the escrow (or without ESCROW_KEY) MyRxCard email sign-in simply
reports "keys not escrowed yet" and the password gate is unaffected.
