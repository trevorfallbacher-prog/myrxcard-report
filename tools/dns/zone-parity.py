#!/usr/bin/env python3
"""Zone parity: parse a GoDaddy/BIND zone export, compare it with live DNS, and
(with a Cloudflare API token in tools/sync-worker/.cftoken) create the zone,
import every record, and diff Cloudflare's copy against the export.

  python3 zone-parity.py inventory <export.txt>            # parse + live-DNS check, no changes
  python3 zone-parity.py import    <export.txt> <domain>   # create zone if needed, add missing records, then diff
  python3 zone-parity.py diff      <export.txt> <domain>   # diff Cloudflare's records vs the export

Records to proxy through Cloudflare (orange cloud) are only the report hosts;
everything else is imported DNS-only so mail, Webflow, Teams, Intune, and
Pages keep resolving exactly as today.
"""
import json, os, re, subprocess, sys, urllib.request

PROXY_HOSTS = {"reports"}  # subdomains to proxy (Access + Worker Routes need this)
TOKEN_FILE = os.path.expanduser("~/myrxcard-live-report/.deploy/tools/sync-worker/.cftoken")
ACCOUNT = "b8a5fbaaa1c68973ff2775f3cf39cbc0"

def parse_zone(path):
    """Minimal BIND parser good enough for registrar exports: handles $ORIGIN, $TTL,
    @, relative names, quoted TXT (multi-string), SOA/NS lines (skipped)."""
    origin = None; ttl = 3600; recs = []
    for raw in open(path, encoding="utf-8", errors="replace"):
        line = raw.split(";")[0].rstrip() if not '"' in raw else raw.rstrip()
        if not line.strip(): continue
        if line.startswith("$ORIGIN"): origin = line.split()[1].rstrip("."); continue
        if line.startswith("$TTL"): ttl = int(re.sub(r"\D", "", line.split()[1]) or 3600); continue
        parts = re.findall(r'"[^"]*"|\S+', line)
        if not parts: continue
        name = parts[0]; i = 1
        if parts[i].isdigit(): rttl = int(parts[i]); i += 1
        else: rttl = ttl
        if parts[i].upper() == "IN": i += 1
        rtype = parts[i].upper(); i += 1
        rdata = parts[i:]
        if rtype in ("SOA", "NS") and name in ("@", origin, (origin or "") + "."): continue
        if name == "@": fqdn = origin
        elif name.endswith("."): fqdn = name.rstrip(".")
        else: fqdn = f"{name}.{origin}"
        if rtype == "TXT": content = "".join(p.strip('"') for p in rdata)
        elif rtype == "MX": content = " ".join(rdata).rstrip("."); 
        elif rtype in ("CNAME",): content = rdata[0].rstrip(".")
        else: content = " ".join(rdata)
        recs.append({"name": fqdn.lower(), "type": rtype, "content": content, "ttl": rttl, "prio": int(rdata[0]) if rtype == "MX" else None})
    return origin, recs

def dig(name, rtype):
    out = subprocess.run(["dig", "+short", rtype, name], capture_output=True, text=True).stdout.strip()
    return [l.strip().rstrip(".") for l in out.splitlines() if l.strip()]

def inventory(path):
    origin, recs = parse_zone(path)
    print(f"{origin}: {len(recs)} records in export")
    bad = 0
    for r in recs:
        live = dig(r["name"], r["type"])
        want = r["content"]
        if r["type"] == "TXT": ok = any(want.replace('" "', "") in l.replace('" "', "").replace('"', "") for l in live)
        elif r["type"] == "MX": ok = any(want.split()[-1].lower() in l.lower() for l in live)
        else: ok = any(want.lower() == l.lower() for l in live)
        flag = "ok " if ok else "LIVE MISMATCH"
        if not ok: bad += 1
        print(f"  {flag}  {r['type']:5} {r['name']:45} {want[:70]}")
    print(f"{bad} records differ from live DNS (0 expected unless the export is stale)")

def cf(method, path, body=None):
    tok = open(TOKEN_FILE).read().strip()
    req = urllib.request.Request("https://api.cloudflare.com/client/v4" + path, method=method, headers={"Authorization": "Bearer " + tok, "content-type": "application/json"}, data=json.dumps(body).encode() if body is not None else None)
    try: return json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e: return json.loads(e.read())

def zone_id(domain, create=False):
    z = cf("GET", f"/zones?name={domain}")
    if z.get("result"): return z["result"][0]["id"], z["result"][0]
    if not create: return None, None
    z = cf("POST", "/zones", {"name": domain, "account": {"id": ACCOUNT}, "type": "full"})
    if not z.get("success"): sys.exit("zone create failed: " + json.dumps(z.get("errors")))
    return z["result"]["id"], z["result"]

def cf_records(zid):
    out = []; page = 1
    while True:
        r = cf("GET", f"/zones/{zid}/dns_records?per_page=100&page={page}")
        out += r.get("result", [])
        if page >= r.get("result_info", {}).get("total_pages", 1): break
        page += 1
    return out

def key(r): return (r["name"].lower().rstrip("."), r["type"], (r.get("content") or "").lower().rstrip(".").replace('"', ""))

def diff(path, domain, do_import=False):
    origin, recs = parse_zone(path)
    zid, z = zone_id(domain, create=do_import)
    if not zid: sys.exit("zone not on Cloudflare yet (run import)")
    print(f"zone {domain} id {zid} status {z['status']} nameservers {z.get('name_servers')}")
    have = {key(r) for r in cf_records(zid)}
    missing = [r for r in recs if key(r) not in have]
    if do_import:
        for r in missing:
            body = {"type": r["type"], "name": r["name"], "content": r["content"], "ttl": 1 if r["ttl"] < 60 else r["ttl"], "proxied": r["type"] in ("A", "CNAME") and r["name"].split(".")[0] in PROXY_HOSTS}
            if r["type"] == "MX": body["priority"] = r["prio"]; body["content"] = r["content"].split(" ", 1)[1]
            res = cf("POST", f"/zones/{zid}/dns_records", body)
            print(("  added " if res.get("success") else "  FAILED ") + f"{r['type']:5} {r['name']:45} {r['content'][:60]}" + ("" if res.get("success") else "  " + json.dumps(res.get("errors"))[:160]))
        have = {key(r) for r in cf_records(zid)}; missing = [r for r in recs if key(r) not in have]
    print(f"{len(recs) - len(missing)}/{len(recs)} export records present on Cloudflare")
    for r in missing: print(f"  MISSING {r['type']:5} {r['name']:45} {r['content'][:70]}")
    extra = [r for r in cf_records(zid) if (r["name"].lower(), r["type"], (r.get("content") or "").lower().rstrip(".").replace('"', "")) not in {key(x) for x in recs}]
    for r in extra: print(f"  extra on CF {r['type']:5} {r['name']:45} {(r.get('content') or '')[:70]}  proxied={r.get('proxied')}")
    if z["status"] != "active": print("\nNAMESERVERS to set at GoDaddy:", ", ".join(z.get("name_servers", [])))

if __name__ == "__main__":
    a = sys.argv[1:]
    if not a: sys.exit(__doc__)
    if a[0] == "inventory": inventory(a[1])
    elif a[0] == "import": diff(a[1], a[2], do_import=True)
    elif a[0] == "diff": diff(a[1], a[2])
    else: sys.exit(__doc__)
