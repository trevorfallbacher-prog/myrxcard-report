// myrxcard-image — AI visuals for Document Studio.
//
//   POST {pw, kind: "image", prompt}  → {image:<b64>, type, via}   raster illustration
//   POST {pw, kind: "icon",  prompt}  → {svg:"<svg…>", via}        flat brand-palette icon
//
// The Avalon palette is enforced server-side: raster prompts get it appended,
// icon SVGs are instructed to use only these fills.
//
// Backends, best available first:
//   images: OpenAI gpt-image-1 → Workers AI FLUX-1 schnell
//   icons:  Anthropic Claude → OpenAI chat → Workers AI llama
//
// Secrets: TEAM_PW (required — use the report gate password),
//          OPENAI_API_KEY / ANTHROPIC_API_KEY (optional, better quality).
// NOTE: on this account a fresh `wrangler deploy` has been observed to leave
// the new version without its secret bindings — after deploying worker code,
// re-run `wrangler secret put TEAM_PW` (any secret put re-binds them all).

const BRAND = "navy #315280, teal #1c80b8, green #abc269, soft blue-gray #abbad4";
const BRAND_SUFFIX = ` — flat modern healthcare illustration, brand palette ${BRAND}, on a solid pure white #FFFFFF background (no tint, no gradient, no scene behind), no embedded text`;
const ICON_SYS =
  "You draw flat vector icons as standalone SVG markup. Reply with ONLY an <svg> element, no prose, no code fences. " +
  `Rules: viewBox="0 0 100 100"; fills ONLY from this palette: ${BRAND}, plus white; ` +
  "no gradients, no text elements, no scripts, no images, no external references; " +
  "bold simple geometric shapes that stay readable at 40px.";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "content-type",
};
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", ...CORS } });

// keep only a sane, inert <svg> element
function cleanSvg(text) {
  const m = String(text || "").match(/<svg[\s\S]*?<\/svg>/i);
  if (!m) return null;
  let svg = m[0]
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<foreignObject[\s\S]*?<\/foreignObject>/gi, "")
    .replace(/\son\w+\s*=\s*"[^"]*"/gi, "")
    .replace(/\s(?:xlink:)?href\s*=/gi, " data-href=");
  // models often omit the namespace; without it an <img> data URI renders blank
  if (!/xmlns\s*=/.test(svg)) svg = svg.replace(/<svg/i, '<svg xmlns="http://www.w3.org/2000/svg"');
  return svg;
}

// premium backends are best-effort: any failure (bad key, unverified org,
// rate limit, outage) falls through to the built-in Workers AI models so the
// feature never goes fully dark
async function makeIcon(env, prompt) {
  let premiumErr = null;
  if (env.ANTHROPIC_API_KEY) {
    try {
      const r = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
        body: JSON.stringify({ model: "claude-sonnet-5", max_tokens: 2500, system: ICON_SYS,
          messages: [{ role: "user", content: `Icon: ${prompt}` }] }),
      });
      const out = await r.json();
      if (!r.ok) throw new Error(out.error?.message || `Anthropic ${r.status}`);
      const svg = cleanSvg(out.content?.[0]?.text);
      if (svg) return { svg, via: "claude-sonnet-5" };
      throw new Error("no svg in reply");
    } catch (e) { premiumErr = `anthropic: ${e.message}`; }
  }
  if (env.OPENAI_API_KEY) {
    try {
      const r = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${env.OPENAI_API_KEY}` },
        body: JSON.stringify({ model: "gpt-4o-mini", max_tokens: 2500,
          messages: [{ role: "system", content: ICON_SYS }, { role: "user", content: `Icon: ${prompt}` }] }),
      });
      const out = await r.json();
      if (!r.ok) throw new Error(out.error?.message || `OpenAI ${r.status}`);
      const svg = cleanSvg(out.choices?.[0]?.message?.content);
      if (svg) return { svg, via: "gpt-4o-mini" };
      throw new Error("no svg in reply");
    } catch (e) { premiumErr = `openai: ${e.message}`; }
  }
  if (env.AI) {
    const res = await env.AI.run("@cf/meta/llama-3.3-70b-instruct-fp8-fast", {
      messages: [{ role: "system", content: ICON_SYS }, { role: "user", content: `Icon: ${prompt}` }],
      max_tokens: 2500,
    });
    const svg = cleanSvg(res.response);
    if (svg) return { svg, via: "llama-3.3", note: premiumErr ? `fell back (${premiumErr})` : undefined };
  }
  throw new Error(premiumErr || "icon generation needs ANTHROPIC_API_KEY or OPENAI_API_KEY");
}

async function makeImage(env, prompt, size) {
  const full = prompt + BRAND_SUFFIX;
  let premiumErr = null;
  if (env.OPENAI_API_KEY) {
    try {
      const r = await fetch("https://api.openai.com/v1/images/generations", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${env.OPENAI_API_KEY}` },
        body: JSON.stringify({ model: "gpt-image-1", prompt: full, size, quality: "medium", n: 1, background: "opaque" }),
      });
      const out = await r.json();
      if (!r.ok) throw new Error(out.error?.message || `OpenAI ${r.status}`);
      return { image: out.data[0].b64_json, type: "image/png", via: "gpt-image-1" };
    } catch (e) { premiumErr = `openai: ${e.message}`; }
  }
  if (env.AI) {
    const res = await env.AI.run("@cf/black-forest-labs/flux-1-schnell", { prompt: full, steps: 8 });
    return { image: res.image, type: "image/jpeg", via: "flux-1-schnell", note: premiumErr ? `fell back (${premiumErr})` : undefined };
  }
  throw new Error(premiumErr || "no image backend — set OPENAI_API_KEY or enable Workers AI");
}

// ---------------- prompt → chart spec (reports dashboard) ----------------
// Turns a plain-English request into a strict JSON chart spec that the
// dashboard's own renderer executes against ALREADY-LOADED search events.
// The model never sees data and never returns code — only a spec, which is
// re-validated here so the client can trust every field.
const CHART_SYS = `You translate an analytics request about MyRxCard's prescription-search data into ONE JSON chart spec. Reply with ONLY the JSON object — no prose, no code fences.

The data: one row per drug search (or card-save) on myrxcard.com and its partner microsites.

Spec shape:
{"title": short human title,
 "chart": "bar"|"line"|"donut"|"number"|"table",
 "measure": "searches"|"sessions"|"prints"|"wallet_saves"|"featured_rate"|"print_rate"|"avg_top_price",
 "groupBy": null|"microsite"|"drug"|"state"|"city"|"device"|"browser"|"platform"|"dosage",
 "bucket": null|"day"|"week"|"month",
 "where": object with any of: microsite, drug, state (2-letter code), city, device ("mobile"|"desktop"), platform ("apple"|"google"|"physical"), printed (bool), wallet_saved (bool), featured (bool),
 "limit": integer 1-24 (top-N; default 10)}

Rules:
- "line" needs bucket (default "week") and uses groupBy null (single series).
- "number" = one KPI, groupBy null.
- "bar"/"donut"/"table" need groupBy.
- measure meanings: searches = search count; sessions = unique visitors; prints = physical card prints; wallet_saves = Apple/Google wallet saves; featured_rate = share of searches showing a featured pharmacy; print_rate = prints per search; avg_top_price = average best price shown.
- microsite values are partner names like "Vault Strategies", "Rochester Regional Health", "Brookshire Brothers", "UW Health (UWHC)", "VIP", "Direct site".

Examples:
"wallet saves by platform" -> {"title":"Wallet saves by platform","chart":"donut","measure":"wallet_saves","groupBy":"platform","bucket":null,"where":{},"limit":10}
"weekly searches on vault" -> {"title":"Vault Strategies — searches per week","chart":"line","measure":"searches","groupBy":null,"bucket":"week","where":{"microsite":"Vault Strategies"},"limit":10}
"top 5 drugs printed on mobile" -> {"title":"Top drugs printed on mobile","chart":"bar","measure":"prints","groupBy":"drug","bucket":null,"where":{"device":"mobile"},"limit":5}`;

const CHART_ENUM = {
  chart: ["bar", "line", "donut", "number", "table"],
  measure: ["searches", "sessions", "prints", "wallet_saves", "featured_rate", "print_rate", "avg_top_price"],
  groupBy: ["microsite", "drug", "state", "city", "device", "browser", "platform", "dosage"],
  bucket: ["day", "week", "month"],
  whereKeys: ["microsite", "drug", "state", "city", "device", "platform", "printed", "wallet_saved", "featured"],
};
function validateChartSpec(raw) {
  const s = typeof raw === "object" && raw ? raw : {};
  const spec = {
    title: String(s.title || "Untitled chart").slice(0, 120),
    chart: CHART_ENUM.chart.includes(s.chart) ? s.chart : "bar",
    measure: CHART_ENUM.measure.includes(s.measure) ? s.measure : "searches",
    groupBy: CHART_ENUM.groupBy.includes(s.groupBy) ? s.groupBy : null,
    bucket: CHART_ENUM.bucket.includes(s.bucket) ? s.bucket : null,
    where: {},
    limit: Math.max(1, Math.min(24, parseInt(s.limit, 10) || 10)),
  };
  if (s.where && typeof s.where === "object")
    for (const k of CHART_ENUM.whereKeys) if (s.where[k] !== undefined && s.where[k] !== null)
      spec.where[k] = typeof s.where[k] === "boolean" ? s.where[k] : String(s.where[k]).slice(0, 80);
  // structural coherence: lines are single-series over time; KPIs have no axis
  if (spec.chart === "line") { spec.groupBy = null; if (!spec.bucket) spec.bucket = "week"; }
  else spec.bucket = null;
  if (spec.chart === "number") spec.groupBy = null;
  if (["bar", "donut", "table"].includes(spec.chart) && !spec.groupBy) spec.chart = "number";
  return spec;
}
const parseSpecText = (text) => {
  const m = String(text).match(/\{[\s\S]*\}/);
  return m ? JSON.parse(m[0]) : null;
};
async function makeChartSpec(env, prompt) {
  let premiumErr = null;
  if (env.ANTHROPIC_API_KEY) {
    try {
      const r = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
        body: JSON.stringify({ model: "claude-sonnet-5", max_tokens: 600, system: CHART_SYS,
          messages: [{ role: "user", content: prompt }] }),
      });
      const out = await r.json();
      if (!r.ok) throw new Error(out.error?.message || `Anthropic ${r.status}`);
      const spec = parseSpecText((out.content || []).map((c) => c.text || "").join(""));
      if (spec) return { spec: validateChartSpec(spec), via: "claude-sonnet-5" };
      throw new Error("no JSON in reply");
    } catch (e) { premiumErr = `anthropic: ${e.message}`; }
  }
  if (env.OPENAI_API_KEY) {
    try {
      const r = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${env.OPENAI_API_KEY}` },
        body: JSON.stringify({ model: "gpt-4o-mini", max_tokens: 600, response_format: { type: "json_object" },
          messages: [{ role: "system", content: CHART_SYS }, { role: "user", content: prompt }] }),
      });
      const out = await r.json();
      if (!r.ok) throw new Error(out.error?.message || `OpenAI ${r.status}`);
      const spec = parseSpecText(out.choices?.[0]?.message?.content || "");
      if (spec) return { spec: validateChartSpec(spec), via: "gpt-4o-mini", note: premiumErr ? `fell back (${premiumErr})` : undefined };
      throw new Error("no JSON in reply");
    } catch (e) { premiumErr = `${premiumErr ? premiumErr + "; " : ""}openai: ${e.message}`; }
  }
  if (env.AI) {
    try {
      const res = await env.AI.run("@cf/meta/llama-3.3-70b-instruct-fp8-fast", {
        messages: [{ role: "system", content: CHART_SYS }, { role: "user", content: prompt }],
        max_tokens: 600,
      });
      const spec = parseSpecText(res.response || "");
      if (spec) return { spec: validateChartSpec(spec), via: "llama-3.3-70b", note: premiumErr ? `fell back (${premiumErr})` : undefined };
      premiumErr = `${premiumErr ? premiumErr + "; " : ""}llama: no JSON (${String(res.response || "").slice(0, 80)})`;
    } catch (e) { premiumErr = `${premiumErr ? premiumErr + "; " : ""}llama: ${e.message}`; }
  }
  throw new Error(premiumErr || "chart generation needs an AI backend");
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
    if (req.method !== "POST") return json({ error: "POST only" }, 405);
    let body;
    try { body = await req.json(); } catch { return json({ error: "bad json" }, 400); }
    if (!env.TEAM_PW || body.pw !== env.TEAM_PW) return json({ error: "bad password" }, 403);
    const prompt = String(body.prompt || "").slice(0, 2000).trim();
    if (!prompt) return json({ error: "empty prompt" }, 400);
    const size = ["1024x1024", "1536x1024", "1024x1536"].includes(body.size) ? body.size : "1024x1024";
    try {
      if (body.kind === "chart") {
        return json(await makeChartSpec(env, prompt));
      }
      if (body.kind === "icon") {
        const out = await makeIcon(env, prompt);
        if (!out.svg) return json({ error: "model did not return usable SVG — try rewording" }, 502);
        return json(out);
      }
      return json(await makeImage(env, prompt, size));
    } catch (e) {
      return json({ error: String((e && e.message) || e) }, 500);
    }
  },
};
