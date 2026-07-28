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
const CHART_SYS = `You translate an analytics request about MyRxCard PHARMACY CLAIMS (utilization) data into ONE JSON chart spec. Reply with ONLY the JSON object — no prose, no code fences.

The data: quarterly pharmacy-claims facts — paid and reversed claims with dollar amounts, by month, pharmacy group, state, pharmacy, brand/generic, therapeutic class and drug.

Spec shape:
{"title": short human title,
 "chart": "bar"|"line"|"donut"|"number"|"table"|"bump"|"multiline",
 "measure": "paid_claims"|"reversed_claims"|"net_claims"|"paid_dollars"|"reversed_dollars"|"net_dollars"|"reversal_rate",
 "groupBy": null|"month"|"group"|"state"|"pharmacy"|"brand"|"class"|"drug",
 "where": object with any of: group, state (2-letter), pharmacy, brand ("brand"|"generic"), class, drug, month ("YYYY-MM"),
 "limit": integer 1-24 (top-N; default 10)}

Rules:
- "line" = the TOTAL measure over months (single series; groupBy forced to month).
- "bump" = rank-over-time: one line per groupBy item, y = that item's rank in each month's top-N. USE THIS for any "<measure> by <dimension> over time / per month" request — it is the expected look. limit = top-N per month (default 10, max 13).
- "multiline" = raw values over months, one line per top groupBy item — when they explicitly want values per item over time.
- "number" = one KPI, groupBy null. "bar"/"donut"/"table" need groupBy.
- measure meanings: paid_claims/reversed_claims = claim counts; net_claims = paid minus reversed; *_dollars = gross plan amounts; reversal_rate = reversed/paid claims as a percent.
- SCOPE: claims data ONLY. There is no website-search data here (no searches, sessions, wallet saves, prints, prices shown). If the request needs data outside this catalog, or an unexpressible shape, reply {"error":"<one sentence: what this can chart instead>"}. NEVER substitute a different measure under the requested title.

Examples:
"reversed claims by drug" -> {"title":"Reversed claims by drug","chart":"bar","measure":"reversed_claims","groupBy":"drug","where":{},"limit":10}
"reversals by drug over time" -> {"title":"Reversed claims by drug — rank over time","chart":"bump","measure":"reversed_claims","groupBy":"drug","where":{},"limit":10}
"paid dollars per month" -> {"title":"Paid dollars per month","chart":"line","measure":"paid_dollars","groupBy":"month","where":{},"limit":24}
"reversal rate by pharmacy group" -> {"title":"Reversal rate by pharmacy group","chart":"bar","measure":"reversal_rate","groupBy":"group","where":{},"limit":10}`;

const CHART_ENUM = {
  chart: ["bar", "line", "donut", "number", "table", "bump", "multiline"],
  measure: ["paid_claims", "reversed_claims", "net_claims", "paid_dollars", "reversed_dollars", "net_dollars", "reversal_rate"],
  groupBy: ["month", "group", "state", "pharmacy", "brand", "class", "drug"],
  bucket: [],
  whereKeys: ["group", "state", "pharmacy", "brand", "class", "drug", "month"],
};
function validateChartSpec(raw) {
  const s = typeof raw === "object" && raw ? raw : {};
  // A measure/groupBy OUTSIDE the enum means the model tried to chart data we
  // don't have (e.g. "reversed_claims"). Refuse loudly — silently defaulting
  // to "searches" once produced a chart wearing the user's title over the
  // wrong data, which is worse than any error.
  if (s.error) return { error: String(s.error).slice(0, 300) };
  if (s.measure && !CHART_ENUM.measure.includes(s.measure))
    return { error: `"${s.measure}" isn't in this dataset — chartable measures: ${CHART_ENUM.measure.join(", ")}.` };
  if (s.groupBy && !CHART_ENUM.groupBy.includes(s.groupBy))
    return { error: `Can't group by "${s.groupBy}" — available: ${CHART_ENUM.groupBy.join(", ")}.` };
  const spec = {
    title: String(s.title || "Untitled chart").slice(0, 120),
    chart: CHART_ENUM.chart.includes(s.chart) ? s.chart : "bar",
    measure: CHART_ENUM.measure.includes(s.measure) ? s.measure : "searches",
    groupBy: CHART_ENUM.groupBy.includes(s.groupBy) ? s.groupBy : null,
    bucket: null,
    where: {},
    limit: Math.max(1, Math.min(24, parseInt(s.limit, 10) || 10)),
  };
  if (s.where && typeof s.where === "object")
    for (const k of CHART_ENUM.whereKeys) if (s.where[k] !== undefined && s.where[k] !== null)
      spec.where[k] = typeof s.where[k] === "boolean" ? s.where[k] : String(s.where[k]).slice(0, 80);
  // structural coherence: a line is the measure over months; KPIs have no axis
  spec.bucket = null;
  if (spec.chart === "line") spec.groupBy = "month";
  if ((spec.chart === "bump" || spec.chart === "multiline") && (!spec.groupBy || spec.groupBy === "month")) spec.chart = "line";
  if (spec.chart === "bump") spec.limit = Math.min(spec.limit, 13);
  if (spec.chart === "number") spec.groupBy = null;
  if (["bar", "donut", "table"].includes(spec.chart) && !spec.groupBy) spec.chart = "number";
  return spec;
}
const parseSpecText = (text) => {
  const m = String(text).match(/\{[\s\S]*\}/);
  return m ? JSON.parse(m[0]) : null;
};
async function makeChartSpec(env, prompt) {
  // The model does not know the date and will otherwise invent month filters
  // for "last N months" (seen live: where.month "2022-11" -> empty chart).
  const chartSys = CHART_SYS + `\nToday is ${new Date().toISOString().slice(0, 10)}. The loaded data covers roughly the last four quarters. For "last N months" / "over time" ranges, OMIT the month filter entirely — the chart already plots every loaded month. Only set where.month when one specific month is named.`;
  let premiumErr = null;
  if (env.ANTHROPIC_API_KEY) {
    try {
      const r = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
        body: JSON.stringify({ model: "claude-sonnet-5", max_tokens: 600, system: chartSys,
          messages: [{ role: "user", content: prompt }] }),
      });
      const out = await r.json();
      if (!r.ok) throw new Error(out.error?.message || `Anthropic ${r.status}`);
      const spec = parseSpecText((out.content || []).map((c) => c.text || "").join(""));
      if (spec) { const v = validateChartSpec(spec); return v.error ? { error: v.error } : { spec: v, via: "claude-sonnet-5" }; }
      throw new Error("no JSON in reply");
    } catch (e) { premiumErr = `anthropic: ${e.message}`; }
  }
  if (env.OPENAI_API_KEY) {
    try {
      const r = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${env.OPENAI_API_KEY}` },
        body: JSON.stringify({ model: "gpt-4o-mini", max_tokens: 600, response_format: { type: "json_object" },
          messages: [{ role: "system", content: chartSys }, { role: "user", content: prompt }] }),
      });
      const out = await r.json();
      if (!r.ok) throw new Error(out.error?.message || `OpenAI ${r.status}`);
      const spec = parseSpecText(out.choices?.[0]?.message?.content || "");
      if (spec) { const v = validateChartSpec(spec); return v.error ? { error: v.error } : { spec: v, via: "gpt-4o-mini", note: premiumErr ? `fell back (${premiumErr})` : undefined }; }
      throw new Error("no JSON in reply");
    } catch (e) { premiumErr = `${premiumErr ? premiumErr + "; " : ""}openai: ${e.message}`; }
  }
  if (env.AI) {
    try {
      const res = await env.AI.run("@cf/meta/llama-3.3-70b-instruct-fp8-fast", {
        messages: [{ role: "system", content: chartSys }, { role: "user", content: prompt }],
        max_tokens: 600,
      });
      const spec = parseSpecText(res.response || "");
      if (spec) { const v = validateChartSpec(spec); return v.error ? { error: v.error } : { spec: v, via: "llama-3.3-70b", note: premiumErr ? `fell back (${premiumErr})` : undefined }; }
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
        const out = await makeChartSpec(env, prompt);
        return json(out, out.error ? 422 : 200);
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
