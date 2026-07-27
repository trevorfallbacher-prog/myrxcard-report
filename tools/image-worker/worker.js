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
