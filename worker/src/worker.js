// reconpipe on Cloudflare Workers — serverless passive recon pipeline.
//
// POST /api/scans {domain, authorized} -> {scan_id} immediately.
// GET  /api/scans/{id}                -> poll; each poll advances the state
// machine by a bounded chunk (Workers have limited per-request CPU).
// Scan state lives in KV with a 1h TTL. Passive recon only.

import { enumerateCrtsh, probeLive, huntJs, waybackHarvest } from "./recon.js";

const SCAN_TTL = 3600;
const MAX_HOSTS = 25;
const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status, headers: { "Content-Type": "application/json" },
  });

function cleanDomain(raw) {
  return String(raw || "").trim().toLowerCase()
    .replace(/\.$/, "").replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
}

async function createScan(req, env) {
  let body;
  try { body = await req.json(); } catch { return json({ detail: "Invalid JSON" }, 400); }
  const domain = cleanDomain(body.domain);
  if (!DOMAIN_RE.test(domain)) return json({ detail: "Invalid domain (e.g. example.com)" }, 400);
  if (!body.authorized) return json({ detail: "Confirm you are authorized to recon this target" }, 400);

  const id = crypto.randomUUID().replace(/-/g, "").slice(0, 12);
  const scan = {
    id, domain, status: "enumerating",
    queue: [], hosts: [], jsResults: [],
    wayback: null, enumNote: null, error: null,
    counts: { subdomains: 0, live: 0, secrets: 0, endpoints: 0, interesting: 0 },
  };
  await env.SCANS.put(id, JSON.stringify(scan), { expirationTtl: SCAN_TTL });
  return json({ scan_id: id });
}

async function pollScan(id, env) {
  const raw = await env.SCANS.get(id);
  if (!raw) return json({ detail: "Unknown scan id" }, 404);
  const scan = JSON.parse(raw);

  try {
    if (scan.status === "enumerating") {
      const [subs, wb] = await Promise.all([
        enumerateCrtsh(scan.domain).catch((e) => ({ _error: String(e.message || e).slice(0, 80) })),
        waybackHarvest(scan.domain).catch((e) => ({ _error: String(e.message || e).slice(0, 80) })),
      ]);
      if (subs._error) {
        scan.enumNote = "crt.sh failed: " + subs._error;
        scan.counts.subdomains = 0;
        scan.queue = [scan.domain];
      } else {
        scan.counts.subdomains = subs.length;
        scan.queue = [scan.domain, ...subs].slice(0, MAX_HOSTS);
      }
      if (wb._error) {
        scan.wayback = { seen: 0, interesting: [], error: wb._error };
      } else {
        scan.wayback = wb;
        scan.counts.interesting = wb.interesting.length;
      }
      scan.hosts = [...scan.queue];
      scan.status = "probing";
    }

    if (scan.status === "probing") {
      // One host per poll: probe + full JS hunt is the heaviest unit of work.
      const host = scan.queue.shift();
      if (host !== undefined) {
        const liveUrl = await probeLive(host);
        if (liveUrl) {
          scan.counts.live++;
          const res = await huntJs(liveUrl);
          for (const f of res.files || []) {
            scan.counts.secrets += (f.secrets || []).length;
            scan.counts.endpoints += (f.endpoints || []).length;
          }
          scan.jsResults.push(res);
        }
      }
      if (!scan.queue.length) scan.status = "done";
    }

    await env.SCANS.put(id, JSON.stringify(scan), { expirationTtl: SCAN_TTL });
  } catch (e) {
    scan.status = "error";
    scan.error = String(e.message || e).slice(0, 300);
    await env.SCANS.put(id, JSON.stringify(scan), { expirationTtl: SCAN_TTL });
  }

  const { queue, ...pub } = scan;
  pub.pending = queue.length;
  return json(pub);
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === "/api/scans" && req.method === "POST") return createScan(req, env);
    const m = url.pathname.match(/^\/api\/scans\/([A-Za-z0-9]+)$/);
    if (m && req.method === "GET") return pollScan(m[1], env);
    return new Response(INDEX_HTML, { headers: { "Content-Type": "text/html;charset=utf-8" } });
  },
};
