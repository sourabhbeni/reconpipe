// reconpipe engines — JS port of the Python reconpipe/jshunter logic.
// Passive recon only: plain GETs, no exploitation.

const UA = "reconpipe/0.1 (bug-bounty recon; passive only)";
const HTTP_TIMEOUT_MS = 10000;

// ---------- secret patterns (port of jshunter/patterns.py) ----------
const PATTERNS = [
  { name: "aws-access-key-id", re: /\b(AKIA[0-9A-Z]{16})\b/,
    severity: "CRITICAL", desc: "AWS access key ID. Pair with the secret key for full account access." },
  { name: "aws-secret-key-assignment", re: /(aws_secret|aws-secret|secret[_-]?access[_-]?key)\s*[:=]\s*['"]([A-Za-z0-9/+=]{40})['"]/i,
    severity: "CRITICAL", desc: "Probable AWS secret access key in an assignment." },
  { name: "google-api-key", re: /\b(AIza[0-9A-Za-z\-_]{35})\b/,
    severity: "HIGH", desc: "Google API key. Check which APIs it can call and whether referrer-restricted." },
  { name: "google-oauth-client-id", re: /\b([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b/,
    severity: "MEDIUM", desc: "Google OAuth client ID. Useful for OAuth misconfiguration testing." },
  { name: "github-token", re: /\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,})\b/,
    severity: "CRITICAL", desc: "GitHub token. May grant repo/org access depending on scopes." },
  { name: "slack-token", re: /\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b/,
    severity: "HIGH", desc: "Slack token. Can read/post messages depending on scopes." },
  { name: "stripe-live-key", re: /\b((?:sk|rk)_live_[A-Za-z0-9]{16,})\b/,
    severity: "CRITICAL", desc: "Stripe LIVE secret/restricted key." },
  { name: "stripe-test-key", re: /\b((?:sk|rk)_test_[A-Za-z0-9]{16,})\b/,
    severity: "MEDIUM", desc: "Stripe test key. Lower risk, but shows key-handling hygiene." },
  { name: "private-key-block", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    severity: "CRITICAL", desc: "Private key material embedded in JavaScript." },
  { name: "firebase-url", re: /https:\/\/([A-Za-z0-9\-]+\.firebaseio\.com)/,
    severity: "MEDIUM", desc: "Firebase realtime DB URL. Test for world-readable/writable rules." },
  { name: "jwt-token", re: /\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b/,
    severity: "MEDIUM", desc: "JWT. Decode it: check expiry, weak signing, sensitive claims." },
  { name: "generic-api-key-assignment",
    re: /(api[_-]?key|apikey|api[_-]?secret|client[_-]?secret)\s*[:=]\s*['"]([^'"]{16,})['"]/i,
    severity: "MEDIUM", desc: "Generic API key/secret assignment.", entropyGated: true },
  { name: "generic-token-assignment",
    re: /(auth[_-]?token|access[_-]?token|bearer)\s*[:=]\s*['"]([^'"]{20,})['"]/i,
    severity: "MEDIUM", desc: "Generic auth/access token assignment.", entropyGated: true },
];

function entropy(s) {
  const counts = {};
  for (const c of s) counts[c] = (counts[c] || 0) + 1;
  let h = 0;
  for (const c in counts) {
    const p = counts[c] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function looksRandom(v) {
  if (v.length < 16) return false;
  const low = v.toLowerCase();
  for (const junk of ["example", "placeholder", "xxx", "test", "dummy", "sample",
                      "changeme", "your_", "my_", "todo", "undefined", "null"]) {
    if (low.includes(junk)) return false;
  }
  return entropy(v) >= 3.5;
}

export function scanSecrets(text) {
  const findings = [];
  const seen = new Set();
  for (const pat of PATTERNS) {
    const re = new RegExp(pat.re.source, pat.re.flags.includes("g") ? pat.re.flags : pat.re.flags + "g");
    let m;
    while ((m = re.exec(text)) !== null) {
      const value = m[m.length - 1]; // last capture group = the secret itself
      if (!value || seen.has(value)) continue;
      if (pat.entropyGated && !looksRandom(value)) continue;
      seen.add(value);
      findings.push({
        rule: pat.name, severity: pat.severity, description: pat.desc,
        preview: value.length > 16 ? value.slice(0, 6) + "..." + value.slice(-4) : value,
        length: value.length,
      });
    }
  }
  return findings;
}

// ---------- endpoint extraction (port of jshunter/endpoints.py) ----------
const FETCH_CALL = /(?:fetch|axios\.(?:get|post|put|patch|delete|request)|\$\.(?:ajax|get|post)|xmlhttp\.open|open)\s*\(\s*['"`]([^'"`]{1,200})['"`]/gi;
const QUOTED_PATH = /['"`](\/(?:api|v\d|graphql|rest|internal|admin|debug)[A-Za-z0-9\-_/{}:?=&%.]*)['"`]/g;
const ABSOLUTE_URL = /['"`](https?:\/\/[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,200}|wss?:\/\/[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,200})['"`]/g;
const CDN_SKIP = ["googleapis.com", "gstatic.com", "cloudflare.com", "jsdelivr.net",
  "unpkg.com", "facebook.net", "googletagmanager", "hotjar.com", "stripe.com/js"];

export function extractEndpoints(js) {
  const found = new Map();
  const add = (value, kind) => {
    value = value.trim();
    if (!value || value.length > 200 || value === "/" || value === "//") return;
    const k = kind + "|" + value;
    if (!found.has(k)) found.set(k, { value, kind });
  };
  let m;
  while ((m = FETCH_CALL.exec(js)) !== null) add(m[1], "fetch-call");
  while ((m = QUOTED_PATH.exec(js)) !== null) {
    const v = m[1];
    add(v, /graphql|\/gql/i.test(v) ? "graphql" : "api-path");
  }
  while ((m = ABSOLUTE_URL.exec(js)) !== null) {
    const low = m[1].toLowerCase();
    if (CDN_SKIP.some((c) => low.includes(c))) continue;
    add(m[1], "absolute-url");
  }
  return [...found.values()].sort((a, b) =>
    a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : (a.value < b.value ? -1 : 1));
}

export function extractSourcemaps(js, jsUrl) {
  const maps = [];
  const re = /\/\/#\s*sourceMappingURL=(\S+)/g;
  let m;
  while ((m = re.exec(js)) !== null) {
    const ref = m[1].trim();
    if (/^https?:\/\//.test(ref)) maps.push(ref);
    else if (ref.startsWith("//")) maps.push("https:" + ref);
    else maps.push(jsUrl.slice(0, jsUrl.lastIndexOf("/") + 1) + ref.replace(/^\.\//, ""));
  }
  return maps;
}

// ---------- subdomain enum ----------
export async function enumerateCrtsh(domain) {
  const r = await fetch(`https://crt.sh/?q=%25.${domain}&output=json`, {
    headers: { "User-Agent": UA }, signal: AbortSignal.timeout(15000),
  });
  if (!r.ok) throw new Error(`crt.sh: HTTP ${r.status}`);
  const subs = new Set();
  for (const e of await r.json()) {
    for (let n of String(e.name_value || "").split("\n")) {
      n = n.trim().toLowerCase().replace(/\.$/, "");
      if (n && !n.includes("*") && !n.includes("@") &&
          (n === domain || n.endsWith("." + domain))) subs.add(n);
    }
  }
  return [...subs].sort();
}

// ---------- live probe ----------
export async function probeLive(host) {
  for (const scheme of ["https", "http"]) {
    try {
      const r = await fetch(`${scheme}://${host}/`, {
        headers: { "User-Agent": UA }, redirect: "follow",
        signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
      });
      await r.arrayBuffer(); // drain
      if (r.status < 400) return `${scheme}://${host}`;
    } catch { /* try next scheme */ }
  }
  return null;
}

// ---------- JS hunt on one live host ----------
const SCRIPT_SRC = /<script[^>]+src=["']([^"']+)["']/gi;
const MAX_JS_FILES = 8;
const MAX_JS_BYTES = 1500000;

export async function huntJs(baseUrl) {
  const host = new URL(baseUrl).hostname;
  let html;
  try {
    const r = await fetch(baseUrl + "/", {
      headers: { "User-Agent": UA }, redirect: "follow",
      signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
    });
    if (!r.ok) return { url: baseUrl, error: `HTTP ${r.status}`, files: [] };
    html = (await r.text()).slice(0, 500000);
  } catch (e) {
    return { url: baseUrl, error: String(e.message || e).slice(0, 80), files: [] };
  }
  const jsUrls = [];
  const seen = new Set();
  let m;
  while ((m = SCRIPT_SRC.exec(html)) !== null) {
    try {
      const abs = new URL(m[1], baseUrl + "/").toString();
      const u = new URL(abs);
      if (u.hostname === host && !seen.has(abs)) { seen.add(abs); jsUrls.push(abs); }
    } catch { /* skip bad URLs */ }
    if (jsUrls.length >= MAX_JS_FILES) break;
  }
  const files = [];
  for (const jsUrl of jsUrls) {
    try {
      const r = await fetch(jsUrl, {
        headers: { "User-Agent": UA },
        signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
      });
      if (!r.ok) { files.push({ url: jsUrl, error: `HTTP ${r.status}` }); continue; }
      const buf = await r.arrayBuffer();
      const text = new TextDecoder().decode(buf.slice(0, MAX_JS_BYTES));
      files.push({
        url: jsUrl,
        secrets: scanSecrets(text),
        endpoints: extractEndpoints(text).slice(0, 60),
        sourcemaps: extractSourcemaps(text, jsUrl),
      });
    } catch (e) {
      files.push({ url: jsUrl, error: String(e.message || e).slice(0, 80) });
    }
  }
  return { url: baseUrl, files };
}

// ---------- wayback harvest ----------
const INTERESTING_PARAMS = new Set(
  ("id,q,s,search,query,keyword,url,uri,redirect,redir,next,return,returnurl," +
   "callback,file,path,page,pg,dir,folder,doc,document,template,theme,lang," +
   "locale,user,username,email,name,token,key,api_key,apikey,debug,test,admin," +
   "edit,delete").split(","));
const PATH_HINTS = ["/api/", "/graphql", "/gql", "/admin", "/debug", "/test",
  "/dev", "/staging", "/internal", "/.git/", "/.env", "swagger", "openapi.json", "wp-json"];

export async function waybackHarvest(domain, limit = 5000) {
  const params = new URLSearchParams({
    url: domain + "/*", output: "json", filter: "statuscode:200",
    collapse: "urlkey", limit: String(limit),
  });
  const r = await fetch(`http://web.archive.org/cdx/search/cdx?${params}`, {
    headers: { "User-Agent": UA }, signal: AbortSignal.timeout(20000),
  });
  if (!r.ok) throw new Error(`wayback: HTTP ${r.status}`);
  const rows = await r.json();
  const urls = [];
  for (let i = 1; i < rows.length; i++) {
    if (rows[i].length >= 3) urls.push(rows[i][2]);
  }
  const out = [];
  const seen = new Set();
  for (const u of urls) {
    if (seen.has(u)) continue;
    seen.add(u);
    let parsed;
    try { parsed = new URL(u); } catch { continue; }
    const pnames = [...parsed.searchParams.keys()].map((k) => k.toLowerCase());
    const hitParams = [...new Set(pnames.filter((k) => INTERESTING_PARAMS.has(k)))].sort();
    const low = u.toLowerCase();
    const hitPath = PATH_HINTS.some((h) => low.includes(h));
    if (hitParams.length || hitPath) {
      out.push({ url: u, params: hitParams,
                 reason: hitParams.length ? "params:" + hitParams.join(",") : "path" });
    }
    if (out.length >= 300) break;
  }
  return { seen: urls.length, interesting: out };
}
