// Builds a single-file Worker bundle for raw API deploys (no wrangler needed):
// bundles src/worker.js + src/recon.js, then inlines public/index.html
// wherever the source falls back from env.ASSETS.
//
// Usage: node build-api-bundle.mjs   -> writes dist/worker.api.mjs
import { execSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const dir = dirname(fileURLToPath(import.meta.url));
mkdirSync(join(dir, "dist"), { recursive: true });

execSync("npx -y esbuild src/worker.js --bundle --format=esm --outfile=dist/worker.bundle.mjs --log-level=error", { cwd: dir });

let bundle = readFileSync(join(dir, "dist/worker.bundle.mjs"), "utf8");
const html = readFileSync(join(dir, "public/index.html"), "utf8");
// worker.js ends with `return new Response(INDEX_HTML, ...)` — INDEX_HTML is
// defined at the top of the bundle so the reference resolves.
bundle = `const INDEX_HTML = ${JSON.stringify(html)};\n` + bundle;
if (!bundle.includes("INDEX_HTML")) throw new Error("bundle build failed");
writeFileSync(join(dir, "dist/worker.api.mjs"), bundle);
console.log(`wrote dist/worker.api.mjs (${bundle.length} bytes)`);
