// enview ui: does the security posture actually hold, and do the writes round-trip?
// Runs against a throwaway .env so no real secret is touched.
import { mkdtempSync, readFileSync, writeFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest } from "node:http";
import { startEnviewUi } from "../src/server.js";

const dir = mkdtempSync(join(tmpdir(), "enview-ui-"));
const envPath = join(dir, ".env");
const ORIGINAL = [
  "# a comment that must survive",
  "",
  'API_KEY="sk-test-abcdef123456"', // gitleaks:allow — synthetic fixture, not a real key
  "PORT=3000",
  "EMPTY=",
  "QUOTED='single quoted value'",
  "",
].join("\n");
writeFileSync(envPath, ORIGINAL);

const { server, token, port } = await startEnviewUi({ roots: [dir], port: 4179, maxDepth: 2 });
const base = `http://127.0.0.1:${port}`;
let pass = 0, fail = 0;
const check = (name, ok, detail = "") => {
  if (ok) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name} ${detail}`); }
};

const call = (path, opts = {}) => fetch(base + path, {
  ...opts,
  headers: { "x-enview-token": token, "content-type": "application/json", ...(opts.headers || {}) },
});

console.log("\n--- security ---");
let r = await fetch(`${base}/api/projects`);
check("no token is rejected", r.status === 401);

r = await fetch(`${base}/api/projects`, { headers: { "x-enview-token": "wrong-token-of-same-length-xxxxxxxxxxxxxxxxxxx" } });
check("wrong token is rejected", r.status === 401);

// fetch() forbids setting Host, so it would silently send the real one and prove nothing.
// A rebinding attack sets it on the wire, so the test has to as well.
const rawHost = (hostHeader) => new Promise((resolve) => {
  const req = httpRequest({ host: "127.0.0.1", port, path: "/api/projects", method: "GET",
    headers: { host: hostHeader, "x-enview-token": token } }, (res) => {
    res.resume();
    res.on("end", () => resolve(res.statusCode));
  });
  req.on("error", () => resolve(0));
  req.end();
});
check("spoofed Host rejected (DNS rebinding)", (await rawHost("evil.example.com")) === 403);
check("rebound Host:port rejected", (await rawHost(`attacker.test:${port}`)) === 403);
check("legitimate Host accepted", (await rawHost(`127.0.0.1:${port}`)) === 200);

r = await call("/api/projects", { headers: { origin: "https://evil.example.com" } });
check("bad Origin is rejected", r.status === 403, `got ${r.status}`);

r = await call("/api/value?file=" + encodeURIComponent(join(dir, "..", "..", "secrets.env")) + "&key=X");
check("path outside the scan allowlist is rejected", r.status === 404, `got ${r.status}`);

r = await call("/api/projects");
check("no CORS header is exposed", !r.headers.get("access-control-allow-origin"));
check("responses are no-store", (r.headers.get("cache-control") || "").includes("no-store"));

console.log("\n--- listing ---");
const data = await r.json();
const file = data.projects[0].files[0];
check("file discovered", !!file, JSON.stringify(data.projects));
check("4 keys listed", file.keys.length === 4, `got ${file.keys.length}`);
check("values are masked in the listing", !JSON.stringify(file).includes("sk-test-abcdef123456"));
check("API_KEY flagged credential-shaped", file.keys.find((k) => k.key === "API_KEY")?.sensitive === true);
check("EMPTY reported empty", file.keys.find((k) => k.key === "EMPTY")?.empty === true);

console.log("\n--- reveal ---");
const revealed = await (await call(`/api/value?file=${encodeURIComponent(envPath)}&key=API_KEY`)).json();
check("reveal returns the real value", revealed.value === "sk-test-abcdef123456", JSON.stringify(revealed));

console.log("\n--- writes ---");
await call("/api/key", { method: "PUT", body: JSON.stringify({ file: envPath, key: "PORT", value: "8080" }) });
let content = readFileSync(envPath, "utf-8");
check("edited value written", /^PORT=8080$/m.test(content), content);
check("comment preserved", content.includes("# a comment that must survive"));
check("untouched quoting preserved", content.includes(`API_KEY="sk-test-abcdef123456"`));
check("single-quote style preserved", content.includes("QUOTED='single quoted value'"));
check("backup created", readdirSync(dir).some((f) => f.startsWith(".env.bak.")));

// A backup holds the value you just changed. If .gitignore does not cover it, editing a secret
// creates a fresh exposure — `.env` as a pattern does not match `.env.bak.<stamp>`.
{
  const { execFileSync } = await import("node:child_process");
  const repo = mkdtempSync(join(tmpdir(), "enview-bak-"));
  execFileSync("git", ["init", "-q"], { cwd: repo, stdio: "pipe" });
  writeFileSync(join(repo, ".gitignore"), ".env\n");
  writeFileSync(join(repo, ".env"), "SECRET=old-value-to-be-rotated\n");
  const inRepo = await startEnviewUi({ roots: [repo], port: 4183, maxDepth: 2 });
  await fetch(`http://127.0.0.1:4183/api/key`, {
    method: "PUT",
    headers: { "x-enview-token": inRepo.token, "content-type": "application/json" },
    body: JSON.stringify({ file: join(repo, ".env"), key: "SECRET", value: "new-value" }),
  });
  const gitignore = readFileSync(join(repo, ".gitignore"), "utf-8");
  check("backup pattern added to .gitignore", gitignore.includes("*.bak.*"), gitignore);
  const bak = readdirSync(repo).find((f) => f.startsWith(".env.bak."));
  let ignored = false;
  try {
    execFileSync("git", ["check-ignore", join(repo, bak)], { cwd: repo, stdio: "pipe" });
    ignored = true;
  } catch { ignored = false; }
  check("git actually ignores the backup", ignored);
  check("original .env still ignored", gitignore.includes(".env"));
  inRepo.server.close();
  rmSync(repo, { recursive: true, force: true });
}

await call("/api/key", { method: "PUT", body: JSON.stringify({ file: envPath, key: "NEW_KEY", value: "hello world" }) });
content = readFileSync(envPath, "utf-8");
check("added key is quoted when it needs to be", /^NEW_KEY="hello world"$/m.test(content), content);

await call("/api/key", { method: "DELETE", body: JSON.stringify({ file: envPath, key: "PORT" }) });
content = readFileSync(envPath, "utf-8");
check("deleted key is gone", !/^PORT=/m.test(content));
check("other keys survive delete", /^EMPTY=$/m.test(content) && content.includes("API_KEY="));

r = await call("/api/key", { method: "PUT", body: JSON.stringify({ file: envPath, key: "bad key!", value: "x" }) });
check("invalid key name rejected", r.status === 400, `got ${r.status}`);

console.log("\n--- remediation ---");
const gen = await (await call("/api/action", { method: "POST", body: JSON.stringify({ file: envPath, action: "generate-example" }) })).json();
const example = readFileSync(gen.target, "utf-8");
check(".env.example created", gen.created === true);
check(".env.example keeps keys", /^API_KEY=$/m.test(example), example);
check(".env.example strips every value", !example.includes("sk-test") && !example.includes("hello world"), example);
check(".env.example keeps comments", example.includes("# a comment that must survive"));

// ---------------------------------------------------------------- git history
console.log("\n--- git history ---");
{
  const { execFileSync } = await import("node:child_process");
  const { scanHistory } = await import("../src/index.js");
  const repo = mkdtempSync(join(tmpdir(), "enview-git-"));
  const run = (...args) => execFileSync("git", args, { cwd: repo, stdio: "pipe" });
  run("init", "-q");
  run("config", "user.email", "t@t.test");
  run("config", "user.name", "t");
  writeFileSync(join(repo, ".env"), "OPENAI_API_KEY=sk-committed-secret-value\n"); // gitleaks:allow — synthetic fixture
  run("add", "-A");
  run("commit", "-qm", "oops");
  // Remove it the way people actually do — delete the file and gitignore it, believing that
  // is the fix. It is not: the blob is still in history, which is the point of this scan.
  rmSync(join(repo, ".env"));
  writeFileSync(join(repo, ".gitignore"), ".env\n");
  run("add", "-A");
  run("commit", "-qm", "remove env");

  const histories = scanHistory([repo]);
  const found = histories[0]?.findings?.find((f) => f.filePath === ".env");
  check("finds a secret deleted from the working tree", !!found);
  check("reports it is no longer tracked", found?.stillTracked === false);
  check("recovers the key name from history", !!found?.sensitiveKeys.includes("OPENAI_API_KEY"), JSON.stringify(found?.keys));
  check("never returns the historical value", !JSON.stringify(histories).includes("sk-committed-secret-value"));
  rmSync(repo, { recursive: true, force: true });
}

// ---------------------------------------------------------------- gitignore detection
// This is the check that was silently wrong on Windows for every file. It agrees with git or
// it is worthless, so the test asserts both directions.
console.log("\n--- gitignore detection ---");
{
  const { execFileSync } = await import("node:child_process");
  const { scanProjects } = await import("../src/index.js");
  const repo = mkdtempSync(join(tmpdir(), "enview-ignore-"));
  execFileSync("git", ["init", "-q"], { cwd: repo, stdio: "pipe" });
  writeFileSync(join(repo, ".gitignore"), ".env\n");
  writeFileSync(join(repo, ".env"), "A=1\n");
  writeFileSync(join(repo, ".env.local"), "B=2\n");
  const files = scanProjects([repo], { maxDepth: 2 }).flatMap((p) => p.files);
  check("gitignored file reported as ignored", files.find((f) => f.fileName === ".env")?.gitIgnored === true);
  check("non-ignored file reported as not ignored", files.find((f) => f.fileName === ".env.local")?.gitIgnored === false);
  rmSync(repo, { recursive: true, force: true });
}

console.log(`\n${fail ? `FAIL — ${fail} of ${pass + fail}` : `PASS — ${pass} checks`}`);
server.close();
rmSync(dir, { recursive: true, force: true });
process.exitCode = fail ? 1 : 0;
