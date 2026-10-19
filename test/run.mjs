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

// ---------------------------------------------------------------- untrack
console.log("\n--- untrack ---");
{
  const { execFileSync } = await import("node:child_process");
  const repo = mkdtempSync(join(tmpdir(), "enview-untrack-"));
  const run = (...args) => execFileSync("git", args, { cwd: repo, stdio: "pipe" });
  run("init", "-q");
  run("config", "user.email", "t@t.test");
  run("config", "user.name", "t");
  writeFileSync(join(repo, ".env"), "SECRET=still-tracked-value\n"); // gitleaks:allow — synthetic fixture
  run("add", "-A");
  run("commit", "-qm", "oops, committed a secret");

  const isTracked = () => {
    try { execFileSync("git", ["ls-files", "--error-unmatch", ".env"], { cwd: repo, stdio: "pipe" }); return true; }
    catch { return false; }
  };
  check("fixture starts tracked", isTracked());

  const inRepo = await startEnviewUi({ roots: [repo], port: 4184, maxDepth: 2 });
  const untrackCall = (path, opts = {}) => fetch(`http://127.0.0.1:4184${path}`, {
    ...opts,
    headers: { "x-enview-token": inRepo.token, "content-type": "application/json", ...(opts.headers || {}) },
  });

  const res = await (await untrackCall("/api/action", {
    method: "POST",
    body: JSON.stringify({ file: join(repo, ".env"), action: "untrack" }),
  })).json();
  check("untrack reports ok", res.ok === true, JSON.stringify(res));
  check("untrack adds to .gitignore", res.gitignoreAdded === true);
  check("file no longer tracked by git", !isTracked());
  check(".gitignore contains the filename", readFileSync(join(repo, ".gitignore"), "utf-8").includes(".env"));
  check("working copy content is untouched", readFileSync(join(repo, ".env"), "utf-8") === "SECRET=still-tracked-value\n");
  check("no backup written — git rm --cached never touches file contents", !readdirSync(repo).some((f) => f.startsWith(".env.bak.")));

  inRepo.server.close();
  rmSync(repo, { recursive: true, force: true });
}

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

// ---------------------------------------------------------------- history endpoint
// Same fixture shape as the CLI-level history scan above, but exercised through the UI's own
// HTTP endpoint — the thing the browser button actually calls.
console.log("\n--- history endpoint ---");
{
  const { execFileSync } = await import("node:child_process");
  const repo = mkdtempSync(join(tmpdir(), "enview-history-api-"));
  const run = (...args) => execFileSync("git", args, { cwd: repo, stdio: "pipe" });
  run("init", "-q");
  run("config", "user.email", "t@t.test");
  run("config", "user.name", "t");
  writeFileSync(join(repo, ".env"), "OPENAI_API_KEY=sk-endpoint-secret-value\n"); // gitleaks:allow — synthetic fixture
  run("add", "-A");
  run("commit", "-qm", "oops");
  rmSync(join(repo, ".env"));
  writeFileSync(join(repo, ".gitignore"), ".env\n");
  run("add", "-A");
  run("commit", "-qm", "remove env");

  const inRepo = await startEnviewUi({ roots: [repo], port: 4185, maxDepth: 2 });
  const historyCall = (path) => fetch(`http://127.0.0.1:4185${path}`, { headers: { "x-enview-token": inRepo.token } });

  const badRes = await historyCall(`/api/history?path=${encodeURIComponent(dir)}`);
  check("path outside this server's scan allowlist is rejected", badRes.status === 404, `got ${badRes.status}`);

  const body = await (await historyCall(`/api/history?path=${encodeURIComponent(repo)}`)).json();
  const found = body.findings.find((f) => f.file === ".env");
  check("history endpoint finds the deleted secret", !!found, JSON.stringify(body));
  check("reports it is no longer tracked", found?.stillTracked === false);
  check("recovers the key name", !!found?.keys.includes("OPENAI_API_KEY"), JSON.stringify(found));
  check("remedy text present", typeof found?.remedy === "string" && found.remedy.length > 0);
  check("never returns the historical value", !JSON.stringify(body).includes("sk-endpoint-secret-value"));

  inRepo.server.close();
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

// ---------------------------------------------------------------- a missing path is an error
// The regression this locks down: `enview protect ./typo` printed a green tick and exited 0.
// In CI that is a security gate reporting success on a directory it never opened. Every command
// that takes paths must refuse, so the whole surface is asserted rather than just protect.
// ---------------------------------------------------------------- reported version is real
// `--version` was hardcoded and reported 0.2.0 for two releases after package.json moved on.
// One fact, two sources of truth, nothing asserting they agreed. This is that assertion.
console.log("\n--- reported version matches package.json ---");
{
  const { execFileSync } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const { dirname } = await import("node:path");
  const here = dirname(fileURLToPath(import.meta.url));
  const bin = join(here, "..", "bin", "enview.js");
  const pkgVersion = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8")).version;
  const reported = execFileSync(process.execPath, [bin, "--version"], { encoding: "utf8" }).trim();
  check(`enview --version reports ${pkgVersion}`, reported === pkgVersion, `got ${reported}`);
}

console.log("\n--- missing paths are refused ---");
{
  const { execFileSync } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const { dirname } = await import("node:path");
  const bin = join(dirname(fileURLToPath(import.meta.url)), "..", "bin", "enview.js");
  const ghost = join(dir, "no-such-directory");

  const run = (args) => {
    try {
      execFileSync(process.execPath, [bin, ...args], { encoding: "utf8", stdio: "pipe" });
      return 0;
    } catch (e) { return e.status ?? -1; }
  };

  for (const cmd of ["scan", "audit", "keys", "drift", "protect"]) {
    check(`${cmd} exits non-zero on a path that does not exist`, run([cmd, ghost]) === 2);
  }
  // The inverse, so this cannot be satisfied by a command that just always fails.
  check("scan still succeeds on a real path", run(["scan", dir]) === 0);
  // protect must still fail for the RIGHT reason — a real finding, not a bad path.
  check("protect still exits 1 on real findings", run(["protect", dir]) === 1);
}

// ---------------------------------------------------------------- value length is not leaked
// mask() clamps its bullet count to 8-24 precisely so the mask cannot be measured. Shipping the
// true length in the same payload defeated that; this asserts the field is gone and stays gone.
console.log("\n--- value length is not disclosed ---");
{
  const res = await call("/api/projects");
  const body = await res.json();
  const keys = body.projects.flatMap((p) => p.files).flatMap((f) => f.keys);
  const apiKey = keys.find((k) => k.key === "API_KEY");
  const short = keys.find((k) => k.key === "PORT");        // 4 chars
  check("no length field on any key", keys.every((k) => k.length === undefined));
  check("mask does not reveal true length", apiKey.masked.length !== "sk-test-abcdef123456".length);
  // The real assertion: a 4-char value and a 20-char value must be indistinguishable. The old
  // 8-24 clamp passed the check above while failing this one.
  check("short and long values mask identically", short.masked === apiKey.masked);
  check("empty is still reported", keys.find((k) => k.key === "EMPTY")?.empty === true);
  check("raw value never appears in the listing", !JSON.stringify(body).includes("abcdef123456"));
}

console.log("\n--- repo git config cannot execute code ---");
{
  const { execFileSync } = await import("node:child_process");
  const { existsSync } = await import("node:fs");
  const { scanDirectories, untrackFile } = await import("../src/scanner.js");
  const { scanHistories } = await import("../src/history.js");
  const { gitSync } = await import("../src/git.js");
  const repo = mkdtempSync(join(tmpdir(), "enview-fsmonitor-"));
  const marker = join(repo, "marker").replace(/\\/g, "/");
  try {
    execFileSync("git", ["init", "-q"], { cwd: repo, stdio: "pipe" });
    writeFileSync(join(repo, ".env"), "API_TOKEN=abc123\n");
    execFileSync("git", ["config", "core.fsmonitor", `echo ran > '${marker}'; false`], { cwd: repo, stdio: "pipe" });

    // Prove the hook runs here before checking that enview blocks it.
    execFileSync("git", ["ls-files"], { cwd: repo, stdio: "pipe" });
    check("positive control: plain git executes repo fsmonitor", existsSync(marker));
    rmSync(marker, { force: true });

    scanDirectories([repo], { maxDepth: 2 });
    check("directory scan does not execute repo fsmonitor", !existsSync(marker));
    scanHistories([repo]);
    check("history scan does not execute repo fsmonitor", !existsSync(marker));
    untrackFile(repo, join(repo, ".env"));
    check("untrack does not execute repo fsmonitor", !existsSync(marker));
    const result = gitSync(["ls-files"], { cwd: repo, stdio: "pipe" });
    check("gitSync does not execute repo fsmonitor", !existsSync(marker));
    check("gitSync preserves the Buffer result", Buffer.isBuffer(result));
    let threw = false;
    try { gitSync(["ls-files", "--error-unmatch", "missing"], { cwd: repo, stdio: "pipe" }); }
    catch (error) { threw = error.status !== 0; }
    check("gitSync preserves non-zero exit throws", threw);
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
}

const {
  clean, cdCommand, buildAuditReport, printScanResults, printKeysResults, printAuditResults,
  printDriftResults, printHistoryResults, printProtectResults, printFixResults,
} = await import("../src/reporter.js");
const captureOutput = (print) => {
  const log = console.log;
  const lines = [];
  try {
    console.log = (...args) => lines.push(args.join(" "));
    print();
  } finally {
    console.log = log;
  }
  return lines.join("\n");
};
const payload = "X\x1b]52;c;QUFBQQ==\x07\x1b[2KHIDE";
const terminalProjects = [{
  name: "fixture",
  path: "/tmp/enview",
  files: [".env", ".env.production"].map((fileName, i) => {
    const keys = i === 0 ? [payload, "API_TOKEN"] : ["API_TOKEN"];
    return {
      fileName,
      filePath: `/tmp/enview/${fileName}`,
      projectDir: "/tmp/enview",
      projectName: "fixture",
      environment: i === 0 ? "development" : "production",
      keys,
      encryptedKeys: [],
      plaintextKeys: keys,
      sensitiveKeys: keys,
      encryption: { type: "none", partial: false, encryptedCount: 0, totalCount: keys.length },
      inGitRepo: true,
      gitIgnored: false,
      gitTracked: false,
      gitInHistory: false,
      lastCommit: null,
      modifiedAt: new Date(),
      size: 100,
    };
  }),
}];
const hasPayload = (text) => text.includes("\x1b]52") || text.includes("\x07") || text.includes("\x1b[2K");

console.log("\n--- terminal output cannot carry escape sequences ---");
{
  for (const print of [printKeysResults, printAuditResults, printDriftResults]) {
    const output = captureOutput(() => print(terminalProjects));
    check(`${print.name} blocks terminal payloads`, !hasPayload(output));
    check(`${print.name} keeps the key visible`, output.includes("\\x1b]52"));
  }
  check("C1 controls use visible Unicode escapes", clean("a\u009bb") === "a\\u009bb");
  check("C0, DEL and C1 boundaries are escaped", clean("\x00\t\n\r\x1b\x1f\x7f\x80\x9f") === "\\x00\\x09\\x0a\\x0d\\x1b\\x1f\\x7f\\u0080\\u009f");
  check("clean preserves printable text and converts nullish values", clean("café 中文 \\x1b") === "café 中文 \\x1b" && clean(null) === "" && clean(undefined) === "" && clean(42) === "42");

  // Names and paths reach different output branches than key names.
  const projects = terminalProjects.map((p) => ({
    ...p, name: payload, path: `/tmp/${payload}`,
    files: p.files.map((f) => ({ ...f, fileName: f.fileName + payload, environment: payload })),
  }));
  const before = JSON.stringify(projects);
  for (const print of [printScanResults, printKeysResults, printAuditResults, printDriftResults]) {
    check(`${print.name} escapes names and paths`, !hasPayload(captureOutput(() => print(projects))));
  }
  const histories = [{ repoName: payload, root: `/tmp/${payload}`, findings: [{
    filePath: payload, kind: "env", why: "environment file", sensitiveKeys: [payload],
    keys: [payload], stillTracked: false, firstCommitted: null, lastCommitted: null,
  }] }];
  const report = {
    projects,
    summary: { critical: 1, workingTree: 1, history: 0 },
    findings: [{ type: "plaintext_secrets", project: payload, file: payload, keys: [payload] }],
  };
  const actions = {
    gitignoreAdded: [{ project: payload, fileName: payload }],
    alreadyIgnored: [{ project: payload, fileName: payload }],
  };
  check("history escapes repo names and file paths", !hasPayload(captureOutput(() => printHistoryResults(histories))));
  check("protect escapes project names and file paths", !hasPayload(captureOutput(() => printProtectResults(report))));
  check("fix escapes entries and project paths", !hasPayload(captureOutput(() => printFixResults(projects, actions))));

  check("scan JSON stays byte-for-byte faithful", captureOutput(() => printScanResults(projects, { json: true })) === JSON.stringify(projects, null, 2));
  check("history JSON stays byte-for-byte faithful", captureOutput(() => printHistoryResults(histories, { json: true })) === JSON.stringify(histories, null, 2));
  check("audit JSON stays byte-for-byte faithful", captureOutput(() => printAuditResults(projects, { json: true })) === JSON.stringify(buildAuditReport(projects), null, 2));
  const expectedKeys = { [payload]: Object.fromEntries(projects[0].files.map((f) => [f.fileName,
    f.keys.map((name) => ({ name, encrypted: false, sensitive: true })),
  ])) };
  check("keys JSON stays byte-for-byte faithful", captureOutput(() => printKeysResults(projects, { json: true })) === JSON.stringify(expectedKeys, null, 2));
  check("library audit keeps original names and keys", buildAuditReport(projects).findings[0].project === payload && buildAuditReport(projects).findings[0].keys[0] === payload);
  check("human-readable reports do not mutate scan data", JSON.stringify(projects) === before);
}

console.log("\n--- suggested commands are not injectable ---");
{
  check("semicolon injection gets no command", cdCommand("/tmp/x; echo INJECTED; #", "dotenvx encrypt") === null);
  check("command substitution gets no command", cdCommand("/tmp/$(id)", "x") === null);
  check("ampersand injection gets no command", cdCommand("C:\\code\\a & calc", "x") === null);
  check("Windows paths with spaces are quoted", cdCommand("C:\\Users\\A B\\code\\proj", "npx @dotenvx/dotenvx encrypt") === "cd \"C:\\Users\\A B\\code\\proj\" && npx @dotenvx/dotenvx encrypt");
  check("Unicode and allowed punctuation are quoted", cdCommand("/tmp/É中文９ _-.:\\/~@+,=", "x") === "cd \"/tmp/É中文９ _-.:\\/~@+,=\" && x");
  check("quotes, shell expansions and trailing controls get no command", ["\"", "'", "`", "%", "!", "|", "\n", "\r", "\x1b"].every((char) => cdCommand("/tmp/x" + char, "x") === null));
  const projects = terminalProjects.map((p) => ({ ...p, path: "/tmp/x; echo INJECTED; #" }));
  const actions = { gitignoreAdded: [], alreadyIgnored: [] };
  for (const print of [printAuditResults, printFixResults]) {
    const output = captureOutput(() => print(projects, actions));
    check(`${print.name} omits injectable cd commands`, !output.includes("cd /tmp/x; echo") && !output.includes("cd \"/tmp/x;"));
    check(`${print.name} explains manual navigation`, output.includes(projects[0].path) && output.includes("shell metacharacters") && output.includes("cd there yourself"));
  }
}

console.log(`\n${fail ? `FAIL — ${fail} of ${pass + fail}` : `PASS — ${pass} checks`}`);
server.close();
rmSync(dir, { recursive: true, force: true });
process.exitCode = fail ? 1 : 0;
