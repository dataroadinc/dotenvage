/**
 * Integration tests for the Next.js sentinel (__DOTENVAGE_LOADED)
 *
 * The dotenvage-next wrapper loads env vars in a parent process and
 * spawns Next.js as a child.  Without a cross-process sentinel the
 * child's loadEnv() / preinit would re-read .env files from disk,
 * clobbering the properly-layered values the parent already resolved
 * (e.g. .env.local overrides lost).
 *
 * Every test spawns a fresh child process so the module-scoped
 * `loaded` flag in loader.mjs / preinit.mjs is always false —
 * only the sentinel env var prevents re-loading.
 */

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { pathToFileURL } = require("node:url");

let dotenvage;
try {
  dotenvage = require("../index.js");
} catch {
  console.warn(
    'Skipping nextjs-integration tests — run "pnpm run build" first.'
  );
  process.exit(0);
}

describe("Next.js integration — __DOTENVAGE_LOADED sentinel", () => {
  let tmpDir;
  let manager;
  let identityString;
  /** file:// URL strings for ESM imports inside child scripts */
  let loaderUrl;
  let preinitUrl;
  let configUrl;
  let originalEnv;

  before(() => {
    originalEnv = { ...process.env };

    manager = dotenvage.JsSecretManager.generate();
    identityString = manager.identityString();

    loaderUrl = pathToFileURL(
      path.resolve(__dirname, "../nextjs/loader.mjs")
    ).href;
    preinitUrl = pathToFileURL(
      path.resolve(__dirname, "../nextjs/preinit.mjs")
    ).href;
    configUrl = pathToFileURL(
      path.resolve(__dirname, "../nextjs/config.mjs")
    ).href;

    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dotenvage-nextjs-"));

    // .env  — base values (NODE_ENV=local triggers .env.local loading)
    fs.writeFileSync(
      path.join(tmpDir, ".env"),
      [
        "NODE_ENV=local",
        "BASE_ONLY=from-base",
        "OVERLAP=base-value",
        `ENCRYPTED_SECRET=${manager.encryptValue("decrypted-base")}`,
      ].join("\n") + "\n"
    );

    // .env.local — overrides
    fs.writeFileSync(
      path.join(tmpDir, ".env.local"),
      [
        "LOCAL_ONLY=from-local",
        "OVERLAP=local-override",
        `ENCRYPTED_SECRET=${manager.encryptValue("decrypted-local")}`,
      ].join("\n") + "\n"
    );
  });

  after(() => {
    process.env = originalEnv;
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // ── helpers ───────────────────────────────────────────────

  /**
   * Run an ESM snippet in a child process whose cwd is tmpDir.
   * Returns the parsed JSON that the script writes to stdout.
   */
  function runChild(script, env = {}) {
    const name = `t-${Date.now()}-${Math.random().toString(36).slice(2)}.mjs`;
    const file = path.join(tmpDir, name);
    fs.writeFileSync(file, script);
    try {
      const stdout = execFileSync("node", [file], {
        cwd: tmpDir,
        env: { PATH: process.env.PATH, HOME: process.env.HOME, ...env },
        encoding: "utf-8",
        timeout: 15_000,
      });
      // loadEnv / preinit may print log lines before the JSON
      for (const line of stdout.trim().split("\n").reverse()) {
        try {
          return JSON.parse(line);
        } catch {
          /* not JSON — skip */
        }
      }
      throw new Error(`No JSON found in child output:\n${stdout}`);
    } finally {
      try {
        fs.unlinkSync(file);
      } catch {
        /* best-effort cleanup */
      }
    }
  }

  /** Minimal env needed for a child that should actually load.
   *  NODE_ENV is intentionally omitted — the loader discovers
   *  NODE_ENV=local from .env, which triggers .env.local loading. */
  function loadableEnv(extra = {}) {
    return {
      DOTENVAGE_AGE_KEY: identityString,
      ...extra,
    };
  }

  // ── loader.mjs — loadEnv() ───────────────────────────────

  describe("loadEnv()", () => {
    it("loads .env files and sets sentinel when no sentinel present", () => {
      const r = runChild(
        `import { loadEnv } from "${loaderUrl}";
         const sentinelBefore = process.env.__DOTENVAGE_LOADED ?? "UNSET";
         loadEnv();
         process.stdout.write(JSON.stringify({
           sentinelBefore,
           sentinelAfter: process.env.__DOTENVAGE_LOADED ?? "UNSET",
           OVERLAP:          process.env.OVERLAP          ?? "UNSET",
           LOCAL_ONLY:       process.env.LOCAL_ONLY       ?? "UNSET",
           BASE_ONLY:        process.env.BASE_ONLY        ?? "UNSET",
           ENCRYPTED_SECRET: process.env.ENCRYPTED_SECRET ?? "UNSET",
         }));`,
        loadableEnv()
      );

      assert.strictEqual(r.sentinelBefore, "UNSET");
      assert.strictEqual(r.sentinelAfter, "1");
      // .env.local must override .env
      assert.strictEqual(r.OVERLAP, "local-override");
      assert.strictEqual(r.LOCAL_ONLY, "from-local");
      assert.strictEqual(r.BASE_ONLY, "from-base");
      // encrypted value from .env.local wins after decryption
      assert.strictEqual(r.ENCRYPTED_SECRET, "decrypted-local");
    });

    it("skips entirely when sentinel is already set", () => {
      const r = runChild(
        `import { loadEnv } from "${loaderUrl}";
         loadEnv();
         process.stdout.write(JSON.stringify({
           OVERLAP:    process.env.OVERLAP    ?? "UNSET",
           BASE_ONLY:  process.env.BASE_ONLY  ?? "UNSET",
           LOCAL_ONLY: process.env.LOCAL_ONLY  ?? "UNSET",
         }));`,
        {
          __DOTENVAGE_LOADED: "1",
          OVERLAP: "from-parent",
          // no AGE key — would fail if loadEnv actually tried
        }
      );

      assert.strictEqual(
        r.OVERLAP,
        "from-parent",
        "sentinel must prevent loadEnv from overwriting parent values"
      );
      assert.strictEqual(
        r.BASE_ONLY,
        "UNSET",
        ".env vars must not appear when sentinel blocked loading"
      );
      assert.strictEqual(r.LOCAL_ONLY, "UNSET");
    });
  });

  // ── preinit.mjs ──────────────────────────────────────────

  describe("preinit", () => {
    it("loads and sets sentinel when no sentinel present", () => {
      const r = runChild(
        `await import("${preinitUrl}");
         process.stdout.write(JSON.stringify({
           sentinel: process.env.__DOTENVAGE_LOADED ?? "UNSET",
           OVERLAP:  process.env.OVERLAP            ?? "UNSET",
         }));`,
        loadableEnv()
      );

      assert.strictEqual(r.sentinel, "1");
      assert.strictEqual(r.OVERLAP, "local-override");
    });

    it("skips when sentinel is already set", () => {
      const r = runChild(
        `await import("${preinitUrl}");
         process.stdout.write(JSON.stringify({
           BASE_ONLY: process.env.BASE_ONLY ?? "UNSET",
         }));`,
        { __DOTENVAGE_LOADED: "1" }
      );

      assert.strictEqual(
        r.BASE_ONLY,
        "UNSET",
        "preinit must not load .env files when sentinel is set"
      );
    });
  });

  // ── config.mjs — withDotenvage() ─────────────────────────

  describe("withDotenvage()", () => {
    it("passes config through and respects sentinel", () => {
      const r = runChild(
        `import { withDotenvage } from "${configUrl}";
         const cfg = withDotenvage({ reactStrictMode: true });
         process.stdout.write(JSON.stringify({
           configOk:  cfg.reactStrictMode === true,
           BASE_ONLY: process.env.BASE_ONLY ?? "UNSET",
         }));`,
        { __DOTENVAGE_LOADED: "1" }
      );

      assert.strictEqual(r.configOk, true, "config must be passed through");
      assert.strictEqual(
        r.BASE_ONLY,
        "UNSET",
        "sentinel must prevent loading"
      );
    });
  });

  // ── cross-process (the actual wrapper.mjs flow) ──────────

  describe("cross-process wrapper flow", () => {
    it("preserves .env.local overrides in child when sentinel is set", () => {
      // Simulate: parent loaded correctly → child inherits env + sentinel
      const r = runChild(
        `import { loadEnv } from "${loaderUrl}";
         loadEnv();
         process.stdout.write(JSON.stringify({
           OVERLAP:          process.env.OVERLAP,
           LOCAL_ONLY:       process.env.LOCAL_ONLY,
           ENCRYPTED_SECRET: process.env.ENCRYPTED_SECRET,
         }));`,
        {
          __DOTENVAGE_LOADED: "1",
          OVERLAP: "local-override",
          LOCAL_ONLY: "from-local",
          ENCRYPTED_SECRET: "decrypted-local",
          DOTENVAGE_AGE_KEY: identityString,
        }
      );

      assert.strictEqual(r.OVERLAP, "local-override");
      assert.strictEqual(r.LOCAL_ONLY, "from-local");
      assert.strictEqual(
        r.ENCRYPTED_SECRET,
        "decrypted-local",
        "decrypted value from parent must survive into child"
      );
    });

    it("without sentinel child re-reads disk and overwrites parent values", () => {
      // The pre-fix scenario: no sentinel → child re-loads from disk.
      // A parent-only value (not in any .env file) is unaffected, but
      // OVERLAP gets rewritten to whatever the layering produces.
      const r = runChild(
        `import { loadEnv } from "${loaderUrl}";
         loadEnv();
         process.stdout.write(JSON.stringify({
           OVERLAP:     process.env.OVERLAP,
           PARENT_ONLY: process.env.PARENT_ONLY ?? "UNSET",
         }));`,
        loadableEnv({
          OVERLAP: "stale-parent-value",
          PARENT_ONLY: "only-from-parent",
        })
      );

      // loadEnv() re-reads .env files — OVERLAP is overwritten
      assert.strictEqual(
        r.OVERLAP,
        "local-override",
        "without sentinel, loadEnv re-reads from disk"
      );
      // Values not in any .env file survive the overwrite
      assert.strictEqual(r.PARENT_ONLY, "only-from-parent");
    });

    it("encrypted values round-trip correctly through parent → child", () => {
      // Parent decrypted ENCRYPTED_SECRET to "decrypted-local" and
      // passed it to the child.  With sentinel the child must NOT
      // re-decrypt (which would produce the same value but waste work,
      // or worse fail if the key is unavailable at runtime).
      const r = runChild(
        `import { loadEnv } from "${loaderUrl}";
         loadEnv();
         const val = process.env.ENCRYPTED_SECRET;
         process.stdout.write(JSON.stringify({
           ENCRYPTED_SECRET: val,
           isPlaintext: !val.startsWith("ENC["),
         }));`,
        {
          __DOTENVAGE_LOADED: "1",
          ENCRYPTED_SECRET: "decrypted-local",
          // deliberately no AGE key — must not need one
        }
      );

      assert.strictEqual(r.ENCRYPTED_SECRET, "decrypted-local");
      assert.strictEqual(
        r.isPlaintext,
        true,
        "child must see the decrypted plaintext, not the ENC[...] ciphertext"
      );
    });
  });

  // ── edge cases ───────────────────────────────────────────

  describe("edge cases", () => {
    it("sentinel with empty string is treated as unset (falsy)", () => {
      // An empty string is falsy in JS — loadEnv should proceed
      const r = runChild(
        `import { loadEnv } from "${loaderUrl}";
         loadEnv();
         process.stdout.write(JSON.stringify({
           OVERLAP: process.env.OVERLAP ?? "UNSET",
         }));`,
        loadableEnv({ __DOTENVAGE_LOADED: "" })
      );

      // Empty sentinel ⇒ loadEnv runs ⇒ OVERLAP comes from .env.local
      assert.strictEqual(r.OVERLAP, "local-override");
    });

    it("multiple loadEnv calls in same process are idempotent", () => {
      const r = runChild(
        `import { loadEnv } from "${loaderUrl}";
         loadEnv();
         const first = process.env.OVERLAP;
         // manually change env to prove second call is a no-op
         process.env.OVERLAP = "mutated";
         loadEnv();
         process.stdout.write(JSON.stringify({
           first,
           second: process.env.OVERLAP,
         }));`,
        loadableEnv()
      );

      assert.strictEqual(r.first, "local-override");
      assert.strictEqual(
        r.second,
        "mutated",
        "second loadEnv must be a no-op (module-scoped loaded flag)"
      );
    });

    it("sentinel survives through two levels of child processes", () => {
      // grandparent → parent (sentinel) → child (sentinel inherited)
      const innerUrl = loaderUrl;
      const r = runChild(
        `import { execFileSync } from "node:child_process";
         import { writeFileSync, unlinkSync } from "node:fs";
         import { join } from "node:path";

         const inner = join(process.cwd(), "_inner.mjs");
         writeFileSync(inner, \`
           import { loadEnv } from "${innerUrl}";
           loadEnv();
           process.stdout.write(JSON.stringify({
             OVERLAP:  process.env.OVERLAP  ?? "UNSET",
             sentinel: process.env.__DOTENVAGE_LOADED ?? "UNSET",
           }));
         \`);
         try {
           const out = execFileSync("node", [inner], {
             cwd: process.cwd(),
             env: process.env,
             encoding: "utf-8",
             timeout: 10_000,
           });
           // forward the grandchild's JSON
           const lines = out.trim().split("\\n");
           for (let i = lines.length - 1; i >= 0; i--) {
             try { JSON.parse(lines[i]); process.stdout.write(lines[i]); break; }
             catch {}
           }
         } finally { try { unlinkSync(inner); } catch {} }`,
        {
          __DOTENVAGE_LOADED: "1",
          OVERLAP: "grandparent-value",
        }
      );

      assert.strictEqual(
        r.OVERLAP,
        "grandparent-value",
        "sentinel must propagate through two levels of spawning"
      );
      assert.strictEqual(r.sentinel, "1");
    });
  });
});
