/**
 * Pre-initialization environment variable loader for Next.js
 *
 * This module loads encrypted .env files BEFORE Next.js loads its own .env files.
 * It must be loaded before Next.js starts (via -r flag, require hook, or wrapper script).
 *
 * IMPORTANT: Next.js's @next/env does NOT overwrite existing process.env values.
 * By loading encrypted env vars FIRST, we ensure:
 * 1. Encrypted values are decrypted and set in process.env
 * 2. When @next/env runs, it sees existing values and doesn't overwrite them
 * 3. Decrypted values are preserved throughout the Next.js build/runtime
 *
 * This is critical for Edge Runtime (middleware) where NEXT_PUBLIC_* variables
 * need to be inlined at build time.
 *
 * Usage:
 *   - Via -r flag: node -r @dotenvage/node/nextjs/preinit node_modules/.bin/next dev
 *   - Via wrapper script: See wrapper.mjs
 */
import * as dotenvage from "../index.js";

let loaded = false;

/**
 * Loads environment variables from encrypted .env files
 * This runs immediately when this module is imported
 *
 * Note: @next/env respects existing process.env values and won't overwrite them,
 * so by loading first, our decrypted values take precedence over the encrypted .env files.
 */
function loadEnvPreinit() {
  // Only load once — check both the module-scoped flag and the cross-process
  // sentinel so that a child process inheriting our env doesn't re-load.
  if (loaded || process.env.__DOTENVAGE_LOADED) {
    return;
  }

  try {
    // Store which variables existed before loading (for debugging)
    const existingVars = new Set(Object.keys(process.env));

    // Create loader and load environment variables from encrypted .env files
    // This mutates process.env with decrypted values
    const loader = dotenvage.JsEnvLoader.new();
    const loadedPaths = loader.load();

    const variableNames = loader.getAllVariableNames();
    const isProduction = process.env.NODE_ENV === "production";

    // Extract just the filenames from the actually loaded paths
    const envFiles = loadedPaths.map((p) => p.split("/").pop());

    // Check which variables already existed (for debugging info)
    const overwrittenVars = variableNames.filter((name) =>
      existingVars.has(name)
    );

    if (!isProduction || process.env.VERCEL) {
      console.log(
        `✓ Pre-initialized ${variableNames.length} environment variables from dotenvage`
      );
      if (envFiles.length > 0) {
        console.log(`  - Decrypted: ${envFiles.join(", ")}`);
      }
      if (
        overwrittenVars.length > 0 &&
        process.env.NODE_ENV === "development"
      ) {
        console.log(
          `  Note: ${overwrittenVars.length} variables already existed and were preserved`
        );
      }
    }

    loaded = true;
    // Sentinel survives into child processes spawned with env: process.env,
    // so loader.mjs / preinit.mjs in the child will skip re-loading.
    process.env.__DOTENVAGE_LOADED = "1";
  } catch (error) {
    // Always show errors - we need to know if loading fails
    const errorMessage =
      error instanceof Error ? error.message : String(error);
    console.error(
      "❌ Failed to pre-initialize environment variables from dotenvage:",
      errorMessage
    );
    console.error("");
    console.error("  Make sure one of these is set:");
    console.error(
      "    - EKG_AGE_KEY (direct AGE identity string: AGE-SECRET-KEY-...)"
    );
    console.error("    - DOTENVAGE_AGE_KEY (direct AGE identity string)");
    console.error("    - AGE_KEY (direct AGE identity string)");
    console.error(
      "    - EKG_AGE_KEY_NAME in .env (for key name-based lookup: ekg/myproject)"
    );
    console.error("");

    // In production/Vercel, fail hard - we need env vars to work
    if (process.env.NODE_ENV === "production" || process.env.VERCEL) {
      console.error(
        "  This is a production build. Environment variables are required!"
      );
      process.exit(1);
    }

    // In development, warn but continue
    console.warn(
      "  Continuing in development mode, but some features may not work."
    );
    loaded = true;
  }
}

// Auto-load when this module is imported
loadEnvPreinit();
