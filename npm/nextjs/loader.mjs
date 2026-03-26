/**
 * Next.js environment variable loader using dotenvage
 *
 * This module loads encrypted .env files at runtime, making environment
 * variables available to the Next.js application.
 *
 * It automatically loads encrypted .env files in all environments:
 * - Local development (loads from .env, .env.local, etc.)
 * - Vercel CI (loads from committed encrypted .env files)
 * - Production builds (loads from committed encrypted .env files)
 *
 * For Vercel CI, you only need to set the encryption key as an environment variable:
 * - EKG_AGE_KEY (for key name-based lookup: ekg/dr-rs-ekg)
 * - DOTENVAGE_AGE_KEY or AGE_KEY (for direct key string)
 *
 * Encrypted .env files are committed to git and loaded at runtime.
 * No need to sync environment variables to Vercel separately.
 *
 * Usage in next.config.mjs:
 *   import { loadEnv } from '@dotenvage/node/nextjs'
 *   loadEnv()
 */
import * as dotenvage from "../index.js";

let loaded = false;

/**
 * Loads environment variables from encrypted .env files
 * This runs automatically when this module is imported
 * Always loads from dotenvage in all environments (local, Vercel CI, production)
 */
export function loadEnv() {
  // Only load once — check both the module-scoped flag and the cross-process
  // sentinel set by preinit.mjs (or a prior loadEnv call in a parent process).
  // Without this, a child process spawned by wrapper.mjs would re-read .env
  // files from disk, clobbering the properly-layered values already in
  // process.env (e.g. .env.local overrides lost).
  if (loaded || process.env.__DOTENVAGE_LOADED) {
    return;
  }

  try {
    // Create loader and load environment variables from encrypted .env files
    // This mutates process.env with decrypted values
    // Works in all environments: local, Vercel CI, production
    const loader = dotenvage.JsEnvLoader.new();
    const loadedPaths = loader.load();

    const variableNames = loader.getAllVariableNames();
    const isProduction = process.env.NODE_ENV === "production";

    // Extract just the filenames from the actually loaded paths
    const envFiles = loadedPaths.map((p) => p.split("/").pop());

    if (!isProduction || process.env.VERCEL) {
      console.log(
        `✓ Loaded ${variableNames.length} environment variables from dotenvage`
      );
      if (envFiles.length > 0) {
        console.log(`  - Decrypted: ${envFiles.join(", ")}`);
      }
    }

    loaded = true;
    process.env.__DOTENVAGE_LOADED = "1";
  } catch (error) {
    // Always show errors - we need to know if loading fails
    const errorMessage =
      error instanceof Error ? error.message : String(error);
    console.error(
      "❌ Failed to load environment variables from dotenvage:",
      errorMessage
    );
    console.error("");
    console.error("  Make sure one of these is set:");
    console.error(
      "    - EKG_AGE_KEY (for key name-based lookup: ekg/dr-rs-ekg)"
    );
    console.error("    - DOTENVAGE_AGE_KEY (direct key string)");
    console.error("    - AGE_KEY (direct key string)");
    console.error(
      "    - EKG_AGE_KEY_NAME in .env file (points to key file location)"
    );
    console.error("");

    // In production/Vercel, fail hard - we need env vars to work
    if (process.env.NODE_ENV === "production" || process.env.VERCEL) {
      console.error(
        "  This is a production build. Environment variables are required!"
      );
      process.exit(1);
    }

    // In development, warn but continue (might be missing key for testing)
    console.warn(
      "  Continuing in development mode, but some features may not work."
    );

    // Mark as loaded to prevent retry loops
    loaded = true;
  }
}

/**
 * Get all environment variables (for testing/debugging)
 */
export function getAllEnvVars() {
  try {
    const loader = dotenvage.JsEnvLoader.new();
    return loader.getAllVariables();
  } catch (error) {
    console.error("Error getting environment variables:", error);
    return {};
  }
}

/**
 * Get variable names (for testing/debugging)
 */
export function getEnvVarNames() {
  try {
    const loader = dotenvage.JsEnvLoader.new();
    return loader.getAllVariableNames();
  } catch (error) {
    console.error("Error getting variable names:", error);
    return [];
  }
}
