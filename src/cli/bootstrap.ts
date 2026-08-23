#!/usr/bin/env node
/**
 * Hilbras Spectra CLI bootstrap.
 */
import("./index.js").catch((err) => {
  console.error("Failed to start spectra:", err);
  process.exit(1);
});
