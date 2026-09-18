#!/usr/bin/env node
"use strict";

const { execSync } = require("child_process");
const path = require("path");
const fs = require("fs");

function build() {
  const root = path.join(__dirname, "..", "..");
  const distDir = path.join(__dirname, "..", "dist");

  fs.mkdirSync(distDir, { recursive: true });

  console.log("Building spectra...");

  // Build release binary
  execSync("cargo build --release --bin spectra", {
    cwd: root,
    stdio: "inherit",
  });

  // Copy binary to dist
  const srcBinary = path.join(root, "target", "release", "spectra");
  const destBinary = path.join(distDir, "spectra");
  fs.copyFileSync(srcBinary, destBinary);
  fs.chmodSync(destBinary, 0o755);

  // Create wrapper script
  const wrapper = `#!/usr/bin/env bash
exec "$(dirname "$0")/spectra" "$@"`;
  fs.writeFileSync(path.join(distDir, "cli.js"), wrapper);
  fs.chmodSync(path.join(distDir, "cli.js"), 0o755);

  // Create index.js for require()
  const indexJs = `#!/usr/bin/env node
"use strict";

const { execFileSync } = require("child_process");
const path = require("path");

const binary = path.join(__dirname, "spectra");

function spectra(args = []) {
  return execFileSync(binary, args, {
    encoding: "utf-8",
    stdio: ["pipe", "pipe", "pipe"],
  });
}

module.exports = { spectra };
`;
  fs.writeFileSync(path.join(distDir, "index.js"), indexJs);

  // Create TypeScript types
  const indexDts = `export declare function spectra(args?: string[]): string;
`;
  fs.writeFileSync(path.join(distDir, "index.d.ts"), indexDts);

  console.log("Build complete!");
}

build();
