#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

function uninstall() {
  const binDir = path.join(__dirname, "..", "bin");
  const distDir = path.join(__dirname, "..", "dist");

  console.log("Uninstalling spectra...");

  // Remove symlink
  const linkPath = path.join(binDir, "spectra");
  if (fs.existsSync(linkPath)) {
    fs.unlinkSync(linkPath);
  }
  if (fs.existsSync(linkPath + ".exe")) {
    fs.unlinkSync(linkPath + ".exe");
  }

  // Remove binary
  const binaryPath = path.join(distDir, "spectra");
  if (fs.existsSync(binaryPath)) {
    fs.unlinkSync(binaryPath);
  }

  console.log("Uninstallation complete.");
}

uninstall();
