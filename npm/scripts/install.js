#!/usr/bin/env node
"use strict";

const { execSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const PLATFORMS = {
  linux: { x64: "x86_64-unknown-linux-gnu", arm64: "aarch64-unknown-linux-gnu" },
  darwin: { x64: "x86_64-apple-darwin", arm64: "aarch64-apple-darwin" },
};

const ARCHIVES = {
  linux: "tar.gz",
  darwin: "tar.gz",
};

function getPlatform() {
  const platform = process.platform;
  const arch = process.arch;

  if (!PLATFORMS[platform]) {
    throw new Error(`Unsupported platform: ${platform}`);
  }
  if (!PLATFORMS[platform][arch]) {
    throw new Error(`Unsupported architecture: ${arch}`);
  }

  return {
    target: PLATFORMS[platform][arch],
    archive: ARCHIVES[platform],
    platform,
    arch,
  };
}

function getPackageName() {
  return "spectra";
}

function getDownloadUrl(version, target) {
  const repo = "https://github.com/hilbras/spectra";
  return `${repo}/releases/download/v${version}/spectra-${version}-${target}.tar.gz`;
}

function install() {
  const pkg = require("../package.json");
  const { target, archive, platform } = getPlatform();
  const binDir = path.join(__dirname, "..", "bin");
  const distDir = path.join(__dirname, "..", "dist");

  // Create directories
  fs.mkdirSync(binDir, { recursive: true });
  fs.mkdirSync(distDir, { recursive: true });

  console.log(`Installing spectra v${pkg.version} for ${target}...`);

  // Check if binary already exists in dist
  const binaryName = platform === "win32" ? "spectra.exe" : "spectra";
  const binaryPath = path.join(distDir, binaryName);

  if (fs.existsSync(binaryPath)) {
    console.log(`Binary already exists at ${binaryPath}`);
    makeExecutable(binaryPath);
    createSymlink(binaryPath, binDir);
    return;
  }

  // Try to download pre-built binary
  const url = getDownloadUrl(pkg.version, target);
  console.log(`Downloading from ${url}...`);

  try {
    downloadAndExtract(url, distDir, binaryName);
    makeExecutable(binaryPath);
    createSymlink(binaryPath, binDir);
    console.log("Installation successful!");
  } catch (err) {
    console.warn(`Could not download pre-built binary: ${err.message}`);
    console.log("Falling back to cargo build...");

    try {
      buildFromSource(binaryPath);
      makeExecutable(binaryPath);
      createSymlink(binaryPath, binDir);
      console.log("Build successful!");
    } catch (buildErr) {
      console.error(`Build failed: ${buildErr.message}`);
      console.error("Please install manually:");
      console.error("  cargo install --path apps/cli --name spectra");
      process.exit(1);
    }
  }
}

function downloadAndExtract(url, destDir, binaryName) {
  const tmpFile = path.join(destDir, "tmp.tar.gz");

  execSync(`curl -fsSL -o "${tmpFile}" "${url}"`, { stdio: "inherit" });
  execSync(`tar -xzf "${tmpFile}" -C "${destDir}"`, { stdio: "inherit" });

  // Find extracted binary
  const files = fs.readdirSync(destDir);
  for (const file of files) {
    if (file.startsWith("spectra") && file !== "tmp.tar.gz") {
      const extracted = path.join(destDir, file);
      const target = path.join(destDir, binaryName);
      if (extracted !== target) {
        fs.renameSync(extracted, target);
      }
    }
  }

  // Cleanup
  fs.rmSync(tmpFile, { force: true });
}

function buildFromSource(binaryPath) {
  const root = path.join(__dirname, "..", "..");
  execSync(`cargo build --release --bin spectra`, {
    cwd: root,
    stdio: "inherit",
  });

  const srcBinary = path.join(root, "target", "release", "spectra");
  fs.copyFileSync(srcBinary, binaryPath);
}

function makeExecutable(filePath) {
  if (process.platform !== "win32") {
    fs.chmodSync(filePath, 0o755);
  }
}

function createSymlink(binaryPath, binDir) {
  const linkPath = path.join(binDir, "spectra");
  if (fs.existsSync(linkPath)) {
    fs.unlinkSync(linkPath);
  }

  try {
    fs.symlinkSync(path.relative(binDir, binaryPath), linkPath);
  } catch {
    // Windows fallback - copy instead
    fs.copyFileSync(binaryPath, linkPath + ".exe");
  }
}

install();
