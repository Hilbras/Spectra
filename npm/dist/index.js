#!/usr/bin/env node
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
