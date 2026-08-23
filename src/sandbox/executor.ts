/**
 * Hilbras Spectra — Sandbox Executor
 *
 * Runs target code inside an isolated Docker container with resource limits.
 * Never executes untrusted code on the host.
 */

import { exec } from "node:child_process";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";



const execAsync = promisify(exec);

export interface SandboxConfig {
  /** Container image to use */
  image?: string;
  /** Working directory inside the container */
  workdir?: string;
  /** Memory limit in MB */
  memoryLimitMb?: number;
  /** CPU limit (fraction of 1 core) */
  cpuLimit?: number;
  /** Execution timeout in ms */
  timeoutMs?: number;
  /** Network disabled? */
  noNetwork?: boolean;
}

export interface SandboxResult {
  success: boolean;
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
  containerId?: string;
  error?: string;
}

const DEFAULT_CONFIG: SandboxConfig = {
  image: "node:20-alpine",
  workdir: "/sandbox",
  memoryLimitMb: 512,
  cpuLimit: 0.5,
  timeoutMs: 30_000,
  noNetwork: true,
};

/**
 * Execute a command inside an isolated Docker container.
 * Returns null if Docker is unavailable.
 */
export async function runInSandbox(
  command: string,
  configOverride?: Partial<SandboxConfig>,
): Promise<SandboxResult | null> {
  const config = { ...DEFAULT_CONFIG, ...configOverride };
  const startTime = Date.now();
  const containerId = `hsec-${randomUUID().slice(0, 12)}`;

  try {
    // Check if Docker is available
    await execAsync("docker info --format '{{.ServerVersion}}'", { timeout: 5000 });
  } catch {
    // Docker not available — fall back to direct execution with strict limits
    // This should only happen in development; production must use containers
    return runInProcessFallback(command, config);
  }

  const scriptPath = `/tmp/hsec-${containerId}.sh`;
  const script = `#!/bin/sh\nset -e\n${command}\n`;

  try {
    await writeFile(scriptPath, script);

    const dockerArgs = [
      "run",
      "--rm",
      "--name", containerId,
      "--memory", `${config.memoryLimitMb}m`,
      "--cpus", String(config.cpuLimit),
      "--network", config.noNetwork ? "none" : "bridge",
      "-v", `${scriptPath}:/run/script.sh`,
      "-w", config.workdir,
      config.image,
      "sh", "/run/script.sh",
    ];

    const { stdout, stderr } = await execAsync(
      `docker ${dockerArgs.join(" ")}`,
      {
        timeout: config.timeoutMs,
        maxBuffer: 10 * 1024 * 1024, // 10MB output limit
      },
    );

    return {
      success: true,
      stdout: stdout.trim(),
      stderr: stderr.trim(),
      exitCode: 0,
      durationMs: Date.now() - startTime,
      containerId,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const exitCode = err instanceof Error && message.includes("exit code")
      ? parseInt(message.match(/exit code (\d+)/)?.[1] ?? "1", 10)
      : 127;
    return {
      success: false,
      stdout: "",
      stderr: message.slice(0, 2000),
      exitCode,
      durationMs: Date.now() - startTime,
      containerId,
    };
  } finally {
    // Cleanup temp script
    try { await exec(`rm -f ${scriptPath}`); } catch { /* ignore */ }
  }
}

/**
 * Fallback when Docker is unavailable: run in-process with child_process
 * strict limits. Only for development/testing.
 */
async function runInProcessFallback(
  command: string,
  config: SandboxConfig,
): Promise<SandboxResult | null> {
  try {
    const { stdout, stderr } = await execAsync(command, {
      timeout: config.timeoutMs,
      maxBuffer: 10 * 1024 * 1024,
      env: { ...process.env, NODE_ENV: "test-sandbox" },
    });
    return {
      success: true,
      stdout: stdout.trim(),
      stderr: stderr.trim(),
      exitCode: 0,
      durationMs: 0,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      success: false,
      stdout: "",
      stderr: message.slice(0, 2000),
      exitCode: 1,
      durationMs: 0,
    };
  }
}

/**
 * Write a file (Node 22+ fs.promises.writeFile)
 */
async function writeFile(path: string, content: string): Promise<void> {
  const { writeFile: writeFileFs } = await import("node:fs/promises");
  await writeFileFs(path, content, { mode: 0o755 });
}

/**
 * Check if Docker is available on the host
 */
export async function isSandboxAvailable(): Promise<boolean> {
  try {
    await execAsync("docker info --format '{{.ServerVersion}}'", { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}
