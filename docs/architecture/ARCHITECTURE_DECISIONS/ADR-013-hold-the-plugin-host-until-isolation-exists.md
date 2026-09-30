# ADR-013: Hold the Plugin Host Until Isolation Exists

## Status

Accepted

## Context

`spectra-plugins` (692 LOC, 21 tests) and `spectra-sandbox` (735 LOC, 26 tests) are
in the workspace. Together they look like a plugin subsystem with a sandbox behind
it. Neither is connected to anything, and the sandbox is not one.

**`spectra-plugins`** defines a `Plugin` trait, a `PluginManager` holding
`Box<dyn Plugin>`, and three plugins — `EchoPlugin`, `TransformPlugin`, `CounterPlugin`
— that exist to exercise the trait. Nothing in the workspace constructs a
`PluginManager`; the crate has zero importers. There is no manifest loading and no
discovery, and in-process Rust traits cannot be populated from outside the binary, so
there is no mechanism by which a third-party plugin could be registered.

**`spectra-sandbox`** is imported by `spectra-plugins` — which is itself unreferenced —
and spawns a real subprocess with `tokio::process::Command` inside the calling
process. The child inherits the server's uid, filesystem access, network access and
environment. Of the six fields on `ResourceLimits`:

| Field | Enforced during execution? |
|---|---|
| `max_memory_bytes` | No — read by constructors and tests; `ExecutionResult::memory_used_bytes` is hardcoded `0` |
| `max_disk_bytes` | No — never read outside its definition |
| `max_network_connections` | No — read by constructors and tests |
| `allowed_hosts` / `blocked_hosts` | No — `is_host_allowed` has no call site outside tests |
| `max_cpu_time_ms` | Measured **after** the subprocess exits |

`max_cpu_time_ms` shows the shape of the problem. `LocalSandbox::execute` awaits
`cmd.output()` to completion and only then compares elapsed time. A subprocess that
runs forever is reported as `SandboxError::Timeout` once it *eventually exits* — after
consuming whatever CPU, memory and disk it wanted, and after `kill_on_drop` had no
opportunity to act because nothing was dropped.

`SandboxPolicy::is_command_allowed` is a string allowlist applied before the subprocess
starts. That part works, and it is the only control that does. It is a command filter,
not isolation: an allowed `python3` receives everything the server has.

## Decision

**Hold both crates. Do not delete them, and do not wire them.**

Wiring `spectra-plugins` to `spectra-sandbox` as a host would execute third-party code
with the server's full privileges while the type being called `Sandbox` implies the
opposite to anyone reading the call site. That is strictly worse than having no plugin
system, because containment is the entire reason someone would run untrusted code in
it.

`s.txt` Phase 26 states, in its own words: *"Never embed arbitrary Python execution
directly into the main API process."* The wiring does exactly that.

Each crate now carries module-level documentation — a table of which limits are not
enforced — so the facts sit at the point of use rather than in an audit document
nobody opens. They were not deleted: removing 1,427 LOC and 47 tests is a
maintainer's call, and the audit's brief was to establish the actual state *before*
deleting or replacing anything.

## Consequences

- Nothing is lost by not acting now. No first-party code uses either crate.
- A future maintainer reading `SandboxPolicy` sees the unenforced limits in the same
  file, rather than trusting the type name.
- The dead `EventType::PluginLoaded` and its siblings in the event taxonomy remain a
  description of a subsystem that does not exist.

## Recommendation on `s.txt` Phases 24, 25 and 26

**Drop, or explicitly defer with a stated condition.**

- **Phase 24, plugin architecture**, has no host to build against and no consumer.
- **Phase 25, a WASM sandbox**, is the real work: fuel and memory limits enforced
  *during* execution, an explicit capability set, no ambient filesystem or network.
- **Phase 26, a Python runtime**, is a separate large subsystem that belongs behind an
  IPC boundary rather than inside the API process.

None of the three has a first-party consumer, because Spectra has no third-party
plugins. Building a security boundary for hypothetical plugins means the boundary gets
written once, under time pressure, and audited never.

If plugins are wanted later, **Phase 25 done properly is the entry point.** Phases 24
and 26 follow from it.

## Requirements if a host is ever built

1. No ambient filesystem. Every capability granted explicitly.
2. No ambient network, or `target-scope-only` — the same scope the crawler enforces.
3. Fuel and memory limits enforced *during* execution, not measured afterwards.
4. No subprocesses from inside a plugin.
5. No secrets reachable unless granted per plugin.
6. Termination that actually kills, on timeout and on revocation.
7. An audit record per invocation, in a log that survives restart.

`SandboxPolicy` in the current crate satisfies none of 1–3 or 7, and satisfies 6 only
when the future is dropped.
