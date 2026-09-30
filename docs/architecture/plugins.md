# Plugins

**Status:** no plugin host exists, and building one on the current crates would be a
security regression rather than a feature.

## What exists

`spectra-plugins` (692 LOC, 21 tests) is a container: a `Plugin` trait
(`initialize`, `execute`, `shutdown`, `health_check`), a `PluginManager` holding
`Box<dyn Plugin>` in a map, and three plugins — `EchoPlugin`, `TransformPlugin`,
`CounterPlugin` — that exist to exercise the trait.

There is no manifest loading, no discovery, no dynamic loading, and **nothing in the
workspace constructs a `PluginManager`.** Zero importers.

In-process Rust traits cannot be populated from outside the binary in any case, so
there is no mechanism by which a third-party plugin could be registered today.

## Why it is not simply wired up

`spectra-sandbox` (735 LOC, 26 tests) is imported by `spectra-plugins` and is **not a
sandbox.** It spawns a real subprocess with `tokio::process::Command` inside the
calling process, so the child inherits the server's uid, filesystem access, network
access and environment. It is a process launcher with an audit log.

Of the six fields on `ResourceLimits`, how many are enforced while a subprocess runs:

| Field | Enforced? |
|---|---|
| `max_memory_bytes` | No — read only by constructors and tests; `ExecutionResult::memory_used_bytes` is hardcoded `0` |
| `max_disk_bytes` | No — never read outside its definition |
| `max_network_connections` | No — read only by constructors and tests |
| `allowed_hosts` / `blocked_hosts` | No — `is_host_allowed` has no call site outside tests |
| `max_cpu_time_ms` | Measured **after the fact** |

`max_cpu_time_ms` is the clearest illustration. `LocalSandbox::execute` awaits
`cmd.output()` to completion and only then compares the elapsed duration. A
subprocess that runs forever is reported as `SandboxError::Timeout` once it
*eventually exits* — after having consumed whatever CPU, memory and disk it wanted,
and after `kill_on_drop` had no opportunity to act because nothing was dropped.

`SandboxPolicy::is_command_allowed` is a string allowlist applied *before* the
subprocess starts. That part works. But it is a command filter, not isolation: an
allowed `python3` receives everything the server has.

### Why this is worse than nothing

`s.txt` Phase 26 states, in its own words: *"Never embed arbitrary Python execution
directly into the main API process."* Wiring `spectra-plugins` to `spectra-sandbox`
as a host would do exactly that — while the type being called `Sandbox` implies the
opposite to anyone reading the call site.

A plugin host built this way executes third-party code with the server's full
privileges and presents itself as contained. That is strictly worse than having no
plugin system, because the containment is the entire reason someone would run
untrusted code in it.

## Current disposition

Both crates are **held**, and each carries module-level documentation stating what it
does not enforce, in a table, so the facts sit at the point of use rather than in an
audit document nobody opens.

They were not deleted. Removing 1,427 LOC and 47 tests is a maintainer's call, and
Phase 0's brief was to establish the actual state *before* deleting or replacing
anything.

## Recommendation on `s.txt` Phases 24, 25 and 26

**Drop or explicitly defer.** The motivation is sound — running untrusted code safely
does require a real sandbox — but the sequencing does not work:

- Phase 24 (plugin architecture) has no host to build against.
- Phase 25 (WASM sandbox) is the real work: a runtime with fuel and memory limits, an
  explicit capability set, no ambient filesystem or network.
- Phase 26 (Python runtime) is a separate large subsystem behind an IPC boundary.

None of the three has a first-party consumer, because Spectra has no third-party
plugins. Building a security boundary for hypothetical plugins means the boundary
gets written once, under time pressure, and audited never. And the in-repo
alternative is the one design that looks correct and is not, which is the most likely
way this gets wired by accident.

If plugins are wanted later, **Phase 25 done properly is the entry point**, and 24 and
26 follow from it.

## If a host is built, these are the requirements

1. No ambient filesystem. A capability must be granted explicitly.
2. No ambient network, or `target-scope-only` — the same scope the crawler enforces.
3. Fuel and memory limits enforced *during* execution, not measured afterwards.
4. No subprocesses from inside a plugin.
5. No secrets reachable unless granted per-plugin.
6. Termination that actually kills, on timeout and on revocation.
7. An audit record per invocation, in a log that survives restart.

`SandboxPolicy` in the current crate covers none of 1–3 or 7, and covers 6 only when
the future is dropped.
