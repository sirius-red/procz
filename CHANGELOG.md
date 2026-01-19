# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.1.0] - 2026-01-19

### Added

- Windows: `kill(pid, options)` now accepts the full `Signal` set and maps
  "graceful" termination as a best-effort request (e.g. `WM_CLOSE` / console
  control events), with `killWithTimeout` handling escalation.

### Fixed

- Replace `std.time.sleep` with `std.Thread.sleep` for Zig 0.15.2
  compatibility.

## [3.0.0] - 2026-01-19

### Breaking Changes

- `waitPid(pid)` now returns `WaitPidResult` instead of `std.process.Child.Term`.
- `forEachProcessInfo()` callback now receives a single `ProcessInfo` argument instead of `(pid: u32, name: []const u8)`.

### Added

- `WaitPidResult` for normalized `waitPid` semantics across platforms.

### Changed

- Linux/macOS: `waitPid(pid)` is implemented by waiting via `waitpid` when `pid` is a child process, otherwise polling `exists(pid)` until the PID disappears (`exit_code = null` for non-child PIDs).
- Windows: `waitPid(pid)` returns a 32-bit exit code when available.

## [2.0.0] - 2026-01-19

### Breaking Changes

- `cmdline(allocator, pid)` now returns `OwnedArgv` (normalized UTF-8 argv) instead of `OwnedBytes`.

### Added

- New `OwnedArgv` type (arena-backed) with `deinit()` for releasing all argv memory.
- Windows: `cmdline()` supports arbitrary PIDs by reading the target process command line via PEB and parsing it with `CommandLineToArgvW`.

### Changed

- Linux: `cmdline()` now reads `/proc/<pid>/cmdline` and preserves argument boundaries (NUL-separated argv).
- macOS: `cmdline()` now extracts `argv` from `sysctl(KERN_PROCARGS2, pid, ...)`.
- Tests updated/added to validate normalized argv for the current process.

## [1.0.1] - 2026-01-19 [YANKED]

### Changed

- Package module root switched from `src/root.zig` to `src/procz.zig` (no intended API changes).

### Removed

- `src/root.zig` (module root is now `src/procz.zig`).

## [1.0.0] - 2026-01-19

### Added

- Initial cross-platform process API: `forEachProcessInfo`, `getProcessInfo`, `exists`, `kill`, `killWithTimeout`, `terminateThenKill`, `parent`, `children`, `killTree`.
- Spawn and wait helpers: `spawn`, `wait`, `waitAll`, and `waitPid` (implemented on Windows; returns `UnsupportedFeature` on Linux/macOS).
- Best-effort per-PID queries: `exePath`, `cmdline` (returned as a single string; Windows only supports the current process), `user`, and `resourceUsage`.
