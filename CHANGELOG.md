# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-19

### Added

- Initial cross-platform process API: `forEachProcessInfo`, `getProcessInfo`, `exists`, `kill`, `killWithTimeout`, `terminateThenKill`, `parent`, `children`, `killTree`.
- Spawn and wait helpers: `spawn`, `wait`, `waitAll`, and `waitPid` (implemented on Windows; returns `UnsupportedFeature` on Linux/macOS).
- Best-effort per-PID queries: `exePath`, `cmdline` (returned as a single string; Windows only supports the current process), `user`, and `resourceUsage`.

## [1.0.1] - 2026-01-19 [YANKED]

### Changed

- Package module root switched from `src/root.zig` to `src/procz.zig` (no intended API changes).

### Removed

- `src/root.zig` (module root is now `src/procz.zig`).

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
