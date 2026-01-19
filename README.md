# procz

Cross-platform library for handling processes with Zig (0.15.2+).

## TODO

- [x] BREAKING: `cmdline(allocator, pid)` returns a normalized argv list (UTF-8 args) for arbitrary PIDs on all OSes.
- [x] `waitPid(pid)` on Linux + macOS (define semantics; non-child PIDs are a pain on POSIX).
- [x] `kill(pid, options)` parity on Windows (`KillOptions.signal` + what "graceful" means; impacts `killWithTimeout` and `killTree`).
- [x] `forEachProcessInfo()` / `getProcessInfo()`: define what `name` means and make it consistent across OSes.
- [x] `exePath()`: provide a normalized "exe name" story (path is always OS-native).
- [ ] `user()`: normalize user identity output so it's comparable across OSes.
- [ ] `resourceUsage()`: pick a single time base for `start_time_*`.
- [ ] `children()` / `killTree()`: make results deterministic (stable ordering).
