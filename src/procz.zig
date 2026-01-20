//! Cross-platform library for handling processes with Zig (0.15.2+).

const builtin = @import("builtin");
const std = @import("std");
const mem = std.mem;

extern "kernel32" fn GetProcessId(process: std.os.windows.HANDLE) callconv(.winapi) u32;

/// Process types and operations.
pub const process = @import("process.zig");

/// Platform-specific implementations and shared types.
pub const platform = @import("platform.zig");

const OwnedProcessInfo = process.OwnedProcessInfo;
const ForEachInfoCallback = platform.shared.ForEachInfoCallback;

/// Error set used by this library.
pub const Error = platform.shared.Error;
/// Kill strategy used by `kill*` helpers.
pub const KillMode = platform.shared.KillMode;
/// Options for `kill` and related helpers.
pub const KillOptions = platform.shared.KillOptions;
/// Platform-independent signal selector (best-effort mapping).
pub const Signal = platform.shared.Signal;
/// Owned byte buffer returned by some query APIs.
pub const OwnedBytes = platform.shared.OwnedBytes;
/// Owned argv list returned by `cmdline()`.
pub const OwnedArgv = platform.shared.OwnedArgv;
/// Platform-dependent user identity (uid on POSIX, SID on Windows).
pub const UserId = platform.shared.UserId;
/// Owned variant of `UserId` for APIs that allocate.
pub const OwnedUserId = platform.shared.OwnedUserId;
/// Process resource usage and timing information (best-effort).
pub const ResourceUsage = platform.shared.ResourceUsage;
/// Normalized result returned by `waitPid`.
pub const WaitPidResult = platform.shared.WaitPidResult;
/// Process exit status (same as `std.process.Child.Term`).
pub const ExitStatus = std.process.Child.Term;

fn validatePid(pid: u32) Error!void {
    if (pid == 0) return Error.InvalidPid;
}

/// Enumerate process IDs and names for the current operating system.
///
/// The `info.name` slice passed to `callback` may be backed by temporary
/// storage and must be copied if it needs to outlive the callback.
///
/// Errors: any error returned by the platform backend or by `callback` is
/// propagated. If the current OS is not supported, this returns
/// `platform.shared.Error.UnsupportedOS`.
pub fn forEachProcessInfo(
    allocator: mem.Allocator,
    context: anytype,
    callback: ForEachInfoCallback(@TypeOf(context)),
) !void {
    const exec = (try platform.GetModule()).forEachProcessInfo;
    try exec(allocator, context, callback);
}

/// Query information for a single PID.
///
/// The returned `OwnedProcessInfo` must be released with `deinit`.
pub fn getProcessInfo(allocator: mem.Allocator, pid: u32) !OwnedProcessInfo {
    try validatePid(pid);
    const exec = (try platform.GetModule()).getProcessInfo;
    return try exec(allocator, pid);
}

/// Check whether a PID exists.
///
/// Note: this is a best-effort check; some platforms may return `true` for
/// processes that exist but are not queryable due to permissions.
pub fn exists(pid: u32) !bool {
    try validatePid(pid);
    const exec = (try platform.GetModule()).processExists;
    return try exec(pid);
}

/// Terminate a process by PID, using the provided options.
///
/// Returns `Error.NotFound` if the PID does not exist, and `Error.InvalidPid`
/// if `pid` is 0.
pub fn kill(pid: u32, options: KillOptions) !void {
    try validatePid(pid);
    const exec = (try platform.GetModule()).killProcessWithOptions;
    try exec(pid, options);
}

/// Attempt to terminate a process and wait until it disappears, up to `timeout_ns`.
///
/// If `options.mode` is not `force`, this function escalates to a forceful kill
/// after the first timeout window.
///
/// If the process does not exist, this returns successfully.
pub fn killWithTimeout(pid: u32, options: KillOptions, timeout_ns: u64) !void {
    try validatePid(pid);
    kill(pid, options) catch |err| switch (err) {
        Error.NotFound => return,
        else => return err,
    };

    var timer = try std.time.Timer.start();
    while (timer.read() < timeout_ns) {
        if (!try exists(pid)) return;
        std.Thread.sleep(25 * std.time.ns_per_ms);
    }

    if (options.mode != .force) {
        kill(pid, .{ .mode = .force, .signal = .kill }) catch |err| switch (err) {
            Error.NotFound => return,
            else => return err,
        };
        timer = try std.time.Timer.start();
        while (timer.read() < timeout_ns) {
            if (!try exists(pid)) return;
            std.Thread.sleep(25 * std.time.ns_per_ms);
        }
    }

    return Error.Timeout;
}

/// Gracefully terminate a process and escalate to force after `timeout_ns`.
pub fn terminateThenKill(pid: u32, timeout_ns: u64) !void {
    try killWithTimeout(pid, .{ .mode = .graceful }, timeout_ns);
}

/// Return the parent PID of `pid` when available.
pub fn parent(pid: u32) !?u32 {
    try validatePid(pid);
    const exec = (try platform.GetModule()).parentPid;
    return try exec(pid);
}

/// Return the list of child PIDs for `pid`.
///
/// The returned slice is sorted in ascending PID order, owned by the caller,
/// and must be freed with `allocator.free`.
pub fn children(allocator: mem.Allocator, pid: u32) ![]u32 {
    try validatePid(pid);
    const exec = (try platform.GetModule()).childrenPids;
    const pids = try exec(allocator, pid);
    std.sort.heap(u32, pids, {}, std.sort.asc(u32));
    return pids;
}

/// Attempt to kill `pid` and all of its descendants (best-effort).
///
/// The traversal is snapshot-based: the process tree may change while this runs.
pub fn killTree(allocator: mem.Allocator, pid: u32, options: KillOptions) !void {
    try validatePid(pid);
    var visited = std.AutoHashMap(u32, void).init(allocator);
    defer visited.deinit();

    var stack: std.ArrayList(u32) = .empty;
    defer stack.deinit(allocator);

    try visited.put(pid, {});
    try stack.append(allocator, pid);

    var stack_idx: usize = 0;
    while (stack_idx < stack.items.len) : (stack_idx += 1) {
        const current_pid = stack.items[stack_idx];
        const child_pids = children(allocator, current_pid) catch |err| switch (err) {
            Error.AccessDenied, Error.NotFound => continue,
            else => return err,
        };
        defer allocator.free(child_pids);

        for (child_pids) |child_pid| {
            if (visited.contains(child_pid)) continue;
            try visited.put(child_pid, {});
            try stack.append(allocator, child_pid);
        }
    }

    var reverse_idx: usize = stack.items.len;
    while (reverse_idx > 0) {
        reverse_idx -= 1;
        kill(stack.items[reverse_idx], options) catch |err| switch (err) {
            Error.AccessDenied, Error.NotFound => {},
            else => return err,
        };
    }
}

/// Spawn a new process.
///
/// On success, the returned `std.process.Child` must eventually be `wait`ed (or
/// otherwise reaped) by the caller.
pub fn spawn(allocator: mem.Allocator, argv: []const []const u8, options: SpawnOptions) !std.process.Child {
    var child = std.process.Child.init(argv, allocator);
    child.cwd = options.cwd;
    child.env_map = options.env_map;
    child.stdin_behavior = options.stdin;
    child.stdout_behavior = options.stdout;
    child.stderr_behavior = options.stderr;
    child.expand_arg0 = options.expand_arg0;
    try child.spawn();
    return child;
}

/// Options for `spawn`.
pub const SpawnOptions = struct {
    /// Working directory for the child process.
    cwd: ?[]const u8 = null,
    /// Environment map to use (when available).
    env_map: ?*const std.process.EnvMap = null,
    /// Child stdin configuration.
    stdin: std.process.Child.StdIo = .Inherit,
    /// Child stdout configuration.
    stdout: std.process.Child.StdIo = .Inherit,
    /// Child stderr configuration.
    stderr: std.process.Child.StdIo = .Inherit,
    /// Controls whether argv[0] is searched/expanded.
    expand_arg0: std.process.Child.Arg0Expand = .no_expand,
};

/// Wait for a PID to exit (platform support varies).
/// Wait for `pid` to exit.
///
/// On Windows, `exit_code` is typically available.
/// On Linux/macOS, `exit_code` is only available for child processes;
/// non-child PIDs return `exit_code = null` once the PID disappears.
pub fn waitPid(pid: u32) !WaitPidResult {
    try validatePid(pid);
    const exec = (try platform.GetModule()).waitProcess;
    return try exec(pid);
}

/// Wait for a spawned child process and return its termination status.
pub fn wait(child: *std.process.Child) !ExitStatus {
    return try child.wait();
}

/// Wait for all children in `children_list` and return their exit statuses.
///
/// The returned slice is owned by the caller and must be freed with `allocator.free`.
pub fn waitAll(allocator: mem.Allocator, children_list: []const *std.process.Child) ![]ExitStatus {
    const exit_statuses = try allocator.alloc(ExitStatus, children_list.len);
    errdefer allocator.free(exit_statuses);

    for (children_list, 0..) |child, idx| {
        exit_statuses[idx] = try child.wait();
    }
    return exit_statuses;
}

/// Return the executable path for a PID.
///
/// The returned `OwnedBytes` must be released with `deinit`.
pub fn exePath(allocator: mem.Allocator, pid: u32) !OwnedBytes {
    try validatePid(pid);
    const exec = (try platform.GetModule()).exePath;
    const bytes = try exec(allocator, pid);
    return .{ .allocator = allocator, .bytes = bytes };
}

fn pathBaseName(path: []const u8) []const u8 {
    var end = path.len;
    while (end > 0) : (end -= 1) {
        const c = path[end - 1];
        if (c != '/' and c != '\\') break;
    }
    if (end == 0) return "";

    var idx: usize = end;
    while (idx > 0) : (idx -= 1) {
        const c = path[idx - 1];
        if (c == '/' or c == '\\') return path[idx..end];
    }
    return path[0..end];
}

/// Return a canonical executable name (base name) for a PID.
///
/// This is the last path component of `exePath()`. On Windows, the result
/// typically includes the `.exe` extension.
///
/// The returned `OwnedBytes` must be released with `deinit`.
pub fn exeName(allocator: mem.Allocator, pid: u32) !OwnedBytes {
    try validatePid(pid);
    var exe = try exePath(allocator, pid);
    defer exe.deinit();
    return .{ .allocator = allocator, .bytes = try allocator.dupe(u8, pathBaseName(exe.bytes)) };
}

/// Return argv for a PID (UTF-8 args).
///
/// The returned `OwnedArgv` must be released with `deinit`.
pub fn cmdline(allocator: mem.Allocator, pid: u32) !OwnedArgv {
    try validatePid(pid);
    const exec = (try platform.GetModule()).cmdline;
    return try exec(allocator, pid);
}

/// Return the user identity for a PID (uid on POSIX, SID on Windows).
pub fn user(allocator: mem.Allocator, pid: u32) !OwnedUserId {
    try validatePid(pid);
    const exec = (try platform.GetModule()).userId;
    return try exec(allocator, pid);
}

/// Return a normalized user identity for a PID.
///
/// The normalized representation is intended to be comparable across OSes:
/// - POSIX: `uid:<number>`
/// - Windows: `sid:<sid-string>`
///
/// The returned `OwnedBytes` must be released with `deinit`.
pub fn userNormalized(allocator: mem.Allocator, pid: u32) !OwnedBytes {
    try validatePid(pid);
    var id = try user(allocator, pid);
    defer id.deinit();

    const out = switch (id.id) {
        .uid => |uid| try std.fmt.allocPrint(allocator, "uid:{d}", .{uid}),
        .sid => |sid| try std.fmt.allocPrint(allocator, "sid:{s}", .{sid}),
    };
    return .{ .allocator = allocator, .bytes = out };
}

/// Return resource usage for a PID (best-effort, fields may be null).
pub fn resourceUsage(pid: u32) !ResourceUsage {
    try validatePid(pid);
    const exec = (try platform.GetModule()).resourceUsage;
    return try exec(pid);
}

test "forEachProcessInfo" {
    const allocator = std.testing.allocator;
    if (builtin.os.tag == .wasi or builtin.os.tag == .freestanding) return;

    const Stop = error{Found};
    var count: usize = 0;

    forEachProcessInfo(allocator, &count, struct {
        fn cb(ctx: *usize, info: process.ProcessInfo) !void {
            _ = info;
            ctx.* += 1;
            return Stop.Found;
        }
    }.cb) catch |err| {
        if (err != Stop.Found) return err;
    };

    try std.testing.expectEqual(@as(usize, 1), count);
}

test "exists and getProcessInfo for self" {
    const allocator = std.testing.allocator;
    if (builtin.os.tag == .wasi or builtin.os.tag == .freestanding) return;

    const self_pid: u32 = switch (builtin.os.tag) {
        .windows => @intCast(std.os.windows.GetCurrentProcessId()),
        else => @intCast(std.posix.getpid()),
    };

    try std.testing.expect(try exists(self_pid));

    var info = try getProcessInfo(allocator, self_pid);
    defer info.deinit();
    try std.testing.expect(info.pid == self_pid);
}

test "spawn + wait returns exit status" {
    const allocator = std.testing.allocator;
    if (builtin.os.tag == .wasi or builtin.os.tag == .freestanding) return;

    const argv = switch (builtin.os.tag) {
        .windows => &[_][]const u8{ "cmd.exe", "/C", "exit", "7" },
        else => &[_][]const u8{ "/bin/sh", "-c", "exit 7" },
    };

    var child = try spawn(allocator, argv, .{ .stdin = .Ignore, .stdout = .Ignore, .stderr = .Ignore, .expand_arg0 = .no_expand });
    const term = try child.wait();
    try std.testing.expect(term == .Exited);
    try std.testing.expectEqual(@as(u8, 7), term.Exited);
}

test "waitPid returns normalized exit info" {
    const allocator = std.testing.allocator;
    if (builtin.os.tag == .wasi or builtin.os.tag == .freestanding) return;

    const argv = switch (builtin.os.tag) {
        .windows => &[_][]const u8{ "cmd.exe", "/C", "exit", "7" },
        else => &[_][]const u8{ "/bin/sh", "-c", "exit 7" },
    };

    var child = try spawn(allocator, argv, .{ .stdin = .Ignore, .stdout = .Ignore, .stderr = .Ignore, .expand_arg0 = .no_expand });
    const pid: u32 = switch (builtin.os.tag) {
        .windows => GetProcessId(child.id),
        else => @intCast(child.id),
    };

    const res = try waitPid(pid);
    try std.testing.expect(res.exited);
    try std.testing.expectEqual(@as(?u32, 7), res.exit_code);

    if (builtin.os.tag == .windows) {
        _ = try child.wait();
    }
}

test "exePath/cmdline/user/resourceUsage for self" {
    const allocator = std.testing.allocator;
    if (builtin.os.tag == .wasi or builtin.os.tag == .freestanding) return;

    const self_pid: u32 = switch (builtin.os.tag) {
        .windows => @intCast(std.os.windows.GetCurrentProcessId()),
        else => @intCast(std.posix.getpid()),
    };

    var exe = try exePath(allocator, self_pid);
    defer exe.deinit();
    try std.testing.expect(exe.bytes.len > 0);

    var exe_name = try exeName(allocator, self_pid);
    defer exe_name.deinit();
    try std.testing.expect(exe_name.bytes.len > 0);
    try std.testing.expect(std.mem.indexOfAny(u8, exe_name.bytes, "/\\") == null);
    try std.testing.expectEqualStrings(pathBaseName(exe.bytes), exe_name.bytes);

    var cl = cmdline(allocator, self_pid) catch |err| switch (err) {
        Error.UnsupportedFeature => return,
        else => return err,
    };
    defer cl.deinit();
    try std.testing.expect(cl.argv.len > 0);
    try std.testing.expect(cl.argv[0].len > 0);

    var user_id = try user(allocator, self_pid);
    defer user_id.deinit();
    switch (user_id.id) {
        .uid => |uid| try std.testing.expect(uid >= 0),
        .sid => |sid| try std.testing.expect(sid.len > 0),
    }

    var norm_user = try userNormalized(allocator, self_pid);
    defer norm_user.deinit();
    try std.testing.expect(norm_user.bytes.len > 0);
    try std.testing.expect(
        std.mem.startsWith(u8, norm_user.bytes, "uid:") or
            std.mem.startsWith(u8, norm_user.bytes, "sid:"),
    );

    const ru = try resourceUsage(self_pid);
    try std.testing.expect(ru.rss_bytes != null or ru.user_cpu_ns != null or ru.kernel_cpu_ns != null);
    if (ru.start_time_is_unix_epoch) {
        try std.testing.expect(ru.start_time_unix_ns != null);
        try std.testing.expectEqual(ru.start_time_ns, ru.start_time_unix_ns);
    } else {
        if (ru.start_time_unix_ns) |ts| try std.testing.expect(ts > std.time.ns_per_s);
    }
}

test "cmdline returns normalized argv for self" {
    const allocator = std.testing.allocator;
    if (builtin.os.tag == .wasi or builtin.os.tag == .freestanding) return;

    const self_pid: u32 = switch (builtin.os.tag) {
        .windows => @intCast(std.os.windows.GetCurrentProcessId()),
        else => @intCast(std.posix.getpid()),
    };

    var cl = try cmdline(allocator, self_pid);
    defer cl.deinit();

    const std_argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, std_argv);

    try std.testing.expectEqual(std_argv.len, cl.argv.len);
    for (std_argv, cl.argv) |a, b| try std.testing.expectEqualStrings(a, b);
}

test "pid 0 is invalid" {
    const allocator = std.testing.allocator;
    if (builtin.os.tag == .wasi or builtin.os.tag == .freestanding) return;

    try std.testing.expectError(Error.InvalidPid, exists(0));
    try std.testing.expectError(Error.InvalidPid, getProcessInfo(allocator, 0));
    try std.testing.expectError(Error.InvalidPid, kill(0, .{}));
    try std.testing.expectError(Error.InvalidPid, exePath(allocator, 0));
    try std.testing.expectError(Error.InvalidPid, cmdline(allocator, 0));
    try std.testing.expectError(Error.InvalidPid, user(allocator, 0));
    try std.testing.expectError(Error.InvalidPid, resourceUsage(0));
}

test "killing a reaped child returns NotFound" {
    const allocator = std.testing.allocator;
    if (builtin.os.tag == .wasi or builtin.os.tag == .freestanding) return;

    const argv = switch (builtin.os.tag) {
        .windows => &[_][]const u8{ "cmd.exe", "/C", "exit", "0" },
        else => &[_][]const u8{ "/bin/sh", "-c", "exit 0" },
    };

    var child = try spawn(allocator, argv, .{ .stdin = .Ignore, .stdout = .Ignore, .stderr = .Ignore, .expand_arg0 = .no_expand });
    const pid: u32 = switch (builtin.os.tag) {
        .windows => GetProcessId(child.id),
        else => @intCast(child.id),
    };
    _ = try child.wait();

    if (exists(pid) catch false) return;
    try std.testing.expectError(Error.NotFound, kill(pid, .{}));
}

test "children pid list is deterministic (sorted)" {
    var pids = [_]u32{ 10, 2, 7, 7, 3 };
    std.sort.heap(u32, pids[0..], {}, std.sort.asc(u32));
    try std.testing.expectEqualSlices(u32, &[_]u32{ 2, 3, 7, 7, 10 }, pids[0..]);
}

test "windows kill supports all signals" {
    const allocator = std.testing.allocator;
    if (builtin.os.tag != .windows) return;

    const signals = [_]Signal{ .term, .kill, .int, .hup, .quit };
    for (signals) |sig| {
        const argv = &[_][]const u8{
            "cmd.exe",
            "/C",
            "timeout /T 2 /NOBREAK >NUL",
        };

        var child = try spawn(allocator, argv, .{ .stdin = .Ignore, .stdout = .Ignore, .stderr = .Ignore, .expand_arg0 = .no_expand });
        defer _ = child.wait() catch {};

        const pid: u32 = @intCast(GetProcessId(child.id));
        kill(pid, .{ .mode = .graceful, .signal = sig }) catch |err| switch (err) {
            Error.NotFound, Error.AccessDenied => {},
            else => return err,
        };
    }
}
