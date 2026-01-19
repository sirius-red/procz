const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const posix = std.posix;
const shared = @import("shared.zig");
const process = @import("../process.zig");

/// Platform identifier for this backend.
pub const name = "linux";

const Error = shared.Error;
const c_lib = std.c;

fn toPidT(pid: u32) Error!posix.pid_t {
    if (pid == 0) return Error.InvalidPid;
    const max_pid: u32 = @intCast(std.math.maxInt(posix.pid_t));
    if (pid > max_pid) return Error.InvalidPid;
    return @intCast(pid);
}

fn openProcDir() Error!std.fs.Dir {
    return std.fs.openDirAbsolute("/proc", .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => Error.NotFound,
        error.AccessDenied => Error.AccessDenied,
        else => Error.Unexpected,
    };
}

fn nextProcEntry(proc_iter: *std.fs.Dir.Iterator) Error!?std.fs.Dir.Entry {
    return proc_iter.next() catch |err| switch (err) {
        error.AccessDenied => Error.AccessDenied,
        else => Error.Unexpected,
    };
}

/// Enumerate process IDs and names on Linux using `/proc`.
///
/// The `name` slice passed to `callback` is backed by temporary storage and
/// must be copied if it needs to outlive the callback.
pub fn forEachProcessInfo(
    allocator: mem.Allocator,
    context: anytype,
    callback: shared.ForEachInfoCallback(@TypeOf(context)),
) !void {
    _ = allocator;

    var proc_dir = try openProcDir();
    defer proc_dir.close();

    var proc_iter = proc_dir.iterate();
    var name_buf: [256]u8 = undefined;

    while (true) {
        const entry = (try nextProcEntry(&proc_iter)) orelse break;
        if (entry.kind != .directory) continue;

        const pid_u32 = std.fmt.parseUnsigned(u32, entry.name, 10) catch continue;

        var name_slice: []const u8 = "";
        var comm_path_buf: [64]u8 = undefined;
        const comm_path = std.fmt.bufPrint(&comm_path_buf, "/proc/{d}/comm", .{pid_u32}) catch {
            try callback(context, .{ .pid = pid_u32, .name = name_slice });
            continue;
        };

        const comm_file = std.fs.openFileAbsolute(comm_path, .{}) catch null;
        if (comm_file) |file| {
            defer file.close();
            const bytes_read = file.readAll(&name_buf) catch 0;
            if (bytes_read > 0) {
                name_slice = std.mem.trimRight(u8, name_buf[0..bytes_read], "\r\n");
            }
        }

        try callback(context, .{ .pid = pid_u32, .name = name_slice });
    }
}

/// Kill a process by PID.
pub fn killProcess(pid: u32) !void {
    const pid_t = try toPidT(pid);
    posix.kill(pid_t, posix.SIG.TERM) catch |err| switch (err) {
        error.ProcessNotFound => return Error.NotFound,
        error.PermissionDenied => return Error.AccessDenied,
        else => return Error.Unexpected,
    };
}

/// Kill multiple processes by PID.
pub fn killProcesses(pids: []const u32) !void {
    for (pids) |pid| try killProcess(pid);
}

/// Kill a process by PID using `KillOptions`.
pub fn killProcessWithOptions(pid: u32, options: shared.KillOptions) !void {
    const pid_t = try toPidT(pid);

    const sig = if (options.signal) |s| switch (s) {
        .term => posix.SIG.TERM,
        .kill => posix.SIG.KILL,
        .int => posix.SIG.INT,
        .hup => posix.SIG.HUP,
        .quit => posix.SIG.QUIT,
    } else switch (options.mode) {
        .graceful => posix.SIG.TERM,
        .force => posix.SIG.KILL,
    };

    posix.kill(pid_t, sig) catch |err| switch (err) {
        error.ProcessNotFound => return Error.NotFound,
        error.PermissionDenied => return Error.AccessDenied,
        else => return Error.Unexpected,
    };
}

fn procFilePath(buf: []u8, pid: u32, leaf: []const u8) Error![]const u8 {
    if (pid == 0) return Error.InvalidPid;
    return std.fmt.bufPrint(buf, "/proc/{d}/{s}", .{ pid, leaf }) catch Error.Unexpected;
}

/// Best-effort existence check for a PID.
pub fn processExists(pid: u32) !bool {
    var path_buf: [64]u8 = undefined;
    const path = try procFilePath(&path_buf, pid, "stat");
    const file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        error.AccessDenied => return true,
        else => return Error.Unexpected,
    };
    file.close();
    return true;
}

/// Query process info for a single PID.
pub fn getProcessInfo(allocator: mem.Allocator, pid: u32) !process.OwnedProcessInfo {
    var path_buf: [64]u8 = undefined;
    const path = try procFilePath(&path_buf, pid, "comm");
    const file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return Error.NotFound,
        error.AccessDenied => return Error.AccessDenied,
        else => return Error.Unexpected,
    };
    defer file.close();

    var name_buf: [256]u8 = undefined;
    const bytes_read = file.readAll(&name_buf) catch 0;
    const trimmed = std.mem.trimRight(u8, name_buf[0..bytes_read], "\r\n");
    const owned = try allocator.dupe(u8, trimmed);
    return .{ .allocator = allocator, .pid = pid, .name = owned };
}

fn parseProcStatAfterComm(stat: []const u8) ![]const u8 {
    const close_paren = std.mem.lastIndexOfScalar(u8, stat, ')') orelse return Error.Unexpected;
    if (close_paren + 2 > stat.len) return Error.Unexpected;
    return stat[(close_paren + 2)..];
}

fn parseProcStatFields(pid: u32) !struct { ppid: u32, utime: u64, stime: u64, starttime: u64, rss_pages: i64 } {
    var path_buf: [64]u8 = undefined;
    const path = try procFilePath(&path_buf, pid, "stat");
    const file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return Error.NotFound,
        error.AccessDenied => return Error.AccessDenied,
        else => return Error.Unexpected,
    };
    defer file.close();

    var buf: [4096]u8 = undefined;
    const bytes_read = file.readAll(&buf) catch return Error.Unexpected;
    const rest = try parseProcStatAfterComm(buf[0..bytes_read]);

    var it = std.mem.tokenizeScalar(u8, rest, ' ');
    var idx: usize = 0;

    var ppid: ?u32 = null;
    var utime: ?u64 = null;
    var stime: ?u64 = null;
    var starttime: ?u64 = null;
    var rss: ?i64 = null;

    while (it.next()) |tok| : (idx += 1) {
        if (idx == 1) ppid = std.fmt.parseUnsigned(u32, tok, 10) catch null;
        if (idx == 11) utime = std.fmt.parseUnsigned(u64, tok, 10) catch null;
        if (idx == 12) stime = std.fmt.parseUnsigned(u64, tok, 10) catch null;
        if (idx == 19) starttime = std.fmt.parseUnsigned(u64, tok, 10) catch null;
        if (idx == 21) rss = std.fmt.parseInt(i64, tok, 10) catch null;
    }

    return .{
        .ppid = ppid orelse return Error.Unexpected,
        .utime = utime orelse return Error.Unexpected,
        .stime = stime orelse return Error.Unexpected,
        .starttime = starttime orelse return Error.Unexpected,
        .rss_pages = rss orelse return Error.Unexpected,
    };
}

pub fn parentPid(pid: u32) !?u32 {
    const fields = try parseProcStatFields(pid);
    return fields.ppid;
}

/// Return the list of children PIDs for `pid`.
///
/// The returned slice is owned by the caller and must be freed with `allocator.free`.
pub fn childrenPids(allocator: mem.Allocator, pid: u32) ![]u32 {
    var proc_dir = try openProcDir();
    defer proc_dir.close();

    var proc_iter = proc_dir.iterate();
    var list: std.ArrayList(u32) = .empty;
    errdefer list.deinit(allocator);

    while (true) {
        const entry = (try nextProcEntry(&proc_iter)) orelse break;
        if (entry.kind != .directory) continue;
        const child_pid = std.fmt.parseUnsigned(u32, entry.name, 10) catch continue;
        const parent_pid = parentPid(child_pid) catch continue;
        if (parent_pid != null and parent_pid.? == pid) try list.append(allocator, child_pid);
    }

    return try list.toOwnedSlice(allocator);
}

/// Return the executable path for `pid`.
pub fn exePath(allocator: mem.Allocator, pid: u32) ![]u8 {
    var path_buf: [64]u8 = undefined;
    const path = try procFilePath(&path_buf, pid, "exe");

    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const target = std.fs.readLinkAbsolute(path, &link_buf) catch |err| switch (err) {
        error.FileNotFound => return Error.NotFound,
        error.AccessDenied => return Error.AccessDenied,
        else => return Error.Unexpected,
    };

    return allocator.dupe(u8, target);
}

/// Return the command line for `pid`.
pub fn cmdline(allocator: mem.Allocator, pid: u32) !shared.OwnedArgv {
    var path_buf: [64]u8 = undefined;
    const path = try procFilePath(&path_buf, pid, "cmdline");
    const file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return Error.NotFound,
        error.AccessDenied => return Error.AccessDenied,
        else => return Error.Unexpected,
    };
    defer file.close();

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    const raw = try file.readToEndAlloc(a, 1024 * 1024);

    var end = raw.len;
    while (end > 0 and raw[end - 1] == 0) : (end -= 1) {}

    var args: std.ArrayList([]const u8) = .empty;

    var idx: usize = 0;
    while (idx < end) {
        const start = idx;
        while (idx < end and raw[idx] != 0) : (idx += 1) {}
        const arg = raw[start..idx];
        try args.append(a, try a.dupe(u8, arg));

        if (idx == end) break;
        idx += 1; // skip NUL separator
    }

    return .{ .arena = arena, .argv = try args.toOwnedSlice(a) };
}

/// Return the user identity (uid) for `pid`.
pub fn userId(allocator: mem.Allocator, pid: u32) !shared.OwnedUserId {
    var path_buf: [64]u8 = undefined;
    const path = try procFilePath(&path_buf, pid, "status");
    const file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return Error.NotFound,
        error.AccessDenied => return Error.AccessDenied,
        else => return Error.Unexpected,
    };
    defer file.close();

    var buf: [8192]u8 = undefined;
    const bytes_read = file.readAll(&buf) catch return Error.Unexpected;
    const contents = buf[0..bytes_read];

    var line_it = std.mem.tokenizeScalar(u8, contents, '\n');
    while (line_it.next()) |line| {
        if (!std.mem.startsWith(u8, line, "Uid:")) continue;
        var tok_it = std.mem.tokenizeAny(u8, line, " \t");
        _ = tok_it.next();
        const uid_str = tok_it.next() orelse return Error.Unexpected;
        const uid = std.fmt.parseUnsigned(u32, uid_str, 10) catch return Error.Unexpected;
        return .{ .allocator = allocator, .id = .{ .uid = uid } };
    }

    return Error.Unexpected;
}

/// Wait for `pid` to exit (not yet supported on Linux in this library).
pub fn waitProcess(pid: u32) !shared.WaitPidResult {
    if (pid == 0) return Error.InvalidPid;
    if (!try processExists(pid)) return Error.NotFound;

    const pid_t = try toPidT(pid);
    var status: if (builtin.link_libc) c_int else u32 = undefined;

    while (true) {
        const rc = posix.system.waitpid(pid_t, &status, 0);
        if (rc != -1) {
            const st: u32 = @bitCast(status);
            const exited = (st & 0x7f) == 0;
            const exit_code: ?u32 = if (exited) @intCast((st >> 8) & 0xff) else null;
            return .{ .exited = true, .exit_code = exit_code };
        }

        switch (posix.errno(rc)) {
            .INTR => continue,
            .CHILD => break, // not a child process of this process
            else => return Error.Unexpected,
        }
    }

    var sleep_ns: u64 = 10 * std.time.ns_per_ms;
    const max_sleep_ns: u64 = 250 * std.time.ns_per_ms;
    while (try processExists(pid)) {
        std.Thread.sleep(sleep_ns);
        sleep_ns = @min(max_sleep_ns, sleep_ns * 2);
    }

    return .{ .exited = true, .exit_code = null };
}

/// Return resource usage information for `pid`.
pub fn resourceUsage(pid: u32) !shared.ResourceUsage {
    const fields = try parseProcStatFields(pid);

    const clk_tck = c_lib.sysconf(c_lib._SC.CLK_TCK);
    if (clk_tck <= 0) return Error.Unexpected;
    const page_size = c_lib.sysconf(c_lib._SC.PAGESIZE);
    if (page_size <= 0) return Error.Unexpected;

    const tck: u64 = @intCast(clk_tck);
    const ps: u64 = @intCast(page_size);

    const user_ns = (fields.utime * 1_000_000_000) / tck;
    const kernel_ns = (fields.stime * 1_000_000_000) / tck;
    const start_ns = (fields.starttime * 1_000_000_000) / tck;
    const rss_bytes = if (fields.rss_pages <= 0) @as(u64, 0) else @as(u64, @intCast(fields.rss_pages)) * ps;

    return .{
        .rss_bytes = rss_bytes,
        .user_cpu_ns = user_ns,
        .kernel_cpu_ns = kernel_ns,
        .start_time_ns = start_ns,
        .start_time_is_unix_epoch = false,
    };
}
