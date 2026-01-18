const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const posix = std.posix;
const shared = @import("shared.zig");
const process = @import("../process.zig");

/// Platform identifier for this backend.
pub const name = "macos";

const Error = shared.Error;

fn toPidT(pid: u32) Error!posix.pid_t {
    if (pid == 0) return Error.InvalidPid;
    const max_pid: u32 = @intCast(std.math.maxInt(posix.pid_t));
    if (pid > max_pid) return Error.InvalidPid;
    return @intCast(pid);
}

fn errnoToError(errno_value: posix.E) Error {
    return switch (errno_value) {
        .PERM, .ACCES => Error.AccessDenied,
        .SRCH, .NOENT => Error.NotFound,
        .INVAL => Error.InvalidPid,
        else => Error.Unexpected,
    };
}

fn sysctlCheck(rc: c_int) Error!void {
    if (rc == 0) return;
    return errnoToError(posix.errno(rc));
}

fn libcErrno() posix.E {
    if (!builtin.link_libc) return .SUCCESS;
    return @enumFromInt(std.c._errno().*);
}

/// Enumerate process IDs and names on macOS using `sysctl(KERN_PROC_ALL)`.
///
/// The `name` slice passed to `callback` is backed by temporary storage and
/// must be copied if it needs to outlive the callback.
pub fn forEachProcessInfo(
    allocator: mem.Allocator,
    context: anytype,
    callback: shared.ForEachInfoCallback(@TypeOf(context)),
) !void {
    const c_api = @cImport({
        @cInclude("sys/types.h");
        @cInclude("sys/sysctl.h");
        @cInclude("sys/user.h"); // struct kinfo_proc
    });

    var mib = [_]c_int{ c_api.CTL_KERN, c_api.KERN_PROC, c_api.KERN_PROC_ALL, 0 };

    var size: usize = 0;
    try sysctlCheck(c_api.sysctl(&mib, mib.len, null, &size, null, 0));

    const buf = try allocator.alloc(u8, size);
    defer allocator.free(buf);

    try sysctlCheck(c_api.sysctl(&mib, mib.len, buf.ptr, &size, null, 0));

    const count = size / @sizeOf(c_api.struct_kinfo_proc);
    const procs: [*]c_api.struct_kinfo_proc = @ptrCast(@alignCast(buf.ptr));

    var proc_idx: usize = 0;
    while (proc_idx < count) : (proc_idx += 1) {
        const kp = procs[proc_idx];

        const pid_i32: i32 = @intCast(kp.kp_proc.p_pid);
        if (pid_i32 <= 0) continue;

        const comm_ptr: [*:0]const u8 = @ptrCast(&kp.kp_proc.p_comm[0]);
        const comm = std.mem.span(comm_ptr);

        try callback(context, @intCast(pid_i32), comm);
    }
}

/// Kill a process by PID.
pub fn killProcess(pid: u32) !void {
    const pid_t = try toPidT(pid);
    posix.kill(pid_t, posix.SIG.TERM) catch |err| switch (err) {
        error.ProcessNotFound => return Error.NotFound,
        error.PermissionDenied => return Error.AccessDenied,
        error.InvalidArgument => return Error.InvalidPid,
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
        error.InvalidArgument => return Error.InvalidPid,
        else => return Error.Unexpected,
    };
}

/// Best-effort existence check for a PID.
pub fn processExists(pid: u32) !bool {
    const pid_t = try toPidT(pid);
    posix.kill(pid_t, 0) catch |err| switch (err) {
        error.ProcessNotFound => return false,
        error.PermissionDenied => return true,
        error.InvalidArgument => return Error.InvalidPid,
        else => return Error.Unexpected,
    };
    return true;
}

/// Query process info for a single PID.
pub fn getProcessInfo(allocator: mem.Allocator, pid: u32) !process.OwnedProcessInfo {
    _ = try toPidT(pid);
    const c_api = @cImport({
        @cInclude("sys/types.h");
        @cInclude("sys/sysctl.h");
        @cInclude("sys/user.h");
    });

    var mib = [_]c_int{ c_api.CTL_KERN, c_api.KERN_PROC, c_api.KERN_PROC_ALL, 0 };

    var size: usize = 0;
    try sysctlCheck(c_api.sysctl(&mib, mib.len, null, &size, null, 0));

    const buf = try allocator.alloc(u8, size);
    defer allocator.free(buf);

    try sysctlCheck(c_api.sysctl(&mib, mib.len, buf.ptr, &size, null, 0));

    const count = size / @sizeOf(c_api.struct_kinfo_proc);
    const procs: [*]c_api.struct_kinfo_proc = @ptrCast(@alignCast(buf.ptr));

    var proc_idx: usize = 0;
    while (proc_idx < count) : (proc_idx += 1) {
        const kp = procs[proc_idx];
        const pid_i32: i32 = @intCast(kp.kp_proc.p_pid);
        if (pid_i32 <= 0) continue;
        if (@as(u32, @intCast(pid_i32)) != pid) continue;

        const comm_ptr: [*:0]const u8 = @ptrCast(&kp.kp_proc.p_comm[0]);
        const comm = std.mem.span(comm_ptr);
        const owned = try allocator.dupe(u8, comm);
        return .{ .allocator = allocator, .pid = pid, .name = owned };
    }

    return Error.NotFound;
}

/// Return the parent PID for `pid`, if available.
pub fn parentPid(pid: u32) !?u32 {
    _ = try toPidT(pid);
    const c_api = @cImport({
        @cInclude("sys/types.h");
        @cInclude("sys/sysctl.h");
        @cInclude("sys/user.h");
    });

    var mib = [_]c_int{ c_api.CTL_KERN, c_api.KERN_PROC, c_api.KERN_PROC_ALL, 0 };
    var size: usize = 0;
    try sysctlCheck(c_api.sysctl(&mib, mib.len, null, &size, null, 0));

    const buf = try std.heap.page_allocator.alloc(u8, size);
    defer std.heap.page_allocator.free(buf);

    try sysctlCheck(c_api.sysctl(&mib, mib.len, buf.ptr, &size, null, 0));

    const count = size / @sizeOf(c_api.struct_kinfo_proc);
    const procs: [*]c_api.struct_kinfo_proc = @ptrCast(@alignCast(buf.ptr));

    var proc_idx: usize = 0;
    while (proc_idx < count) : (proc_idx += 1) {
        const kp = procs[proc_idx];
        const pid_i32: i32 = @intCast(kp.kp_proc.p_pid);
        if (pid_i32 <= 0) continue;
        if (@as(u32, @intCast(pid_i32)) != pid) continue;
        return @intCast(kp.kp_eproc.e_ppid);
    }
    return null;
}

/// Return the list of children PIDs for `pid`.
///
/// The returned slice is owned by the caller and must be freed with `allocator.free`.
pub fn childrenPids(allocator: mem.Allocator, pid: u32) ![]u32 {
    _ = try toPidT(pid);
    const c_api = @cImport({
        @cInclude("sys/types.h");
        @cInclude("sys/sysctl.h");
        @cInclude("sys/user.h");
    });

    var mib = [_]c_int{ c_api.CTL_KERN, c_api.KERN_PROC, c_api.KERN_PROC_ALL, 0 };
    var size: usize = 0;
    try sysctlCheck(c_api.sysctl(&mib, mib.len, null, &size, null, 0));

    const buf = try allocator.alloc(u8, size);
    defer allocator.free(buf);

    try sysctlCheck(c_api.sysctl(&mib, mib.len, buf.ptr, &size, null, 0));

    const count = size / @sizeOf(c_api.struct_kinfo_proc);
    const procs: [*]c_api.struct_kinfo_proc = @ptrCast(@alignCast(buf.ptr));

    var list = std.ArrayList(u32).init(allocator);
    errdefer list.deinit();

    var proc_idx: usize = 0;
    while (proc_idx < count) : (proc_idx += 1) {
        const kp = procs[proc_idx];
        const pid_i32: i32 = @intCast(kp.kp_proc.p_pid);
        if (pid_i32 <= 0) continue;
        const ppid: u32 = @intCast(kp.kp_eproc.e_ppid);
        if (ppid == pid) try list.append(@intCast(pid_i32));
    }

    return try list.toOwnedSlice();
}

/// Return the executable path for `pid`.
pub fn exePath(allocator: mem.Allocator, pid: u32) ![]u8 {
    _ = try toPidT(pid);
    const c_api = @cImport({
        @cInclude("libproc.h");
    });

    var buf: [4096]u8 = undefined;
    const bytes_written: c_int = c_api.proc_pidpath(@intCast(pid), &buf, @intCast(buf.len));
    if (bytes_written <= 0) return errnoToError(libcErrno());
    return allocator.dupe(u8, buf[0..@intCast(bytes_written)]);
}

/// Return the command line for `pid`.
pub fn cmdline(allocator: mem.Allocator, pid: u32) ![]u8 {
    _ = try toPidT(pid);
    const c_api = @cImport({
        @cInclude("sys/types.h");
        @cInclude("sys/sysctl.h");
    });

    var mib = [_]c_int{ c_api.CTL_KERN, c_api.KERN_PROCARGS2, @intCast(pid) };
    var size: usize = 0;
    try sysctlCheck(c_api.sysctl(&mib, mib.len, null, &size, null, 0));

    const buf = try allocator.alloc(u8, size);
    defer allocator.free(buf);

    try sysctlCheck(c_api.sysctl(&mib, mib.len, buf.ptr, &size, null, 0));
    if (size < @sizeOf(c_int)) return Error.Unexpected;

    const argc: c_int = @bitCast(@as([*]const c_int, @ptrCast(@alignCast(buf.ptr)))[0]);
    if (argc <= 0) return Error.Unexpected;

    var idx: usize = @sizeOf(c_int);
    while (idx < size and buf[idx] != 0) : (idx += 1) {}
    while (idx < size and buf[idx] == 0) : (idx += 1) {}

    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    var arg_idx: c_int = 0;
    while (arg_idx < argc and idx < size) : (arg_idx += 1) {
        const start = idx;
        while (idx < size and buf[idx] != 0) : (idx += 1) {}
        const arg = buf[start..idx];
        if (arg.len != 0) {
            if (out.items.len != 0) try out.append(' ');
            try out.appendSlice(arg);
        }
        while (idx < size and buf[idx] == 0) : (idx += 1) {}
    }

    return try out.toOwnedSlice();
}

/// Return the user identity (uid) for `pid`.
pub fn userId(allocator: mem.Allocator, pid: u32) !shared.OwnedUserId {
    _ = try toPidT(pid);
    const c_api = @cImport({
        @cInclude("sys/types.h");
        @cInclude("sys/sysctl.h");
        @cInclude("sys/user.h");
    });

    var mib = [_]c_int{ c_api.CTL_KERN, c_api.KERN_PROC, c_api.KERN_PROC_ALL, 0 };
    var size: usize = 0;
    try sysctlCheck(c_api.sysctl(&mib, mib.len, null, &size, null, 0));

    const buf = try allocator.alloc(u8, size);
    defer allocator.free(buf);

    try sysctlCheck(c_api.sysctl(&mib, mib.len, buf.ptr, &size, null, 0));

    const count = size / @sizeOf(c_api.struct_kinfo_proc);
    const procs: [*]c_api.struct_kinfo_proc = @ptrCast(@alignCast(buf.ptr));

    var proc_idx: usize = 0;
    while (proc_idx < count) : (proc_idx += 1) {
        const kp = procs[proc_idx];
        const pid_i32: i32 = @intCast(kp.kp_proc.p_pid);
        if (pid_i32 <= 0) continue;
        if (@as(u32, @intCast(pid_i32)) != pid) continue;
        return .{ .allocator = allocator, .id = .{ .uid = @intCast(kp.kp_eproc.e_ucred.cr_uid) } };
    }
    return Error.NotFound;
}

/// Wait for `pid` to exit (not yet supported on macOS in this library).
pub fn waitProcess(pid: u32) !std.process.Child.Term {
    _ = try toPidT(pid);
    return Error.UnsupportedFeature;
}

/// Return resource usage information for `pid`.
pub fn resourceUsage(pid: u32) !shared.ResourceUsage {
    _ = try toPidT(pid);
    const c_api = @cImport({
        @cInclude("libproc.h");
    });

    var info: c_api.rusage_info_v2 = undefined;
    const result_code: c_int = c_api.proc_pid_rusage(@intCast(pid), c_api.RUSAGE_INFO_V2, &info);
    if (result_code != 0) return errnoToError(posix.errno(result_code));

    return .{
        .rss_bytes = info.ri_resident_size,
        .vms_bytes = info.ri_virtual_size,
        .user_cpu_ns = info.ri_user_time,
        .kernel_cpu_ns = info.ri_system_time,
        .start_time_ns = info.ri_proc_start_abstime,
        .start_time_is_unix_epoch = false,
    };
}
