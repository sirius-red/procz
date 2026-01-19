const std = @import("std");

/// Error set used across all platform backends.
pub const Error = error{
    UnsupportedOS,
    /// The current backend does not support this operation.
    UnsupportedFeature,
    /// Operation denied by OS permissions/ACL.
    AccessDenied,
    /// Requested PID or resource was not found.
    NotFound,
    /// Invalid PID provided by the caller.
    InvalidPid,
    /// A timeout expired before the operation completed.
    Timeout,
    /// An unexpected OS or parsing failure occurred.
    Unexpected,
};

/// Callback type used by `forEachProcessInfo`-style APIs.
///
/// The callback receives the PID and a process name slice (which may be backed
/// by temporary storage).
///
/// If the process name must outlive the callback, copy it into caller-owned
/// memory.
pub fn ForEachInfoCallback(comptime T: type) type {
    return fn (ctx: T, pid: u32, name: []const u8) anyerror!void;
}

/// High-level kill strategy for `KillOptions`.
pub const KillMode = enum {
    /// TODO: Add doc comment
    graceful,
    /// TODO: Add doc comment
    force,
};

/// Cross-platform signal selector for `KillOptions`.
pub const Signal = enum {
    /// TODO: Add doc comment
    term,
    /// TODO: Add doc comment
    kill,
    /// TODO: Add doc comment
    int,
    /// TODO: Add doc comment
    hup,
    /// TODO: Add doc comment
    quit,
};

/// Options used by `kill*` operations.
pub const KillOptions = struct {
    mode: KillMode = .graceful,
    signal: ?Signal = null,
};

/// Owned byte buffer returned by platform query functions.
pub const OwnedBytes = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,

    /// Release the owned buffer.
    pub fn deinit(self: *OwnedBytes) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

/// Owned argv list returned by `cmdline()`.
///
/// The argv slices are UTF-8 and allocated from `arena`.
pub const OwnedArgv = struct {
    arena: std.heap.ArenaAllocator,
    argv: []const []const u8,

    /// Release all memory associated with this argv list.
    pub fn deinit(self: *OwnedArgv) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Platform-dependent user identity.
pub const UserId = union(enum) {
    /// POSIX user id.
    uid: u32,
    /// Windows security identifier (SID) string.
    sid: []const u8,
};

/// Owned variant of `UserId`.
pub const OwnedUserId = struct {
    allocator: std.mem.Allocator,
    id: UserId,
    _owned_sid: ?[]u8 = null,

    /// Release any owned memory held by this identity.
    pub fn deinit(self: *OwnedUserId) void {
        if (self._owned_sid) |sid| self.allocator.free(sid);
        self.* = undefined;
    }
};

/// Best-effort process resource usage and timing data.
///
/// Field availability varies by platform and permissions.
pub const ResourceUsage = struct {
    rss_bytes: ?u64 = null,
    vms_bytes: ?u64 = null,
    user_cpu_ns: ?u64 = null,
    kernel_cpu_ns: ?u64 = null,
    start_time_ns: ?u64 = null,
    start_time_is_unix_epoch: bool = false,
};
