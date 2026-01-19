const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const platform = @import("platform.zig");

/// Process information data returned by enumeration APIs.
pub const ProcessInfo = platform.shared.ProcessInfo;

/// Owned process information for APIs that query a single PID.
///
/// The `name` slice is owned by this object and must be released with `deinit`.
pub const OwnedProcessInfo = struct {
    allocator: mem.Allocator,
    pid: u32,
    name: []u8,

    pub fn deinit(self: *OwnedProcessInfo) void {
        self.allocator.free(self.name);
        self.* = undefined;
    }
};

/// Owned list of `ProcessInfo` values.
///
/// The `name` slices in `processes` are allocated from `arena`.
pub const OwnedProcessInfoList = struct {
    arena: std.heap.ArenaAllocator,
    processes: []ProcessInfo,

    /// Release all memory associated with this list.
    pub fn deinit(self: *OwnedProcessInfoList) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
