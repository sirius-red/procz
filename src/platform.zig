const builtin = @import("builtin");

/// Shared platform declarations (callbacks, error set, etc).
pub const shared = @import("platform/shared.zig");

/// Return the platform module for the current operating system.
///
/// The returned type exports the platform implementation (e.g.
/// `forEachProcessInfo` and `killProcess`).
pub fn GetModule() !type {
    return switch (builtin.os.tag) {
        .windows => @import("platform/windows.zig"),
        .linux => @import("platform/linux.zig"),
        .macos => @import("platform/macos.zig"),
        else => shared.Error.UnsupportedOS,
    };
}

test "GetModule selects current backend" {
    const std = @import("std");

    if (builtin.os.tag != .windows and builtin.os.tag != .linux and builtin.os.tag != .macos) {
        try std.testing.expectError(shared.Error.UnsupportedOS, GetModule());
        return;
    }

    const mod = try GetModule();
    switch (builtin.os.tag) {
        .windows => try std.testing.expectEqualStrings("windows", mod.name),
        .linux => try std.testing.expectEqualStrings("linux", mod.name),
        .macos => try std.testing.expectEqualStrings("macos", mod.name),
        else => unreachable,
    }
}
