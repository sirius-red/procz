const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optmize = b.standardOptimizeOption(.{});

    const mod = b.addModule("procz", .{
        .root_source_file = b.path("src/procz.zig"),
        .target = target,
        .optimize = optmize,
    });

    const mod_test = b.addTest(.{ .root_module = mod });
    const run_mod_test = b.addRunArtifact(mod_test);

    const test_step = b.step("test", "Runs tests.");
    test_step.dependOn(&run_mod_test.step);
}
