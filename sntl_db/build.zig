const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.pic = true;

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "sntl_db",
        .root_module = mod,
    });

    b.installArtifact(lib);
}
