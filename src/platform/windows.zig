const std = @import("std");
const mem = std.mem;
const shared = @import("shared.zig");
const process = @import("../process.zig");

/// Platform identifier for this backend.
pub const name = "windows";

const Error = shared.Error;

const DWORD = u32;
const BOOL = i32;
const WCHAR = u16;
const HANDLE = usize;
const UINT = u32;
const ULONG = u32;
const LPVOID = ?*anyopaque;

const th32cs_snapprocess: DWORD = 0x00000002;
const invalid_handle_value: HANDLE = @as(HANDLE, @bitCast(@as(isize, -1)));

const max_path = 260;

const process_terminate: DWORD = 0x0001;
const process_query_limited_information: DWORD = 0x1000;
const process_vm_read: DWORD = 0x0010;
const synchronize: DWORD = 0x00100000;

const win_error_access_denied: DWORD = 5;
const win_error_invalid_handle: DWORD = 6;
const win_error_invalid_parameter: DWORD = 87;
const win_error_insufficient_buffer: DWORD = 122;

const PROCESSENTRY32W = extern struct {
    dw_size: DWORD,
    cnt_usage: DWORD,
    th32_process_id: DWORD,
    th32_default_heap_id: usize,
    th32_module_id: DWORD,
    cnt_threads: DWORD,
    th32_parent_process_id: DWORD,
    pc_pri_class_base: i32,
    dw_flags: DWORD,
    sz_exe_file: [max_path]WCHAR,
};

extern "kernel32" fn CreateToolhelp32Snapshot(dw_flags: DWORD, th32_process_id: DWORD) callconv(.winapi) HANDLE;
extern "kernel32" fn Process32FirstW(snapshot_handle: HANDLE, process_entry: *PROCESSENTRY32W) callconv(.winapi) BOOL;
extern "kernel32" fn Process32NextW(snapshot_handle: HANDLE, process_entry: *PROCESSENTRY32W) callconv(.winapi) BOOL;
extern "kernel32" fn CloseHandle(object_handle: HANDLE) callconv(.winapi) BOOL;
extern "kernel32" fn OpenProcess(desired_access: DWORD, inherit_handle: BOOL, process_id: DWORD) callconv(.winapi) HANDLE;
extern "kernel32" fn TerminateProcess(process_handle: HANDLE, exit_code: UINT) callconv(.winapi) BOOL;
extern "kernel32" fn GetLastError() callconv(.winapi) DWORD;
extern "kernel32" fn QueryFullProcessImageNameW(process_handle: HANDLE, flags: DWORD, exe_name: [*]WCHAR, exe_name_size: *DWORD) callconv(.winapi) BOOL;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) DWORD;
extern "kernel32" fn GetCommandLineW() callconv(.winapi) [*:0]const WCHAR;
extern "kernel32" fn WaitForSingleObject(handle: HANDLE, milliseconds: DWORD) callconv(.winapi) DWORD;
extern "kernel32" fn GetExitCodeProcess(process_handle: HANDLE, exit_code: *DWORD) callconv(.winapi) BOOL;
extern "kernel32" fn LocalFree(mem: LPVOID) callconv(.winapi) LPVOID;

extern "advapi32" fn OpenProcessToken(process_handle: HANDLE, desired_access: DWORD, token_handle: *HANDLE) callconv(.winapi) BOOL;
extern "advapi32" fn GetTokenInformation(
    token_handle: HANDLE,
    token_information_class: DWORD,
    token_information: LPVOID,
    token_information_length: DWORD,
    return_length: *DWORD,
) callconv(.winapi) BOOL;
extern "advapi32" fn ConvertSidToStringSidW(sid: LPVOID, string_sid: *[*:0]WCHAR) callconv(.winapi) BOOL;

extern "psapi" fn GetProcessMemoryInfo(process_handle: HANDLE, counters: *PROCESS_MEMORY_COUNTERS, size: DWORD) callconv(.winapi) BOOL;
extern "kernel32" fn GetProcessTimes(
    process_handle: HANDLE,
    creation_time: *FILETIME,
    exit_time: *FILETIME,
    kernel_time: *FILETIME,
    user_time: *FILETIME,
) callconv(.winapi) BOOL;

/// Return a slice view of a NUL-terminated UTF-16LE buffer.
fn wideSpan(buf: *const [max_path]WCHAR) []const u16 {
    var idx: usize = 0;
    while (idx < max_path and buf.*[idx] != 0) : (idx += 1) {}
    return buf.*[0..idx];
}

fn validatePid(pid: u32) Error!DWORD {
    if (pid == 0) return Error.InvalidPid;
    return @intCast(pid);
}

/// Enumerate process IDs and names on Windows using Tool Help snapshots.
///
/// The `name` slice passed to `callback` is backed by temporary storage and
/// must be copied if it needs to outlive the callback.
pub fn forEachProcessInfo(
    allocator: mem.Allocator,
    context: anytype,
    callback: shared.ForEachInfoCallback(@TypeOf(context)),
) !void {
    _ = allocator;

    const snapshot = CreateToolhelp32Snapshot(th32cs_snapprocess, 0);
    if (snapshot == invalid_handle_value) {
        return switch (GetLastError()) {
            win_error_access_denied => Error.AccessDenied,
            else => Error.Unexpected,
        };
    }
    defer _ = CloseHandle(snapshot);

    var pe: PROCESSENTRY32W = undefined;
    pe.dw_size = @sizeOf(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &pe) == 0) {
        return switch (GetLastError()) {
            win_error_access_denied => Error.AccessDenied,
            else => Error.Unexpected,
        };
    }

    var utf8_buf: [512]u8 = undefined;

    while (true) {
        const pid: u32 = pe.th32_process_id;

        const wide = wideSpan(&pe.sz_exe_file);
        var name_slice: []const u8 = "";
        {
            const utf8_len = std.unicode.utf16LeToUtf8(&utf8_buf, wide) catch 0;
            if (utf8_len > 0) name_slice = utf8_buf[0..utf8_len];
        }

        try callback(context, pid, name_slice);

        if (Process32NextW(snapshot, &pe) == 0) break;
    }
}

/// Kill a process by PID.
pub fn killProcess(pid: u32) !void {
    const pid_dword = try validatePid(pid);
    const handle = OpenProcess(process_terminate, 0, pid_dword);
    if (handle == 0) {
        switch (GetLastError()) {
            win_error_invalid_parameter => return Error.NotFound,
            win_error_access_denied => return Error.AccessDenied,
            else => return Error.Unexpected,
        }
    }
    defer _ = CloseHandle(handle);

    if (TerminateProcess(handle, 1) == 0) {
        switch (GetLastError()) {
            win_error_invalid_handle => return Error.NotFound,
            win_error_access_denied => return Error.AccessDenied,
            else => return Error.Unexpected,
        }
    }
}

/// Kill multiple processes by PID.
pub fn killProcesses(pids: []const u32) !void {
    for (pids) |pid| try killProcess(pid);
}

/// Kill a process by PID using `KillOptions`.
pub fn killProcessWithOptions(pid: u32, options: shared.KillOptions) !void {
    if (options.signal) |sig| switch (sig) {
        .term, .kill => {},
        else => return Error.UnsupportedFeature,
    };
    return killProcess(pid);
}

/// Best-effort existence check for a PID.
pub fn processExists(pid: u32) !bool {
    const pid_dword = try validatePid(pid);
    const handle = OpenProcess(process_query_limited_information, 0, pid_dword);
    if (handle == 0) {
        return switch (GetLastError()) {
            win_error_invalid_parameter => false,
            win_error_access_denied => true,
            else => Error.Unexpected,
        };
    }
    defer _ = CloseHandle(handle);
    return true;
}

/// Query process info for a single PID.
pub fn getProcessInfo(allocator: mem.Allocator, pid: u32) !process.OwnedProcessInfo {
    _ = try validatePid(pid);
    const snapshot = CreateToolhelp32Snapshot(th32cs_snapprocess, 0);
    if (snapshot == invalid_handle_value) {
        return switch (GetLastError()) {
            win_error_access_denied => Error.AccessDenied,
            else => Error.Unexpected,
        };
    }
    defer _ = CloseHandle(snapshot);

    var pe: PROCESSENTRY32W = undefined;
    pe.dw_size = @sizeOf(PROCESSENTRY32W);
    if (Process32FirstW(snapshot, &pe) == 0) {
        return switch (GetLastError()) {
            win_error_access_denied => Error.AccessDenied,
            else => Error.Unexpected,
        };
    }

    while (true) {
        if (pe.th32_process_id == pid) {
            const wide = wideSpan(&pe.sz_exe_file);
            const owned = if (wide.len == 0) try allocator.dupe(u8, "") else try std.unicode.utf16LeToUtf8Alloc(allocator, wide);
            return .{ .allocator = allocator, .pid = pid, .name = owned };
        }
        if (Process32NextW(snapshot, &pe) == 0) break;
    }
    return Error.NotFound;
}

/// Return the parent PID for `pid`, if available.
pub fn parentPid(pid: u32) !?u32 {
    _ = try validatePid(pid);
    const snapshot = CreateToolhelp32Snapshot(th32cs_snapprocess, 0);
    if (snapshot == invalid_handle_value) {
        return switch (GetLastError()) {
            win_error_access_denied => Error.AccessDenied,
            else => Error.Unexpected,
        };
    }
    defer _ = CloseHandle(snapshot);

    var pe: PROCESSENTRY32W = undefined;
    pe.dw_size = @sizeOf(PROCESSENTRY32W);
    if (Process32FirstW(snapshot, &pe) == 0) {
        return switch (GetLastError()) {
            win_error_access_denied => Error.AccessDenied,
            else => Error.Unexpected,
        };
    }

    while (true) {
        if (pe.th32_process_id == pid) return pe.th32_parent_process_id;
        if (Process32NextW(snapshot, &pe) == 0) break;
    }
    return null;
}

/// Return the list of children PIDs for `pid`.
///
/// The returned slice is owned by the caller and must be freed with `allocator.free`.
pub fn childrenPids(allocator: mem.Allocator, pid: u32) ![]u32 {
    _ = try validatePid(pid);
    const snapshot = CreateToolhelp32Snapshot(th32cs_snapprocess, 0);
    if (snapshot == invalid_handle_value) {
        return switch (GetLastError()) {
            win_error_access_denied => Error.AccessDenied,
            else => Error.Unexpected,
        };
    }
    defer _ = CloseHandle(snapshot);

    var pe: PROCESSENTRY32W = undefined;
    pe.dw_size = @sizeOf(PROCESSENTRY32W);
    if (Process32FirstW(snapshot, &pe) == 0) {
        return switch (GetLastError()) {
            win_error_access_denied => Error.AccessDenied,
            else => Error.Unexpected,
        };
    }

    var list = std.ArrayList(u32).init(allocator);
    errdefer list.deinit();

    while (true) {
        if (pe.th32_parent_process_id == pid) try list.append(pe.th32_process_id);
        if (Process32NextW(snapshot, &pe) == 0) break;
    }

    return try list.toOwnedSlice();
}

/// Return the executable path for `pid`.
pub fn exePath(allocator: mem.Allocator, pid: u32) ![]u8 {
    const pid_dword = try validatePid(pid);
    const handle = OpenProcess(process_query_limited_information, 0, pid_dword);
    if (handle == 0) {
        return switch (GetLastError()) {
            win_error_invalid_parameter => Error.NotFound,
            win_error_access_denied => Error.AccessDenied,
            else => Error.Unexpected,
        };
    }
    defer _ = CloseHandle(handle);

    var wide_buf: [32768]WCHAR = undefined;
    var size: DWORD = @intCast(wide_buf.len);
    if (QueryFullProcessImageNameW(handle, 0, &wide_buf, &size) == 0) {
        return switch (GetLastError()) {
            win_error_insufficient_buffer => Error.Unexpected,
            win_error_access_denied => Error.AccessDenied,
            win_error_invalid_parameter => Error.NotFound,
            else => Error.Unexpected,
        };
    }

    return std.unicode.utf16LeToUtf8Alloc(allocator, wide_buf[0..@intCast(size)]);
}

/// Return the command line for `pid` (only supported for the current process).
pub fn cmdline(allocator: mem.Allocator, pid: u32) ![]u8 {
    _ = try validatePid(pid);
    if (pid != GetCurrentProcessId()) return Error.UnsupportedFeature;
    const wide = std.mem.span(GetCommandLineW());
    return std.unicode.utf16LeToUtf8Alloc(allocator, wide);
}

/// Return the user identity (SID string) for `pid`.
pub fn userId(allocator: mem.Allocator, pid: u32) !shared.OwnedUserId {
    const token_query: DWORD = 0x0008;
    const token_user: DWORD = 1;

    const pid_dword = try validatePid(pid);
    const handle = OpenProcess(process_query_limited_information, 0, pid_dword);
    if (handle == 0) {
        return switch (GetLastError()) {
            win_error_invalid_parameter => Error.NotFound,
            win_error_access_denied => Error.AccessDenied,
            else => Error.Unexpected,
        };
    }
    defer _ = CloseHandle(handle);

    var token: HANDLE = 0;
    if (OpenProcessToken(handle, token_query, &token) == 0) {
        return switch (GetLastError()) {
            win_error_access_denied => Error.AccessDenied,
            else => Error.Unexpected,
        };
    }
    defer _ = CloseHandle(token);

    var needed: DWORD = 0;
    _ = GetTokenInformation(token, token_user, null, 0, &needed);
    if (needed == 0) return Error.Unexpected;

    const buf = try allocator.alloc(u8, needed);
    defer allocator.free(buf);

    if (GetTokenInformation(token, token_user, buf.ptr, needed, &needed) == 0) {
        return switch (GetLastError()) {
            win_error_access_denied => Error.AccessDenied,
            else => Error.Unexpected,
        };
    }

    const SID_AND_ATTRIBUTES = extern struct {
        sid: LPVOID,
        attributes: DWORD,
    };
    const TOKEN_USER = extern struct {
        user: SID_AND_ATTRIBUTES,
    };

    const tu: *const TOKEN_USER = @ptrCast(@alignCast(buf.ptr));

    var sid_w: [*:0]WCHAR = undefined;
    if (ConvertSidToStringSidW(tu.user.sid, &sid_w) == 0) return Error.Unexpected;
    defer _ = LocalFree(@ptrCast(sid_w));

    const sid_utf8 = try std.unicode.utf16LeToUtf8Alloc(allocator, std.mem.span(sid_w));
    return .{ .allocator = allocator, .id = .{ .sid = sid_utf8 }, ._owned_sid = sid_utf8 };
}

/// Wait for `pid` to exit and return its exit code.
pub fn waitProcess(pid: u32) !std.process.Child.Term {
    const wait_object_0: DWORD = 0x00000000;
    const infinite: DWORD = 0xFFFFFFFF;

    const pid_dword = try validatePid(pid);
    const handle = OpenProcess(synchronize | process_query_limited_information, 0, pid_dword);
    if (handle == 0) {
        return switch (GetLastError()) {
            win_error_invalid_parameter => Error.NotFound,
            win_error_access_denied => Error.AccessDenied,
            else => Error.Unexpected,
        };
    }
    defer _ = CloseHandle(handle);

    const wait_rc = WaitForSingleObject(handle, infinite);
    if (wait_rc != wait_object_0) return Error.Unexpected;

    var exit_code: DWORD = 0;
    if (GetExitCodeProcess(handle, &exit_code) == 0) {
        return switch (GetLastError()) {
            win_error_access_denied => Error.AccessDenied,
            win_error_invalid_handle => Error.NotFound,
            else => Error.Unexpected,
        };
    }

    return .{ .Exited = @intCast(exit_code & 0xFF) };
}

const FILETIME = extern struct {
    dw_low_date_time: DWORD,
    dw_high_date_time: DWORD,
};

const PROCESS_MEMORY_COUNTERS = extern struct {
    cb: DWORD,
    page_fault_count: DWORD,
    peak_working_set_size: usize,
    working_set_size: usize,
    quota_peak_paged_pool_usage: usize,
    quota_paged_pool_usage: usize,
    quota_peak_non_paged_pool_usage: usize,
    quota_non_paged_pool_usage: usize,
    pagefile_usage: usize,
    peak_pagefile_usage: usize,
};

fn filetimeToU64(ft: FILETIME) u64 {
    return (@as(u64, ft.dw_high_date_time) << 32) | ft.dw_low_date_time;
}

pub fn resourceUsage(pid: u32) !shared.ResourceUsage {
    const pid_dword = try validatePid(pid);
    const handle = OpenProcess(process_query_limited_information | process_vm_read, 0, pid_dword);
    if (handle == 0) {
        return switch (GetLastError()) {
            win_error_invalid_parameter => Error.NotFound,
            win_error_access_denied => Error.AccessDenied,
            else => Error.Unexpected,
        };
    }
    defer _ = CloseHandle(handle);

    var creation: FILETIME = undefined;
    var exit: FILETIME = undefined;
    var kernel: FILETIME = undefined;
    var user: FILETIME = undefined;
    if (GetProcessTimes(handle, &creation, &exit, &kernel, &user) == 0) {
        return switch (GetLastError()) {
            win_error_access_denied => Error.AccessDenied,
            win_error_invalid_handle => Error.NotFound,
            else => Error.Unexpected,
        };
    }

    const windows_to_unix_100ns: u64 = 116444736000000000;
    const creation_100ns = filetimeToU64(creation);
    const unix_100ns = if (creation_100ns > windows_to_unix_100ns) creation_100ns - windows_to_unix_100ns else 0;

    var mem_counters: PROCESS_MEMORY_COUNTERS = undefined;
    mem_counters.cb = @sizeOf(PROCESS_MEMORY_COUNTERS);
    const mem_ok = GetProcessMemoryInfo(handle, &mem_counters, mem_counters.cb) != 0;

    return .{
        .rss_bytes = if (mem_ok) @intCast(mem_counters.working_set_size) else null,
        .vms_bytes = if (mem_ok) @intCast(mem_counters.pagefile_usage) else null,
        .user_cpu_ns = filetimeToU64(user) * 100,
        .kernel_cpu_ns = filetimeToU64(kernel) * 100,
        .start_time_ns = unix_100ns * 100,
        .start_time_is_unix_epoch = true,
    };
}
