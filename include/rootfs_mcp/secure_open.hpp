#pragma once

#include <string>
#include <sys/types.h>

namespace rootfs_mcp {

// Probe (cached) whether the running kernel supports openat2(2).
bool openat2_supported();

// Open `rel` beneath the directory file descriptor `dirfd` without ever
// following a symbolic link in any path component, and without allowing the
// resolution to escape `dirfd`.
//
// When the kernel supports openat2() this uses
//   RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS
// so the guarantee is enforced by the kernel during resolution (no TOCTOU).
// Otherwise it falls back to a component-wise openat(O_PATH|O_NOFOLLOW)
// walk with fstat() verification of every intermediate component, plus a
// final /proc/self/fd cross-check against `expect_canonical` when it is
// non-empty. `expect_canonical` must be the canonical absolute path the
// caller authorized; a mismatch means a race swapped in a link and the
// open fails with ELOOP.
//
// `flags` apply to the final component (O_NOFOLLOW and O_CLOEXEC are added
// automatically). `rel` of "." duplicates `dirfd` itself.
// Returns an fd >= 0, or -1 with errno set (ELOOP on symlink/escape).
int open_beneath(int dirfd, const std::string& rel, int flags, mode_t mode = 0,
                 const std::string& expect_canonical = std::string());

// Read the canonical path of an open fd via /proc/self/fd. Returns "" on
// error.
std::string fd_canonical_path(int fd);

} // namespace rootfs_mcp
