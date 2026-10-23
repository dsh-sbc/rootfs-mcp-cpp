#include "rootfs_mcp/secure_open.hpp"
#include "rootfs_mcp/util.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__has_include)
#if __has_include(<linux/openat2.h>)
#include <linux/openat2.h>
#define ROOTFS_MCP_HAVE_OPENAT2_HDR 1
#endif
#endif

#ifndef ROOTFS_MCP_HAVE_OPENAT2_HDR
// Fallback definitions for older libc/kernel headers.
struct open_how {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};
#ifndef RESOLVE_NO_SYMLINKS
#define RESOLVE_NO_SYMLINKS 0x04
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_BENEATH 0x08
#endif
#endif

#ifndef __NR_openat2
#if defined(__x86_64__)
#define __NR_openat2 437
#elif defined(__riscv)
#define __NR_openat2 437
#else
#define __NR_openat2 -1
#endif
#endif

namespace rootfs_mcp {

namespace {

int probe_openat2() {
    if (__NR_openat2 < 0) return 0;
    struct open_how how;
    std::memset(&how, 0, sizeof(how));
    how.flags = O_PATH | O_CLOEXEC;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
    // Opening "." beneath AT_FDCWD always succeeds when the syscall exists.
    int fd = static_cast<int>(syscall(__NR_openat2, AT_FDCWD, ".", &how, sizeof(how)));
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0; // ENOSYS / EINVAL / EPERM (seccomp) -> use fallback
}

int openat2_beneath(int dirfd, const char* rel, uint64_t flags, uint64_t mode) {
    struct open_how how;
    std::memset(&how, 0, sizeof(how));
    how.flags = flags | O_NOFOLLOW | O_CLOEXEC;
    how.mode = mode;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
    return static_cast<int>(syscall(__NR_openat2, dirfd, rel, &how, sizeof(how)));
}

// Fallback: component-wise openat(O_PATH|O_NOFOLLOW) walk. Every
// intermediate component is fstat-verified to be a real directory (not a
// symlink), the final component gets the caller's flags plus O_NOFOLLOW.
int walk_beneath(int dirfd, const std::string& rel, int flags, mode_t mode) {
    std::vector<std::string> comps = split_path(rel);
    if (comps.empty() || (comps.size() == 1 && comps[0] == ".")) {
        return openat(dirfd, ".", (flags & ~(O_CREAT | O_TRUNC)) | O_NOFOLLOW | O_CLOEXEC, mode);
    }
    int cur = fcntl(dirfd, F_DUPFD_CLOEXEC, 0);
    if (cur < 0) return -1;
    for (size_t i = 0; i < comps.size(); ++i) {
        const std::string& comp = comps[i];
        if (comp == "..") { // an escaped ".." must never reach here
            close(cur);
            errno = ELOOP;
            return -1;
        }
        bool last = (i + 1 == comps.size());
        int next;
        if (last) {
            next = openat(cur, comp.c_str(), flags | O_NOFOLLOW | O_CLOEXEC, mode);
        } else {
            next = openat(cur, comp.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC);
            if (next >= 0) {
                // O_PATH|O_NOFOLLOW opens a symlink itself instead of
                // failing; reject anything that is not a real directory.
                struct stat st;
                bool ok = (fstat(next, &st) == 0) && S_ISDIR(st.st_mode);
                if (!ok) {
                    close(next);
                    close(cur);
                    errno = ELOOP;
                    return -1;
                }
            }
        }
        close(cur);
        if (next < 0) return -1;
        cur = next;
    }
    return cur;
}

} // namespace

bool openat2_supported() {
    static const bool supported = (probe_openat2() == 1);
    return supported;
}

std::string fd_canonical_path(int fd) {
    char link[64];
    std::snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    char buf[4096];
    ssize_t n = readlink(link, buf, sizeof(buf) - 1);
    if (n <= 0) return "";
    buf[n] = '\0';
    // Deleted files get a " (deleted)" suffix; treat as mismatch for auth.
    std::string p(buf);
    const std::string suffix = " (deleted)";
    if (p.size() > suffix.size() && p.compare(p.size() - suffix.size(), suffix.size(), suffix) == 0)
        p.erase(p.size() - suffix.size());
    return p;
}

int open_beneath(int dirfd, const std::string& rel, int flags, mode_t mode,
                 const std::string& expect_canonical) {
    if (dirfd < 0) {
        errno = EBADF;
        return -1;
    }
    int fd;
    if (openat2_supported()) {
        fd = openat2_beneath(dirfd, rel.c_str(), static_cast<uint64_t>(flags),
                             static_cast<uint64_t>(mode));
    } else {
        fd = walk_beneath(dirfd, rel, flags, mode);
    }
    if (fd < 0) return -1;

    if (!expect_canonical.empty()) {
        std::string actual = fd_canonical_path(fd);
        if (actual != expect_canonical) {
            close(fd);
            errno = ELOOP; // race: path changed between authorize and open
            return -1;
        }
    }
    return fd;
}

} // namespace rootfs_mcp
