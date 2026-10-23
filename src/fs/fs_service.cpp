#include "rootfs_mcp/fs_service.hpp"

#include "rootfs_mcp/secure_open.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace rootfs_mcp {

namespace {

struct fd_guard {
    int fd;
    explicit fd_guard(int f) : fd(f) {}
    ~fd_guard() { if (fd >= 0) close(fd); }
    fd_guard(const fd_guard&) = delete;
    fd_guard& operator=(const fd_guard&) = delete;
    int release() { int f = fd; fd = -1; return f; }
};

std::string errno_msg(const std::string& op, int err) {
    return op + ": " + std::strerror(err);
}

[[noreturn]] void throw_errno(const std::string& op) {
    throw std::runtime_error(errno_msg(op, errno));
}

std::string entry_type(mode_t m) {
    if (S_ISREG(m)) return "file";
    if (S_ISDIR(m)) return "directory";
    if (S_ISLNK(m)) return "symlink";
    if (S_ISFIFO(m)) return "fifo";
    if (S_ISSOCK(m)) return "socket";
    if (S_ISCHR(m)) return "char_device";
    if (S_ISBLK(m)) return "block_device";
    return "other";
}

std::string join_path(const std::string& dir, const std::string& name) {
    if (dir == "/") return "/" + name;
    return dir + "/" + name;
}

json stat_to_json(const struct stat& st) {
    json j;
    j["type"] = entry_type(st.st_mode);
    j["size"] = static_cast<uint64_t>(st.st_size);
    j["mode"] = static_cast<uint32_t>(st.st_mode & 07777);
    j["uid"] = static_cast<uint32_t>(st.st_uid);
    j["gid"] = static_cast<uint32_t>(st.st_gid);
    j["nlink"] = static_cast<uint64_t>(st.st_nlink);
    j["mtime"] = static_cast<int64_t>(st.st_mtim.tv_sec);
    j["mtime_iso"] = format_time_utc(st.st_mtim.tv_sec);
    j["atime"] = static_cast<int64_t>(st.st_atim.tv_sec);
    j["ctime"] = static_cast<int64_t>(st.st_ctim.tv_sec);
    j["is_symlink"] = S_ISLNK(st.st_mode) != 0;
    return j;
}

void write_full(int fd, const char* data, size_t len, uint64_t offset, bool use_offset,
                const std::string& op) {
    size_t done = 0;
    while (done < len) {
        ssize_t n = use_offset ? pwrite(fd, data + done, len - done,
                                        static_cast<off_t>(offset + done))
                               : ::write(fd, data + done, len - done);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) throw_errno(op);
        if (n == 0) throw std::runtime_error(op + ": short write");
        done += static_cast<size_t>(n);
    }
}

// Recursive delete beneath an open directory fd. Never follows symlinks:
// children are classified with fstatat(AT_SYMLINK_NOFOLLOW) and directories
// are re-opened with O_NOFOLLOW. Returns the number of entries removed.
uint64_t remove_tree_at(int dirfd, const std::string& name, unsigned depth,
                        uint64_t& errors) {
    if (depth > 128) {
        ++errors;
        return 0; // refuse unbounded recursion
    }
    struct stat st;
    if (fstatat(dirfd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
        ++errors;
        return 0;
    }
    if (!S_ISDIR(st.st_mode)) { // regular file, symlink, fifo, ... : unlink only
        if (unlinkat(dirfd, name.c_str(), 0) != 0) {
            ++errors;
            return 0;
        }
        return 1;
    }
    int fd = openat(dirfd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        ++errors;
        return 0;
    }
    uint64_t removed = 0;
    {
        // fdopendir takes ownership of a *duplicate* fd so `fd` stays usable
        // as dirfd for the child operations after the listing completes.
        int dupfd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
        if (dupfd < 0) {
            close(fd);
            ++errors;
            return 0;
        }
        DIR* d = fdopendir(dupfd);
        if (!d) {
            close(dupfd);
            close(fd);
            ++errors;
            return 0;
        }
        std::vector<std::string> children;
        while (dirent* e = readdir(d)) {
            if (std::strcmp(e->d_name, ".") == 0 || std::strcmp(e->d_name, "..") == 0) continue;
            children.emplace_back(e->d_name);
        }
        closedir(d); // closes dupfd only
        for (const auto& child : children)
            removed += remove_tree_at(fd, child, depth + 1, errors);
    }
    if (unlinkat(dirfd, name.c_str(), AT_REMOVEDIR) == 0)
        ++removed;
    else
        ++errors;
    close(fd);
    return removed;
}

} // namespace

json fs_service::list(const json& args, const std::string& /*session*/) {
    std::string path = arg_string(args, "path", true);
    uint64_t max_entries = arg_u64(args, "max_entries", 256);
    max_entries = std::min<uint64_t>(max_entries, 4096);
    bool include_hidden = arg_bool(args, "include_hidden", false);

    authorized_path ap = policy_.authorize_read(path);
    int fd = open_beneath(ap.rootfd, ap.rel, O_RDONLY | O_DIRECTORY | O_NONBLOCK,
                          0, ap.canonical);
    if (fd < 0) throw_errno("fs_list open " + path);
    DIR* d = fdopendir(fd);
    if (!d) {
        int saved = errno;
        close(fd);
        errno = saved;
        throw_errno("fs_list opendir " + path);
    }

    json entries = json::array();
    uint64_t total = 0;
    bool truncated = false;
    errno = 0;
    while (dirent* e = readdir(d)) {
        if (std::strcmp(e->d_name, ".") == 0 || std::strcmp(e->d_name, "..") == 0) continue;
        if (!include_hidden && e->d_name[0] == '.') continue;
        ++total;
        if (entries.size() >= max_entries) {
            truncated = true;
            continue; // keep counting
        }
        json item;
        item["name"] = e->d_name;
        struct stat st;
        if (fstatat(fd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
            item["type"] = entry_type(st.st_mode);
            item["size"] = static_cast<uint64_t>(st.st_size);
            item["mode"] = static_cast<uint32_t>(st.st_mode & 07777);
            item["mtime"] = static_cast<int64_t>(st.st_mtim.tv_sec);
            item["is_symlink"] = S_ISLNK(st.st_mode) != 0;
        } else {
            item["type"] = "unknown";
            item["stat_error"] = std::strerror(errno);
        }
        entries.push_back(std::move(item));
    }
    closedir(d);

    json result;
    result["path"] = ap.canonical;
    result["entries"] = std::move(entries);
    result["total_entries"] = total;
    result["truncated"] = truncated;
    return result;
}

json fs_service::read(const json& args, const std::string& /*session*/) {
    std::string path = arg_string(args, "path", true);
    uint64_t offset = arg_u64(args, "offset", 0);
    uint64_t length = arg_u64(args, "length", policy_.max_read_bytes());
    if (length == 0) length = policy_.max_read_bytes();
    length = std::min(length, policy_.max_read_bytes());

    authorized_path ap = policy_.authorize_read(path);
    // O_NONBLOCK guarantees a FIFO open returns immediately; after the fstat
    // check below only regular files (where O_NONBLOCK is a no-op) are read.
    int fd = open_beneath(ap.rootfd, ap.rel, O_RDONLY | O_NONBLOCK, 0, ap.canonical);
    if (fd < 0) throw_errno("fs_read open " + path);
    fd_guard g(fd);

    struct stat st;
    if (fstat(fd, &st) != 0) throw_errno("fs_read stat " + path);
    if (S_ISDIR(st.st_mode))
        throw std::runtime_error("fs_read: is a directory: " + ap.canonical);
    if (!S_ISREG(st.st_mode))
        throw std::runtime_error(
            "fs_read: refusing to read special file (fifo/device/socket): " + ap.canonical);

    std::string buf(length, '\0');
    size_t got = 0;
    while (got < length) {
        ssize_t n = pread(fd, &buf[got], length - got, static_cast<off_t>(offset + got));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) throw_errno("fs_read read " + path);
        if (n == 0) break;
        got += static_cast<size_t>(n);
    }
    buf.resize(got);

    // Pseudo-files (e.g. /proc) report size 0; for those "has_more" means
    // the read filled the requested window.
    bool has_more = st.st_size > 0
                        ? (offset + got < static_cast<uint64_t>(st.st_size))
                        : (got == length);

    json result;
    result["path"] = ap.canonical;
    result["offset"] = offset;
    result["length"] = static_cast<uint64_t>(got);
    result["size"] = static_cast<uint64_t>(st.st_size);
    result["has_more"] = has_more;
    if (looks_binary(reinterpret_cast<const uint8_t*>(buf.data()), buf.size())) {
        result["encoding"] = "base64";
        result["content"] = base64_encode(buf);
    } else {
        result["encoding"] = "utf-8";
        result["content"] = std::move(buf);
    }
    return result;
}

json fs_service::write(const json& args, const std::string& session) {
    std::string path = arg_string(args, "path", true);
    std::string content = arg_string(args, "content", true);
    std::string encoding = arg_string(args, "encoding", false, "utf-8");
    bool has_offset = args.is_object() && args.contains("offset") && !args["offset"].is_null();
    uint64_t offset = arg_u64(args, "offset", 0);
    bool has_mode = args.is_object() && args.contains("mode") && !args["mode"].is_null();
    uint64_t file_mode = arg_u64(args, "mode", 0644);

    std::string data;
    if (encoding == "base64") {
        try {
            data = base64_decode(content);
        } catch (const std::exception& e) {
            throw std::invalid_argument(std::string("invalid base64 content: ") + e.what());
        }
    } else if (encoding == "utf-8" || encoding == "text") {
        data = std::move(content);
    } else {
        throw std::invalid_argument("unsupported encoding: " + encoding);
    }
    if (data.size() > policy_.max_write_bytes())
        throw std::runtime_error("fs_write: content exceeds max_write_bytes (" +
                                 std::to_string(policy_.max_write_bytes()) + ")");

    try {
        authorized_path ap = policy_.authorize_write(path);
        int flags = O_WRONLY | O_CREAT | O_NONBLOCK;
        if (!has_offset) flags |= O_TRUNC;
        int fd = open_beneath(ap.rootfd, ap.rel, flags,
                              static_cast<mode_t>(file_mode & 07777), ap.canonical);
        if (fd < 0) throw_errno("fs_write open " + path);
        fd_guard g(fd);

        struct stat st;
        if (fstat(fd, &st) != 0) throw_errno("fs_write stat " + path);
        if (!S_ISREG(st.st_mode))
            throw std::runtime_error(
                "fs_write: refusing to write special file: " + ap.canonical);

        if (has_mode) {
            if (fchmod(fd, static_cast<mode_t>(file_mode & 07777)) != 0)
                throw_errno("fs_write chmod " + path);
        }
        write_full(fd, data.data(), data.size(), offset, has_offset, "fs_write " + path);

        struct stat st2;
        uint64_t new_size = 0;
        if (fstat(fd, &st2) == 0) new_size = static_cast<uint64_t>(st2.st_size);

        json result;
        result["path"] = ap.canonical;
        result["bytes_written"] = static_cast<uint64_t>(data.size());
        result["size"] = new_size;
        result["offset"] = has_offset ? offset : 0;
        audit_.record(session, "fs_write", ap.canonical, true,
                      "bytes=" + std::to_string(data.size()));
        return result;
    } catch (const std::exception& e) {
        audit_.record(session, "fs_write", path, false, e.what());
        throw;
    }
}

json fs_service::stat(const json& args, const std::string& /*session*/) {
    std::string path = arg_string(args, "path", true);
    // No-follow: fs_stat must report the symlink itself, not its target.
    authorized_path ap = policy_.authorize_read_nofollow(path);

    struct stat st;
    if (fstatat(ap.rootfd, ap.rel.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0)
        throw_errno("fs_stat " + path);

    json result = stat_to_json(st);
    result["path"] = ap.canonical;
    if (S_ISLNK(st.st_mode)) {
        char buf[4096];
        ssize_t n = readlinkat(ap.rootfd, ap.rel.c_str(), buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            result["symlink_target"] = buf;
        }
    }
    return result;
}

json fs_service::mkdir(const json& args, const std::string& session) {
    std::string path = arg_string(args, "path", true);
    uint64_t mode = arg_u64(args, "mode", 0755);
    bool recursive = arg_bool(args, "recursive", false);

    try {
        authorized_path ap = policy_.authorize_write(path);
        if (ap.rel == ".")
            throw std::runtime_error("fs_mkdir: path is the authorized root itself");

        std::vector<std::string> comps = split_path(ap.rel);
        if (comps.empty())
            throw std::runtime_error("fs_mkdir: empty relative path");

        if (!recursive) {
            if (mkdirat(ap.rootfd, ap.rel.c_str(), static_cast<mode_t>(mode & 07777)) != 0) {
                if (errno == EEXIST)
                    throw std::runtime_error("fs_mkdir: already exists: " + ap.canonical);
                throw_errno("fs_mkdir " + path);
            }
        } else {
            int cur = fcntl(ap.rootfd, F_DUPFD_CLOEXEC, 0);
            if (cur < 0) throw_errno("fs_mkdir dup");
            fd_guard g(cur);
            std::string rel_so_far;
            for (size_t i = 0; i < comps.size(); ++i) {
                if (mkdirat(cur, comps[i].c_str(), static_cast<mode_t>(mode & 07777)) != 0 &&
                    errno != EEXIST) {
                    throw_errno("fs_mkdir " + path + " (component " + comps[i] + ")");
                }
                int next = openat(cur, comps[i].c_str(),
                                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                if (next < 0) throw_errno("fs_mkdir descend " + comps[i]);
                close(cur);
                cur = next;
                g.fd = cur;
            }
        }
        json result;
        result["path"] = ap.canonical;
        result["created"] = true;
        audit_.record(session, "fs_mkdir", ap.canonical, true, "");
        return result;
    } catch (const std::exception& e) {
        audit_.record(session, "fs_mkdir", path, false, e.what());
        throw;
    }
}

json fs_service::remove(const json& args, const std::string& session) {
    std::string path = arg_string(args, "path", true);
    bool recursive = arg_bool(args, "recursive", false);

    try {
        if (!policy_.enable_delete())
            throw policy_error("fs_remove is disabled (enable_delete=false)");
        authorized_path ap = policy_.authorize_write_nofollow(path);
        policy_.check_deletable(ap);

        struct stat st;
        if (fstatat(ap.rootfd, ap.rel.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0)
            throw_errno("fs_remove stat " + path);

        uint64_t removed = 0;
        uint64_t errors = 0;
        if (S_ISDIR(st.st_mode)) {
            if (!recursive) {
                // Non-recursive: only empty directories may be removed.
                if (unlinkat(ap.rootfd, ap.rel.c_str(), AT_REMOVEDIR) != 0) {
                    if (errno == ENOTEMPTY || errno == EEXIST)
                        throw std::runtime_error(
                            "fs_remove: directory not empty (use recursive=true): " +
                            ap.canonical);
                    throw_errno("fs_remove " + path);
                }
                removed = 1;
            } else {
                removed = remove_tree_at(ap.rootfd, ap.rel, 0, errors);
            }
        } else {
            if (unlinkat(ap.rootfd, ap.rel.c_str(), 0) != 0)
                throw_errno("fs_remove " + path);
            removed = 1;
        }

        json result;
        result["path"] = ap.canonical;
        result["removed"] = errors == 0;
        result["entries_removed"] = removed;
        result["errors"] = errors;
        audit_.record(session, "fs_remove", ap.canonical, errors == 0,
                      "entries=" + std::to_string(removed));
        return result;
    } catch (const std::exception& e) {
        audit_.record(session, "fs_remove", path, false, e.what());
        throw;
    }
}

json fs_service::move(const json& args, const std::string& session) {
    std::string src = arg_string(args, "src", true);
    std::string dst = arg_string(args, "dst", true);

    try {
        authorized_path asrc = policy_.authorize_write_nofollow(src);
        authorized_path adst = policy_.authorize_write_nofollow(dst);
        policy_.check_movable(asrc, adst);

        struct stat st;
        if (fstatat(asrc.rootfd, asrc.rel.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0)
            throw_errno("fs_move stat " + src);

        if (renameat(asrc.rootfd, asrc.rel.c_str(), adst.rootfd, adst.rel.c_str()) != 0) {
            if (errno == EXDEV)
                throw std::runtime_error(
                    "fs_move: cross-device moves are not supported (EXDEV)");
            throw_errno("fs_move " + src + " -> " + dst);
        }
        json result;
        result["src"] = asrc.canonical;
        result["dst"] = adst.canonical;
        result["moved"] = true;
        audit_.record(session, "fs_move", asrc.canonical + " -> " + adst.canonical, true, "");
        return result;
    } catch (const std::exception& e) {
        audit_.record(session, "fs_move", src + " -> " + dst, false, e.what());
        throw;
    }
}

json fs_service::search(const json& args, const std::string& /*session*/) {
    std::string path = arg_string(args, "path", true);
    std::string pattern = arg_string(args, "pattern", true);
    std::string mode = arg_string(args, "mode", false, "name");
    if (mode != "name" && mode != "content")
        throw std::invalid_argument("mode must be 'name' or 'content'");
    uint64_t max_results = std::min<uint64_t>(arg_u64(args, "max_results", 64), 1024);
    uint64_t max_depth = std::min<uint64_t>(arg_u64(args, "max_depth", 8), 64);
    uint64_t budget_ms = std::min<uint64_t>(arg_u64(args, "time_budget_ms", 10000), 60000);

    authorized_path ap = policy_.authorize_read(path);
    int root = open_beneath(ap.rootfd, ap.rel, O_RDONLY | O_DIRECTORY | O_NONBLOCK,
                            0, ap.canonical);
    if (root < 0) throw_errno("fs_search open " + path);

    const bool glob_match = pattern.find_first_of("*?[") != std::string::npos;
    auto name_matches = [&](const std::string& name) {
        if (glob_match) return fnmatch(pattern.c_str(), name.c_str(), 0) == 0;
        return name.find(pattern) != std::string::npos;
    };

    json results = json::array();
    uint64_t errors = 0, scanned_dirs = 0, scanned_files = 0;
    bool hit_limit = false, timed_out = false;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(budget_ms);

    struct frame {
        int fd;
        std::string path;
        uint64_t depth;
    };
    std::vector<frame> stack;
    stack.push_back({root, ap.canonical, 0});

    while (!stack.empty() && !timed_out) {
        if (std::chrono::steady_clock::now() > deadline) {
            timed_out = true;
            break;
        }
        frame fr = stack.back();
        stack.pop_back();
        ++scanned_dirs;

        int dupfd = fcntl(fr.fd, F_DUPFD_CLOEXEC, 0);
        if (dupfd < 0) {
            close(fr.fd);
            ++errors;
            continue;
        }
        DIR* d = fdopendir(dupfd);
        if (!d) {
            close(dupfd);
            close(fr.fd);
            ++errors;
            continue;
        }
        std::vector<std::string> children;
        while (dirent* e = readdir(d)) {
            if (std::strcmp(e->d_name, ".") == 0 || std::strcmp(e->d_name, "..") == 0) continue;
            children.emplace_back(e->d_name);
        }
        closedir(d);

        for (const auto& child : children) {
            if (results.size() >= max_results) {
                hit_limit = true;
                break;
            }
            if (std::chrono::steady_clock::now() > deadline) {
                timed_out = true;
                break;
            }
            std::string child_path = join_path(fr.path, child);
            struct stat st;
            if (fstatat(fr.fd, child.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
                ++errors;
                continue;
            }
            if (S_ISDIR(st.st_mode)) {
                if (mode == "name" && name_matches(child))
                    results.push_back({{"path", child_path}, {"type", "directory"}});
                if (fr.depth < max_depth) {
                    // Symlinks were resolved at authorization time; traversal
                    // itself never follows them (lstat classification +
                    // O_NOFOLLOW open).
                    int cfd = openat(fr.fd, child.c_str(),
                                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                    if (cfd >= 0)
                        stack.push_back({cfd, child_path, fr.depth + 1});
                    else
                        ++errors;
                }
            } else if (S_ISREG(st.st_mode)) {
                ++scanned_files;
                if (mode == "name") {
                    if (name_matches(child))
                        results.push_back({{"path", child_path}, {"type", "file"}});
                } else {
                    // Content search: skip huge and binary files.
                    if (st.st_size > (32 << 20)) continue;
                    int cfd = openat(fr.fd, child.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
                    if (cfd < 0) {
                        ++errors;
                        continue;
                    }
                    fd_guard g(cfd);
                    std::string data;
                    data.resize(static_cast<size_t>(st.st_size));
                    size_t got = 0;
                    while (got < data.size()) {
                        ssize_t n = ::read(cfd, &data[got], data.size() - got);
                        if (n < 0 && errno == EINTR) continue;
                        if (n <= 0) break;
                        got += static_cast<size_t>(n);
                    }
                    data.resize(got);
                    if (looks_binary(reinterpret_cast<const uint8_t*>(data.data()), got))
                        continue;
                    uint64_t line_no = 0;
                    size_t pos = 0;
                    uint64_t per_file = 0;
                    while (pos <= data.size() && per_file < 5) {
                        size_t nl = data.find('\n', pos);
                        if (nl == std::string::npos) nl = data.size();
                        ++line_no;
                        std::string line = data.substr(pos, nl - pos);
                        if (line.find(pattern) != std::string::npos) {
                            if (line.size() > 200) line.resize(200);
                            results.push_back({{"path", child_path},
                                               {"type", "file"},
                                               {"line", line_no},
                                               {"preview", line}});
                            ++per_file;
                            if (results.size() >= max_results) break;
                        }
                        if (nl == data.size()) break;
                        pos = nl + 1;
                    }
                }
            }
            // Symlinks and special files are neither descended into nor read.
        }
        close(fr.fd);
    }

    json result;
    result["path"] = ap.canonical;
    result["pattern"] = pattern;
    result["mode"] = mode;
    result["results"] = std::move(results);
    result["count"] = result["results"].size();
    result["truncated"] = hit_limit;
    result["timed_out"] = timed_out;
    result["errors"] = errors;
    result["scanned_dirs"] = scanned_dirs;
    result["scanned_files"] = scanned_files;
    return result;
}

} // namespace rootfs_mcp
