#include "rootfs_mcp/exec_service.hpp"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <set>
#include <signal.h>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace rootfs_mcp {

namespace {

struct fd_guard {
    int fd;
    explicit fd_guard(int f = -1) : fd(f) {}
    ~fd_guard() { if (fd >= 0) close(fd); }
    fd_guard(const fd_guard&) = delete;
    fd_guard& operator=(const fd_guard&) = delete;
    void reset(int f = -1) {
        if (fd >= 0) close(fd);
        fd = f;
    }
};

uint64_t ms_since(std::chrono::steady_clock::time_point start) {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start)
            .count());
}

void set_nonblocking(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

} // namespace

std::vector<std::string> build_child_env(const std::map<std::string, std::string>& user_env) {
    // Only these variables may ever reach a child process.
    static const std::set<std::string> kWhitelist = {
        "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES",
        "TERM", "TMPDIR", "TZ"};
    std::map<std::string, std::string> env;
    const char* home = std::getenv("HOME");
    env["PATH"] = "/usr/local/bin:/usr/bin:/bin";
    env["HOME"] = home ? home : "/";
    env["LANG"] = "C.UTF-8";
    for (const auto& kv : user_env)
        if (kWhitelist.count(kv.first)) env[kv.first] = kv.second;
    std::vector<std::string> out;
    out.reserve(env.size());
    for (const auto& kv : env) out.push_back(kv.first + "=" + kv.second);
    return out;
}

exec_service::exec_service(const security_policy& policy, audit_log& audit)
    : policy_(policy), audit_(audit) {
    if (sem_init(&exec_slots_, 0, policy_.max_concurrent_exec()) != 0)
        throw std::runtime_error("sem_init failed");
}

exec_service::~exec_service() { sem_destroy(&exec_slots_); }

exec_result exec_service::run(const exec_options& opts, const std::string& session,
                              bool skip_exec_list) {
    auto start = std::chrono::steady_clock::now();
    exec_result res;
    std::string audit_target;
    for (size_t i = 0; i < opts.argv.size(); ++i) {
        if (i) audit_target += ' ';
        audit_target += opts.argv[i];
    }
    if (audit_target.size() > 512) audit_target.resize(512); // bound log record size
    try {
        if (opts.argv.empty())
            throw std::invalid_argument("argv must be a non-empty array");
        for (const auto& a : opts.argv)
            if (a.empty() || a.find('\0') != std::string::npos)
                throw std::invalid_argument("argv entries must be non-empty strings");

        std::string exe = skip_exec_list
                              ? security_policy::canonicalize_existing(opts.argv[0])
                              : policy_.authorize_exec(opts.argv[0]);

        authorized_path cwd_ap; // holds the rootfd open while we validate
        if (!opts.cwd.empty()) {
            cwd_ap = policy_.authorize_read(opts.cwd);
            struct stat st;
            if (fstatat(cwd_ap.rootfd, cwd_ap.rel.c_str(), &st, 0) != 0 || !S_ISDIR(st.st_mode))
                throw std::runtime_error("cwd is not a directory: " + opts.cwd);
        }

        uint64_t timeout_ms = opts.timeout_ms
                                  ? std::min(opts.timeout_ms, policy_.exec_timeout_ms())
                                  : policy_.exec_timeout_ms();
        uint64_t cap = opts.max_output_bytes
                           ? std::min(opts.max_output_bytes, policy_.max_output_bytes())
                           : policy_.max_output_bytes();

        // Concurrency gate: fail fast instead of queueing protocol threads.
        if (sem_trywait(&exec_slots_) != 0)
            throw std::runtime_error("too many concurrent executions");
        struct slot_guard {
            sem_t* s;
            ~slot_guard() { sem_post(s); }
        } slot{&exec_slots_};

        int out_pipe[2] = {-1, -1}, err_pipe[2] = {-1, -1}, serr_pipe[2] = {-1, -1};
        if (pipe2(out_pipe, O_CLOEXEC) != 0 || pipe2(err_pipe, O_CLOEXEC) != 0 ||
            pipe2(serr_pipe, O_CLOEXEC) != 0)
            throw std::runtime_error("pipe2 failed");

        pid_t pid = fork();
        if (pid < 0) {
            close(out_pipe[0]); close(out_pipe[1]);
            close(err_pipe[0]); close(err_pipe[1]);
            close(serr_pipe[0]); close(serr_pipe[1]);
            throw std::runtime_error(std::string("fork failed: ") + std::strerror(errno));
        }

        if (pid == 0) {
            // ---- child ----
            setsid(); // own session/process group so the whole tree can be killed
            dup2(out_pipe[1], STDOUT_FILENO);
            dup2(err_pipe[1], STDERR_FILENO);
            close(out_pipe[0]); close(out_pipe[1]);
            close(err_pipe[0]); close(err_pipe[1]);
            close(serr_pipe[0]);
            // serr_pipe[1] stays open with O_CLOEXEC: EOF in the parent means
            // execve succeeded; anything written means a pre-exec failure.
            if (!opts.cwd.empty() && chdir(opts.cwd.c_str()) != 0) {
                dprintf(serr_pipe[1], "chdir %s: %s", opts.cwd.c_str(), strerror(errno));
                _exit(127);
            }
            std::vector<std::string> env = build_child_env(opts.env);
            std::vector<char*> argv_p, envp_p;
            for (const auto& a : opts.argv) argv_p.push_back(const_cast<char*>(a.c_str()));
            argv_p.push_back(nullptr);
            for (const auto& e : env) envp_p.push_back(const_cast<char*>(e.c_str()));
            envp_p.push_back(nullptr);
            execve(exe.c_str(), argv_p.data(), envp_p.data());
            int saved = errno;
            dprintf(serr_pipe[1], "execve %s: %s", exe.c_str(), strerror(saved));
            _exit(127);
        }

        // ---- parent ----
        close(out_pipe[1]);
        close(err_pipe[1]);
        close(serr_pipe[1]);
        fd_guard out_fd(out_pipe[0]), err_fd(err_pipe[0]), serr_fd(serr_pipe[0]);
        set_nonblocking(out_fd.fd);
        set_nonblocking(err_fd.fd);
        set_nonblocking(serr_fd.fd);

        std::string serr;
        bool out_eof = false, err_eof = false, serr_eof = false;
        bool reaped = false;
        int status = 0;
        bool term_sent = false, kill_sent = false, grace_set = false;
        std::chrono::steady_clock::time_point term_deadline, grace_deadline, final_deadline;
        const auto deadline = start + std::chrono::milliseconds(timeout_ms);

        auto append_capped = [&](std::string& dst, const char* buf, size_t n) {
            size_t stored = res.stdout_text.size() + res.stderr_text.size();
            if (stored + n > cap) {
                n = cap > stored ? cap - stored : 0;
                res.truncated = true;
            }
            if (n) dst.append(buf, n);
        };

        char buf[16384];
        while (true) {
            if (!reaped) {
                pid_t r = waitpid(pid, &status, WNOHANG);
                if (r == pid) reaped = true;
            }

            if (serr_eof && !serr.empty()) {
                // Pre-exec failure reported by the child; it already exited.
                if (!reaped) waitpid(pid, &status, 0);
                res.spawn_ok = false;
                res.spawn_error = serr;
                break;
            }

            bool io_done = out_eof && err_eof && serr_eof;
            if (reaped && io_done) break;

            auto now = std::chrono::steady_clock::now();

            if (now >= deadline) {
                // Wall-clock timeout: escalate TERM -> KILL to the whole
                // process group (the child called setsid, so -pid covers
                // grandchildren too).
                res.timed_out = true;
                if (!term_sent) {
                    kill(-pid, SIGTERM);
                    term_sent = true;
                    term_deadline = now + std::chrono::seconds(1);
                } else if (!kill_sent && now >= term_deadline) {
                    kill(-pid, SIGKILL);
                    kill_sent = true;
                    final_deadline = now + std::chrono::seconds(2);
                } else if (kill_sent && now >= final_deadline) {
                    break; // belt and braces: never wait forever
                }
            } else if (reaped && !io_done && !term_sent) {
                // Direct child is gone but descendants still hold the pipes:
                // give them a short grace, then kill the group so we never
                // block on inherited pipe ends.
                if (!grace_set) {
                    grace_set = true;
                    grace_deadline = now + std::chrono::milliseconds(300);
                } else if (now >= grace_deadline) {
                    kill(-pid, SIGKILL);
                    kill_sent = true;
                    final_deadline = now + std::chrono::seconds(1);
                }
            }
            if (kill_sent && reaped && now >= final_deadline) break;

            struct pollfd pfds[3];
            nfds_t n = 0;
            if (!out_eof) { pfds[n] = {out_fd.fd, POLLIN, 0}; ++n; }
            if (!err_eof) { pfds[n] = {err_fd.fd, POLLIN, 0}; ++n; }
            if (!serr_eof) { pfds[n] = {serr_fd.fd, POLLIN, 0}; ++n; }
            if (n == 0) {
                if (!reaped) { waitpid(pid, &status, 0); reaped = true; }
                continue;
            }
            int pr = poll(pfds, n, 50);
            if (pr < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (pr == 0) continue;
            for (nfds_t i = 0; i < n; ++i) {
                if (!(pfds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
                ssize_t rn = read(pfds[i].fd, buf, sizeof(buf));
                if (rn > 0) {
                    if (pfds[i].fd == out_fd.fd) append_capped(res.stdout_text, buf, rn);
                    else if (pfds[i].fd == err_fd.fd) append_capped(res.stderr_text, buf, rn);
                    else serr.append(buf, static_cast<size_t>(rn));
                } else if (rn == 0 ||
                           (rn < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
                    if (pfds[i].fd == out_fd.fd) { out_eof = true; out_fd.reset(); }
                    else if (pfds[i].fd == err_fd.fd) { err_eof = true; err_fd.reset(); }
                    else { serr_eof = true; serr_fd.reset(); }
                }
            }
        }

        if (!reaped) {
            // Loop exited via a forced break: make sure the direct child is
            // dead and reaped so no zombie is left behind.
            kill(-pid, SIGKILL);
            waitpid(pid, &status, 0);
            reaped = true;
        }
        if (WIFEXITED(status)) {
            res.exit_code = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            res.term_signal = WTERMSIG(status);
            res.exit_code = 128 + res.term_signal;
        }
        // Spawn failure reported through the error pipe takes precedence.
        if (res.spawn_ok && !serr.empty()) {
            res.spawn_ok = false;
            res.spawn_error = serr;
        }

        res.duration_ms = ms_since(start);
        audit_.record(session, skip_exec_list ? "shell_script_exec" : "shell_exec",
                      audit_target, !res.timed_out && res.spawn_ok,
                      "exit=" + std::to_string(res.exit_code) +
                          (res.timed_out ? " timed_out" : ""));
        return res;
    } catch (const std::exception& e) {
        audit_.record(session, skip_exec_list ? "shell_script_exec" : "shell_exec",
                      audit_target, false, e.what());
        throw;
    }
}

} // namespace rootfs_mcp
