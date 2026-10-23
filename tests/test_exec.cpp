// Command execution tests: capture, exit codes, timeout + process-group
// kill, truncation, spawn failure, authorization, concurrency, env filter.
#include <gtest/gtest.h>

#include <chrono>
#include <dirent.h>
#include <fstream>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include "rootfs_mcp/audit_log.hpp"
#include "rootfs_mcp/exec_service.hpp"
#include "rootfs_mcp/security_policy.hpp"

using rootfs_mcp::exec_options;
using rootfs_mcp::exec_result;
using rootfs_mcp::json;
using rootfs_mcp::security_policy;

namespace {

rootfs_mcp::exec_options opts_of(std::vector<std::string> argv) {
    rootfs_mcp::exec_options o;
    o.argv = std::move(argv);
    return o;
}

std::string make_tmpdir() {
    char tmpl[] = "/tmp/rootfs-mcp-exec-XXXXXX";
    EXPECT_TRUE(mkdtemp(tmpl) != nullptr);
    return tmpl;
}

// Scan /proc for any process whose cmdline contains `needle`.
bool process_with_cmdline(const std::string& needle) {
    DIR* d = opendir("/proc");
    if (!d) return false;
    bool found = false;
    while (dirent* e = readdir(d)) {
        if (!isdigit(e->d_name[0])) continue;
        std::ifstream in(std::string("/proc/") + e->d_name + "/cmdline",
                         std::ios::binary);
        std::string cmd((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
        if (cmd.find(needle) != std::string::npos) {
            found = true;
            break;
        }
    }
    closedir(d);
    return found;
}

class ExecTest : public ::testing::Test {
protected:
    static std::string dir;
    static std::unique_ptr<security_policy> policy;
    static std::unique_ptr<rootfs_mcp::audit_log> audit;
    static std::unique_ptr<rootfs_mcp::exec_service> exec;

    static void SetUpTestSuite() {
        dir = make_tmpdir();
        json conf = {
            {"mode", "controlled"},
            {"allow_read", json::array({dir, "/tmp"})},
            {"allow_write", json::array({dir})},
            {"allow_exec",
             json::array({"/bin/echo", "/bin/sh", "/bin/sleep", "/bin/false",
                          "/bin/cat", "/bin/pwd", "/usr/bin/env"})},
            {"exec_timeout_ms", 10000},
            {"max_output_bytes", 65536},
            {"max_concurrent_exec", 4},
            {"audit", false},
        };
        policy = std::make_unique<security_policy>(security_policy::from_json(conf));
        audit = std::make_unique<rootfs_mcp::audit_log>(false, "");
        exec = std::make_unique<rootfs_mcp::exec_service>(*policy, *audit);

        // 200 KB file for truncation tests.
        std::ofstream big(dir + "/big.txt");
        big << std::string(200000, 'A');
    }
};

std::string ExecTest::dir;
std::unique_ptr<security_policy> ExecTest::policy;
std::unique_ptr<rootfs_mcp::audit_log> ExecTest::audit;
std::unique_ptr<rootfs_mcp::exec_service> ExecTest::exec;

TEST_F(ExecTest, EchoCapturesStdout) {
    exec_result r = exec->run(opts_of({"/bin/echo", "hello", "world"}), "s");
    EXPECT_TRUE(r.spawn_ok);
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.stdout_text, "hello world\n");
    EXPECT_FALSE(r.timed_out);
    EXPECT_FALSE(r.truncated);
    EXPECT_LE(r.duration_ms, 5000u);
}

TEST_F(ExecTest, NonZeroExitIsNotSuccess) {
    exec_result r = exec->run(opts_of({"/bin/false"}), "s");
    EXPECT_TRUE(r.spawn_ok);      // the program started fine
    EXPECT_EQ(r.exit_code, 1);    // ... and really exited 1
    EXPECT_FALSE(r.timed_out);
}

TEST_F(ExecTest, StderrAndExitCodeCaptured) {
    exec_result r = exec->run(
        opts_of({"/bin/sh", "-c", "echo out; echo err >&2; exit 3"}), "s");
    EXPECT_TRUE(r.spawn_ok);
    EXPECT_EQ(r.exit_code, 3);
    EXPECT_EQ(r.stdout_text, "out\n");
    EXPECT_EQ(r.stderr_text, "err\n");
}

TEST_F(ExecTest, TimeoutKillsWholeProcessGroup) {
    // Uniquely-named symlink to /bin/sleep: its appearance in /proc cmdlines
    // is an unambiguous marker for surviving group members.
    const std::string marker = dir + "/sleep-marker-987654";
    ASSERT_EQ(symlink("/bin/sleep", marker.c_str()), 0);
    ASSERT_FALSE(process_with_cmdline(marker));
    exec_options o;
    o.argv = {"/bin/sh", "-c",
              marker + " 60 & " + marker + " 60 & /bin/sleep 60"};
    o.timeout_ms = 500;
    exec_result r = exec->run(o, "s");
    EXPECT_TRUE(r.spawn_ok);
    EXPECT_TRUE(r.timed_out);
    // Give init a moment to reap, then verify no group member survived.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT_FALSE(process_with_cmdline(marker));
}

TEST_F(ExecTest, OutputTruncatedAtCap) {
    exec_options o;
    o.argv = {"/bin/cat", dir + "/big.txt"};
    o.max_output_bytes = 4096;
    exec_result r = exec->run(o, "s");
    EXPECT_TRUE(r.spawn_ok);
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_TRUE(r.truncated);
    EXPECT_EQ(r.stdout_text.size(), 4096u);
}

TEST_F(ExecTest, NonexistentProgramIsDistinctError) {
    // admin mode with empty allow_exec: any resolvable executable, but this
    // path does not exist at all -> a distinct error, not an exit code.
    json conf = {{"mode", "admin"},
                 {"allow_read", json::array({"/tmp"})},
                 {"allow_exec", json::array()},
                 {"audit", false}};
    security_policy admin = security_policy::from_json(conf);
    rootfs_mcp::exec_service admin_exec(admin, *audit);
    try {
        admin_exec.run(opts_of({"/nonexistent/rootfs-mcp-xyz"}), "s");
        FAIL() << "expected policy_error";
    } catch (const rootfs_mcp::policy_error& e) {
        EXPECT_NE(std::string(e.what()).find("No such file"), std::string::npos);
    }
}

TEST_F(ExecTest, ExecveFailureReportedViaErrorPipe) {
    // Executable file whose interpreter is missing: passes the authorization
    // and access(X_OK) checks, then execve fails with ENOENT. The child
    // reports this through the pre-exec error pipe as a *spawn failure*,
    // distinct from a command that ran and exited non-zero.
    std::string p = dir + "/bad-interp.sh";
    { std::ofstream f(p); f << "#!/nonexistent/interp-xyz\necho hi\n"; }
    chmod(p.c_str(), 0755);
    json conf = {{"mode", "admin"},
                 {"allow_read", json::array({"/tmp"})},
                 {"allow_exec", json::array()},
                 {"audit", false}};
    security_policy admin = security_policy::from_json(conf);
    rootfs_mcp::exec_service admin_exec(admin, *audit);
    exec_result r = admin_exec.run(opts_of({p}), "s");
    EXPECT_FALSE(r.spawn_ok);
    EXPECT_NE(r.spawn_error.find("No such file"), std::string::npos);
    EXPECT_FALSE(r.timed_out);
}

TEST_F(ExecTest, UnauthorizedProgramRejected) {
    // /bin/rm is not in allow_exec for this controlled-mode policy.
    EXPECT_THROW(exec->run(opts_of({"/bin/rm", "-f", dir + "/big.txt"}), "s"),
                 rootfs_mcp::policy_error);
    // And the file must still be there.
    std::ifstream check(dir + "/big.txt");
    EXPECT_TRUE(check.good());
}

TEST_F(ExecTest, ReadonlyModeRejectsExec) {
    json conf = {{"mode", "readonly"},
                 {"allow_read", json::array({"/tmp"})},
                 {"allow_exec", json::array({"/bin/echo"})},
                 {"audit", false}};
    security_policy ro = security_policy::from_json(conf);
    rootfs_mcp::exec_service ro_exec(ro, *audit);
    EXPECT_THROW(ro_exec.run(opts_of({"/bin/echo", "x"}), "s"), rootfs_mcp::policy_error);
}

TEST_F(ExecTest, EnvIsWhitelistFiltered) {
    exec_options o;
    o.argv = {"/usr/bin/env"};
    o.env = {{"ROOTFS_MCP_SECRET", "should-not-appear"}, {"LANG", "C"}};
    exec_result r = exec->run(o, "s");
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.stdout_text.find("ROOTFS_MCP_SECRET"), std::string::npos);
    EXPECT_NE(r.stdout_text.find("LANG=C\n"), std::string::npos);
    EXPECT_NE(r.stdout_text.find("PATH="), std::string::npos); // minimal default present
}

TEST_F(ExecTest, CwdHonoredAndAuthorized) {
    exec_options o;
    o.argv = {"/bin/pwd"};
    o.cwd = dir;
    exec_result r = exec->run(o, "s");
    EXPECT_EQ(r.stdout_text, security_policy::canonicalize_existing(dir) + "\n");

    o.cwd = "/etc"; // outside allow_read for this policy
    EXPECT_THROW(exec->run(o, "s"), rootfs_mcp::policy_error);
}

TEST_F(ExecTest, GrandchildrenHoldingPipesDoNotBlockForever) {
    // Child exits immediately but a grandchild inherits stdout and keeps it
    // open; run() must return promptly (kill the group), not wait forever.
    exec_options o;
    o.argv = {"/bin/sh", "-c", "/bin/sleep 30 >&1 & echo done"};
    o.timeout_ms = 10000;
    auto start = std::chrono::steady_clock::now();
    exec_result r = exec->run(o, "s");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - start)
                  .count();
    EXPECT_TRUE(r.spawn_ok);
    EXPECT_EQ(r.stdout_text, "done\n");
    EXPECT_LT(ms, 5000); // well under the 10s timeout
}

TEST_F(ExecTest, ConcurrencyGate) {
    json conf = {{"mode", "controlled"},
                 {"allow_read", json::array({"/tmp"})},
                 {"allow_exec", json::array({"/bin/sleep", "/bin/echo"})},
                 {"max_concurrent_exec", 1},
                 {"exec_timeout_ms", 5000},
                 {"audit", false}};
    security_policy p1 = security_policy::from_json(conf);
    rootfs_mcp::exec_service exec1(p1, *audit);

    std::atomic<bool> long_running{false};
    std::thread t([&] {
        exec_options o;
        o.argv = {"/bin/sleep", "2"};
        long_running = true;
        exec1.run(o, "t");
    });
    while (!long_running.load()) std::this_thread::yield();
    std::this_thread::sleep_for(std::chrono::milliseconds(150)); // ensure slot held
    EXPECT_THROW(exec1.run(opts_of({"/bin/echo", "x"}), "s"), std::runtime_error);
    t.join();
}

} // namespace
