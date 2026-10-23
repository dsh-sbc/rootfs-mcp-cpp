// Security policy tests: config load, mode gating, path authorization,
// deny priority, symlink escape, protected system paths, secure open.
#include <gtest/gtest.h>

#include <fcntl.h>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "rootfs_mcp/secure_open.hpp"
#include "rootfs_mcp/security_policy.hpp"

using rootfs_mcp::json;
using rootfs_mcp::policy_error;
using rootfs_mcp::security_policy;
using rootfs_mcp::server_mode;

namespace {

std::string make_tmpdir() {
    char tmpl[] = "/tmp/rootfs-mcp-sec-XXXXXX";
    EXPECT_TRUE(mkdtemp(tmpl) != nullptr);
    return security_policy::canonicalize_existing(tmpl);
}

class SecurityTest : public ::testing::Test {
protected:
    static std::string dir;

    static void SetUpTestSuite() {
        dir = make_tmpdir();
        ::mkdir((dir + "/sub").c_str(), 0755);
        // symlink inside the authorized root pointing outside of it
        EXPECT_EQ(symlink("/etc", (dir + "/escape").c_str()), 0);
    }

    static security_policy make_policy(const char* mode, json extra = json::object()) {
        json conf = {
            {"mode", mode},
            {"allow_read", json::array({dir})},
            {"allow_write", json::array({dir})},
            {"deny", json::array({dir + "/denied"})},
            {"allow_exec", json::array({"/bin/echo"})},
            {"audit", false},
        };
        conf.update(extra);
        return security_policy::from_json(conf);
    }
};

std::string SecurityTest::dir;

TEST_F(SecurityTest, ModeParsing) {
    EXPECT_EQ(rootfs_mcp::parse_mode("readonly"), server_mode::readonly_mode);
    EXPECT_EQ(rootfs_mcp::parse_mode("controlled"), server_mode::controlled);
    EXPECT_EQ(rootfs_mcp::parse_mode("admin"), server_mode::admin);
    EXPECT_THROW(rootfs_mcp::parse_mode("root"), policy_error);
}

TEST_F(SecurityTest, PrefixMatchIsComponentAware) {
    EXPECT_TRUE(security_policy::is_under("/a/b/c", "/a"));
    EXPECT_TRUE(security_policy::is_under("/a", "/a"));
    EXPECT_TRUE(security_policy::is_under("/anything", "/"));
    EXPECT_FALSE(security_policy::is_under("/abc", "/a"));   // /a must not match /abc
    EXPECT_FALSE(security_policy::is_under("relative/x", "/a"));
}

TEST_F(SecurityTest, ReadAuthorization) {
    security_policy p = make_policy("readonly");
    auto ap = p.authorize_read(dir + "/sub");
    EXPECT_EQ(ap.canonical, dir + "/sub");
    EXPECT_EQ(ap.rel, "sub");
    EXPECT_GE(ap.rootfd, 0);

    EXPECT_THROW(p.authorize_read("/etc"), policy_error);        // not under allow_read
    EXPECT_THROW(p.authorize_read(dir + "/missing"), policy_error); // nonexistent
}

TEST_F(SecurityTest, DenyTakesPriority) {
    ::mkdir((dir + "/denied").c_str(), 0755);
    security_policy p = make_policy("readonly");
    EXPECT_THROW(p.authorize_read(dir + "/denied"), policy_error);
    // Deny also wins over allow_write.
    EXPECT_THROW(p.authorize_write(dir + "/denied/x"), policy_error);
}

TEST_F(SecurityTest, DotDotRejected) {
    security_policy p = make_policy("controlled");
    // Existing path that escapes after resolution.
    EXPECT_THROW(p.authorize_read(dir + "/sub/../../etc"), policy_error);
    // Non-existent tail containing "..".
    EXPECT_THROW(p.authorize_write(dir + "/newdir/../escape-file"), policy_error);
    // Legitimate use of ".." that stays inside the root is fine.
    auto ap = p.authorize_read(dir + "/sub/../sub");
    EXPECT_EQ(ap.canonical, dir + "/sub");
}

TEST_F(SecurityTest, SymlinkEscapeRejected) {
    security_policy p = make_policy("readonly");
    // dir/escape -> /etc: resolution lands outside the authorized root.
    EXPECT_THROW(p.authorize_read(dir + "/escape"), policy_error);
    EXPECT_THROW(p.authorize_read(dir + "/escape/passwd"), policy_error);
}

TEST_F(SecurityTest, WriteRequiresControlledMode) {
    security_policy ro = make_policy("readonly");
    EXPECT_THROW(ro.authorize_write(dir + "/x"), policy_error);
    security_policy c = make_policy("controlled");
    EXPECT_NO_THROW(c.authorize_write(dir + "/x"));
}

TEST_F(SecurityTest, ToolGatingByMode) {
    security_policy ro = make_policy("readonly");
    EXPECT_TRUE(ro.tool_permitted("fs_read"));
    EXPECT_TRUE(ro.tool_permitted("sys_info"));
    EXPECT_FALSE(ro.tool_permitted("fs_write"));
    EXPECT_FALSE(ro.tool_permitted("shell_exec"));

    security_policy c = make_policy("controlled");
    EXPECT_TRUE(c.tool_permitted("fs_write"));
    EXPECT_TRUE(c.tool_permitted("shell_exec"));
    EXPECT_FALSE(c.tool_permitted("fs_remove"));         // enable_delete=false
    EXPECT_FALSE(c.tool_permitted("shell_script_exec")); // allow_shell_script=false

    security_policy cd = make_policy("controlled", {{"enable_delete", true}});
    EXPECT_TRUE(cd.tool_permitted("fs_remove"));

    security_policy cs = make_policy("controlled", {{"allow_shell_script", true}});
    EXPECT_TRUE(cs.tool_permitted("shell_script_exec"));
    // allow_shell_script in readonly mode still denies the tool.
    security_policy rs = make_policy("readonly", {{"allow_shell_script", true}});
    EXPECT_FALSE(rs.tool_permitted("shell_script_exec"));

    security_policy a = make_policy("admin");
    EXPECT_TRUE(a.tool_permitted("shell_exec"));
}

TEST_F(SecurityTest, ExecAuthorization) {
    security_policy p = make_policy("controlled");
    EXPECT_NO_THROW(p.authorize_exec("/bin/echo"));
    EXPECT_THROW(p.authorize_exec("/bin/rm"), policy_error); // not in allow_exec
    EXPECT_THROW(p.authorize_exec("/nonexistent"), policy_error);

    // admin + empty allow_exec -> any executable resolvable path
    security_policy admin = make_policy("admin", {{"allow_exec", json::array()}});
    EXPECT_NO_THROW(admin.authorize_exec("/bin/rm"));
}

TEST_F(SecurityTest, ProtectedSystemPaths) {
    // Full-access admin policy: everything writable/deletable per config...
    security_policy admin = make_policy("admin", {
        {"allow_write", json::array({"/"})},
        {"enable_delete", true},
    });
    auto ap_root = admin.authorize_write("/");
    EXPECT_THROW(admin.check_deletable(ap_root), policy_error); // "/" itself

    auto ap_proc = admin.authorize_write("/proc");
    EXPECT_THROW(admin.check_deletable(ap_proc), policy_error);

    auto ap_sys_file = admin.authorize_write("/sys/kernel");
    EXPECT_THROW(admin.check_deletable(ap_sys_file), policy_error);

    auto ap_dev = admin.authorize_write("/dev/null");
    EXPECT_THROW(admin.check_deletable(ap_dev), policy_error);

    // /etc requires an *explicit* write grant at/below /etc; "/" is not enough.
    auto ap_etc = admin.authorize_write("/etc/hostname");
    EXPECT_THROW(admin.check_deletable(ap_etc), policy_error);

    // Explicit grant unlocks it.
    security_policy admin2 = make_policy("admin", {
        {"allow_write", json::array({"/etc"})},
        {"enable_delete", true},
    });
    auto ap_etc2 = admin2.authorize_write("/etc/hostname");
    EXPECT_NO_THROW(admin2.check_deletable(ap_etc2));

    // An ordinary authorized tmp path is fine.
    security_policy c = make_policy("controlled", {{"enable_delete", true}});
    auto ap_tmp = c.authorize_write(dir + "/sub");
    EXPECT_NO_THROW(c.check_deletable(ap_tmp));
}

TEST_F(SecurityTest, SecureOpenRejectsSymlinkComponents) {
    // Both the openat2 path and the fallback must refuse to open through a
    // symlink, even though plain openat() would follow it.
    int rootfd = open(dir.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
    ASSERT_GE(rootfd, 0);
    // "escape" is a symlink to /etc.
    int fd = rootfs_mcp::open_beneath(rootfd, "escape/hostname", O_RDONLY);
    EXPECT_EQ(fd, -1);
    EXPECT_EQ(errno, ELOOP);
    close(rootfd);
    (void)rootfs_mcp::openat2_supported(); // probe must not crash either way
}

TEST_F(SecurityTest, SecureOpenWorksForRealPaths) {
    int rootfd = open(dir.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
    ASSERT_GE(rootfd, 0);
    int fd = rootfs_mcp::open_beneath(rootfd, "sub", O_RDONLY | O_DIRECTORY, 0,
                                      dir + "/sub");
    ASSERT_GE(fd, 0) << "errno=" << errno;
    close(fd);
    close(rootfd);
}

TEST_F(SecurityTest, ConfigDefaults) {
    security_policy p = security_policy::from_json(json::object());
    EXPECT_EQ(p.mode(), server_mode::readonly_mode);
    EXPECT_FALSE(p.allow_shell_script());
    EXPECT_FALSE(p.enable_delete());
    EXPECT_TRUE(p.audit_enabled());
    EXPECT_EQ(p.listen().port, 9898);
    EXPECT_EQ(p.max_concurrent_exec(), 4u);
}

} // namespace
