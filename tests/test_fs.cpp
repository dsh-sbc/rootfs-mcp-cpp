// Filesystem service tests: chunking, binary handling, limits, traversal,
// symlink/escape rejection, FIFO non-blocking behaviour.
#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "rootfs_mcp/audit_log.hpp"
#include "rootfs_mcp/fs_service.hpp"
#include "rootfs_mcp/security_policy.hpp"
#include "rootfs_mcp/util.hpp"

using rootfs_mcp::json;
using rootfs_mcp::policy_error;
using rootfs_mcp::security_policy;

namespace {

std::string make_tmpdir() {
    char tmpl[] = "/tmp/rootfs-mcp-fs-XXXXXX";
    EXPECT_TRUE(mkdtemp(tmpl) != nullptr);
    return tmpl;
}

void write_file(const std::string& path, const std::string& data) {
    std::ofstream out(path, std::ios::binary);
    out << data;
}

class FsTest : public ::testing::Test {
protected:
    static std::string dir;
    static std::unique_ptr<security_policy> policy;
    static std::unique_ptr<rootfs_mcp::audit_log> audit;
    static std::unique_ptr<rootfs_mcp::fs_service> fs;

    static void SetUpTestSuite() {
        dir = security_policy::canonicalize_existing(make_tmpdir());
        write_file(dir + "/small.txt", "hello world\n");
        write_file(dir + "/big.bin", std::string(100000, 'A'));
        std::string binary;
        for (int i = 0; i < 256; ++i) binary.push_back(static_cast<char>(i));
        write_file(dir + "/bin.dat", binary);
        ::mkdir((dir + "/sub").c_str(), 0755);
        write_file(dir + "/sub/nested.txt", "needle in a haystack\nsecond line\n");
        ::mkdir((dir + "/sub/deep").c_str(), 0755);
        write_file(dir + "/sub/deep/leaf.txt", "leaf needle\n");
        write_file(dir + "/.hidden", "x");
        EXPECT_EQ(symlink("/etc", (dir + "/escape_link").c_str()), 0);
        EXPECT_EQ(symlink("small.txt", (dir + "/inner_link").c_str()), 0);
        mkfifo((dir + "/pipe.fifo").c_str(), 0644);

        json conf = {
            {"mode", "controlled"},
            {"allow_read", json::array({dir})},
            {"allow_write", json::array({dir})},
            {"deny", json::array({dir + "/denied"})},
            {"enable_delete", true},
            {"max_read_bytes", 64},
            {"max_write_bytes", 4096},
            {"audit", false},
        };
        ::mkdir((dir + "/denied").c_str(), 0755);
        policy = std::make_unique<security_policy>(security_policy::from_json(conf));
        audit = std::make_unique<rootfs_mcp::audit_log>(false, "");
        fs = std::make_unique<rootfs_mcp::fs_service>(*policy, *audit);
    }
};

std::string FsTest::dir;
std::unique_ptr<security_policy> FsTest::policy;
std::unique_ptr<rootfs_mcp::audit_log> FsTest::audit;
std::unique_ptr<rootfs_mcp::fs_service> FsTest::fs;

TEST_F(FsTest, ListDirectory) {
    json r = fs->list({{"path", dir}}, "s1");
    EXPECT_EQ(r["path"], dir);
    EXPECT_GE(r["entries"].size(), 5u);
    bool saw_hidden = false;
    for (const auto& e : r["entries"]) {
        if (e["name"] == ".hidden") saw_hidden = true;
        if (e["name"] == "escape_link") {
            EXPECT_EQ(e["type"], "symlink");
            EXPECT_EQ(e["is_symlink"], true);
        }
    }
    EXPECT_FALSE(saw_hidden); // hidden excluded by default
    r = fs->list({{"path", dir}, {"include_hidden", true}}, "s1");
    saw_hidden = false;
    for (const auto& e : r["entries"])
        if (e["name"] == ".hidden") saw_hidden = true;
    EXPECT_TRUE(saw_hidden);
}

TEST_F(FsTest, ListMaxEntries) {
    json r = fs->list({{"path", dir}, {"max_entries", 2}}, "s1");
    EXPECT_EQ(r["entries"].size(), 2u);
    EXPECT_EQ(r["truncated"], true);
    EXPECT_GT(r["total_entries"].get<uint64_t>(), 2u);
}

TEST_F(FsTest, ListNonexistentFails) {
    EXPECT_THROW(fs->list({{"path", dir + "/no-such-dir"}}, "s1"), std::exception);
}

TEST_F(FsTest, ReadSmallFile) {
    json r = fs->read({{"path", dir + "/small.txt"}}, "s1");
    EXPECT_EQ(r["content"], "hello world\n");
    EXPECT_EQ(r["encoding"], "utf-8");
    EXPECT_EQ(r["has_more"], false);
    EXPECT_EQ(r["length"], 12u);
}

TEST_F(FsTest, ReadChunkedWithHasMore) {
    json r1 = fs->read({{"path", dir + "/big.bin"}, {"offset", 0}, {"length", 10}}, "s1");
    EXPECT_EQ(r1["length"], 10u);
    EXPECT_EQ(r1["has_more"], true);
    json r2 = fs->read({{"path", dir + "/big.bin"}, {"offset", 99990}, {"length", 50}}, "s1");
    EXPECT_EQ(r2["length"], 10u);
    EXPECT_EQ(r2["has_more"], false);
}

TEST_F(FsTest, ReadLengthCappedByPolicy) {
    // Policy max_read_bytes = 64; requesting more is silently clamped.
    json r = fs->read({{"path", dir + "/big.bin"}, {"length", 1000000}}, "s1");
    EXPECT_EQ(r["length"], 64u);
    EXPECT_EQ(r["has_more"], true);
}

TEST_F(FsTest, ReadBinaryIsBase64) {
    json r = fs->read({{"path", dir + "/bin.dat"}}, "s1");
    EXPECT_EQ(r["encoding"], "base64");
    std::string decoded = rootfs_mcp::base64_decode(r["content"].get<std::string>());
    ASSERT_EQ(decoded.size(), 64u); // capped at max_read_bytes=64
    for (size_t i = 0; i < decoded.size(); ++i)
        EXPECT_EQ(static_cast<uint8_t>(decoded[i]), static_cast<uint8_t>(i));
}

TEST_F(FsTest, ReadFifoFailsFast) {
    auto start = std::chrono::steady_clock::now();
    EXPECT_THROW(fs->read({{"path", dir + "/pipe.fifo"}}, "s1"), std::runtime_error);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - start)
                  .count();
    EXPECT_LT(ms, 2000); // must fail fast, never block on the FIFO
}

TEST_F(FsTest, ReadThroughSymlinkEscapeRejected) {
    // escape_link -> /etc, which is outside allow_read=[dir].
    EXPECT_THROW(fs->read({{"path", dir + "/escape_link/passwd"}}, "s1"), policy_error);
}

TEST_F(FsTest, ReadThroughInnerSymlinkAllowed) {
    json r = fs->read({{"path", dir + "/inner_link"}}, "s1");
    EXPECT_EQ(r["content"], "hello world\n");
}

TEST_F(FsTest, DotDotEscapeRejected) {
    EXPECT_THROW(fs->read({{"path", dir + "/sub/../../etc/passwd"}}, "s1"), policy_error);
    EXPECT_THROW(fs->write({{"path", dir + "/sub/../../tmp/evil"}, {"content", "x"}}, "s1"),
                 policy_error);
}

TEST_F(FsTest, WriteCreateOverwriteOffset) {
    std::string p = dir + "/written.txt";
    json r = fs->write({{"path", p}, {"content", "abcdef"}}, "s1");
    EXPECT_EQ(r["bytes_written"], 6u);

    r = fs->write({{"path", p}, {"content", "XYZ"}, {"offset", 2}}, "s1");
    EXPECT_EQ(r["bytes_written"], 3u);
    json rd = fs->read({{"path", p}}, "s1");
    EXPECT_EQ(rd["content"], "abXYZf");

    // No offset -> truncate + overwrite.
    fs->write({{"path", p}, {"content", "q"}}, "s1");
    rd = fs->read({{"path", p}}, "s1");
    EXPECT_EQ(rd["content"], "q");
}

TEST_F(FsTest, WriteBase64AndMode) {
    std::string p = dir + "/b64.bin";
    std::string raw(256, '\0');
    for (int i = 0; i < 256; ++i) raw[i] = static_cast<char>(255 - i);
    fs->write({{"path", p},
               {"content", rootfs_mcp::base64_encode(raw)},
               {"encoding", "base64"},
               {"mode", 0600}},
              "s1");
    struct stat st;
    ASSERT_EQ(::stat(p.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 07777, 0600u);
    std::ifstream in(p, std::ios::binary);
    std::string got((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_EQ(got, raw);
}

TEST_F(FsTest, WriteExceedingMaxSizeRejected) {
    std::string big(5000, 'B'); // policy max_write_bytes = 4096
    EXPECT_THROW(fs->write({{"path", dir + "/too-big"}, {"content", big}}, "s1"),
                 std::runtime_error);
}

TEST_F(FsTest, WriteOutsideAllowListRejected) {
    EXPECT_THROW(fs->write({{"path", "/tmp/rootfs-mcp-outside-x"}, {"content", "x"}}, "s1"),
                 policy_error);
}

TEST_F(FsTest, WriteToDeniedPrefixRejected) {
    // deny[] has priority over allow_write.
    EXPECT_THROW(fs->write({{"path", dir + "/denied/x"}, {"content", "x"}}, "s1"), policy_error);
}

TEST_F(FsTest, WriteSpecialFileRejected) {
    EXPECT_THROW(fs->write({{"path", dir + "/pipe.fifo"}, {"content", "x"}}, "s1"),
                 std::exception);
}

TEST_F(FsTest, WriteThroughSymlinkRejected) {
    // 'outer_link' will point outside the authorized root; creating the link
    // itself is fine, but writing through it must fail (either at
    // authorization because the resolved path escapes, or at open time).
    std::string outside = dir + "-outside-target";
    write_file(outside, "orig");
    std::string link = dir + "/outer_link";
    unlink(link.c_str());
    EXPECT_EQ(symlink(outside.c_str(), link.c_str()), 0);
    EXPECT_THROW(fs->write({{"path", link}, {"content", "pwned"}}, "s1"), std::exception);
    std::ifstream in(outside);
    std::string got((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_EQ(got, "orig"); // untouched
    unlink(outside.c_str());
}

TEST_F(FsTest, StatFile) {
    json r = fs->stat({{"path", dir + "/small.txt"}}, "s1");
    EXPECT_EQ(r["type"], "file");
    EXPECT_EQ(r["size"], 12u);
    EXPECT_EQ(r["is_symlink"], false);
    EXPECT_GT(r["mtime"].get<int64_t>(), 0);

    r = fs->stat({{"path", dir + "/escape_link"}}, "s1");
    EXPECT_EQ(r["is_symlink"], true);
    EXPECT_EQ(r["symlink_target"], "/etc");
}

TEST_F(FsTest, MkdirVariants) {
    json r = fs->mkdir({{"path", dir + "/newdir"}}, "s1");
    EXPECT_EQ(r["created"], true);
    EXPECT_THROW(fs->mkdir({{"path", dir + "/newdir"}}, "s1"), std::runtime_error); // exists
    EXPECT_THROW(fs->mkdir({{"path", dir + "/a/b/c"}}, "s1"), std::runtime_error); // no parents
    r = fs->mkdir({{"path", dir + "/a/b/c"}, {"recursive", true}, {"mode", 0750}}, "s1");
    EXPECT_EQ(r["created"], true);
    struct stat st;
    ASSERT_EQ(::stat((dir + "/a/b/c").c_str(), &st), 0);
    EXPECT_TRUE(S_ISDIR(st.st_mode));
}

TEST_F(FsTest, RemoveRules) {
    // Non-recursive removal of a non-empty directory must fail.
    EXPECT_THROW(fs->remove({{"path", dir + "/sub"}}, "s1"), std::runtime_error);

    // Build a tree containing a symlink to /etc: recursive removal must not
    // follow it (/etc must remain intact) and must remove the link itself.
    std::string tree = dir + "/tree";
    fs->mkdir({{"path", tree + "/inner"}, {"recursive", true}}, "s1");
    fs->write({{"path", tree + "/inner/f.txt"}, {"content", "data"}}, "s1");
    EXPECT_EQ(symlink("/etc", (tree + "/etc_link").c_str()), 0);
    json r = fs->remove({{"path", tree}, {"recursive", true}}, "s1");
    EXPECT_EQ(r["removed"], true);
    EXPECT_EQ(r["errors"], 0u);
    struct stat st;
    EXPECT_EQ(::stat("/etc", &st), 0);          // sanity: /etc untouched
    EXPECT_NE(::stat(tree.c_str(), &st), 0);    // tree gone
}

TEST_F(FsTest, RemoveAuthorizedRootRejected) {
    EXPECT_THROW(fs->remove({{"path", dir}, {"recursive", true}}, "s1"), policy_error);
}

TEST_F(FsTest, RemoveFile) {
    std::string p = dir + "/to-delete.txt";
    fs->write({{"path", p}, {"content", "bye"}}, "s1");
    json r = fs->remove({{"path", p}}, "s1");
    EXPECT_EQ(r["removed"], true);
    struct stat st;
    EXPECT_NE(::stat(p.c_str(), &st), 0);
}

TEST_F(FsTest, MoveFile) {
    std::string s = dir + "/mv-src.txt", d = dir + "/mv-dst.txt";
    fs->write({{"path", s}, {"content", "payload"}}, "s1");
    json r = fs->move({{"src", s}, {"dst", d}}, "s1");
    EXPECT_EQ(r["moved"], true);
    EXPECT_EQ(fs->read({{"path", d}}, "s1")["content"], "payload");
    // Moving outside the authorized area must be rejected.
    EXPECT_THROW(fs->move({{"src", d}, {"dst", "/tmp/rootfs-mcp-mv-out"}}, "s1"), policy_error);
}

TEST_F(FsTest, SearchByName) {
    json r = fs->search({{"path", dir}, {"pattern", "*.txt"}, {"max_results", 50}}, "s1");
    EXPECT_GE(r["count"].get<uint64_t>(), 3u);
    EXPECT_EQ(r["timed_out"], false);

    r = fs->search({{"path", dir}, {"pattern", "nested.txt"}}, "s1");
    EXPECT_EQ(r["count"], 1u);
    EXPECT_EQ(r["results"][0]["path"], dir + "/sub/nested.txt");
}

TEST_F(FsTest, SearchByContent) {
    json r = fs->search({{"path", dir},
                         {"pattern", "needle"},
                         {"mode", "content"},
                         {"max_results", 50}},
                        "s1");
    EXPECT_GE(r["count"].get<uint64_t>(), 2u); // nested.txt + leaf.txt
    bool saw_line = false;
    for (const auto& m : r["results"])
        if (m.contains("line")) saw_line = true;
    EXPECT_TRUE(saw_line);
}

TEST_F(FsTest, SearchLimits) {
    json r = fs->search({{"path", dir}, {"pattern", "t"}, {"max_results", 1}}, "s1");
    EXPECT_LE(r["count"].get<uint64_t>(), 1u);
    EXPECT_EQ(r["truncated"], true);

    // Depth 0: only direct children considered, no recursion.
    r = fs->search({{"path", dir}, {"pattern", "leaf.txt"}, {"max_depth", 0}}, "s1");
    EXPECT_EQ(r["count"], 0u);
    r = fs->search({{"path", dir}, {"pattern", "leaf.txt"}, {"max_depth", 3}}, "s1");
    EXPECT_EQ(r["count"], 1u);
}

TEST_F(FsTest, SearchDoesNotFollowSymlinks) {
    // 'escape_link' -> /etc contains 'passwd'; searching for that name from
    // the test dir must not descend into the symlink.
    json r = fs->search({{"path", dir}, {"pattern", "passwd"}, {"max_results", 50}}, "s1");
    for (const auto& m : r["results"])
        EXPECT_EQ(m["path"].get<std::string>().find("/etc/"), std::string::npos);
}

} // namespace
