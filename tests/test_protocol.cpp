// Protocol-level tests over real HTTP against a live rootfs-mcp server.
#include <gtest/gtest.h>

#include <cstdio>
#include <memory>
#include <string>
#include <unistd.h>

#include "httplib.h"
#include "mcp_server.h"

#include "rootfs_mcp/audit_log.hpp"
#include "rootfs_mcp/exec_service.hpp"
#include "rootfs_mcp/fs_service.hpp"
#include "rootfs_mcp/security_policy.hpp"
#include "rootfs_mcp/sys_service.hpp"
#include "rootfs_mcp/tool_registry.hpp"

using rootfs_mcp::json;

namespace {

std::string make_tmpdir() {
    char tmpl[] = "/tmp/rootfs-mcp-proto-XXXXXX";
    if (!mkdtemp(tmpl)) return "/tmp";
    return tmpl;
}

httplib::Headers session_headers(const std::string& session) {
    return {{"Accept", "application/json"}, {"Mcp-Session-Id", session}};
}

json rpc(const char* method, json params, int id) {
    return {{"jsonrpc", "2.0"}, {"id", id}, {"method", method}, {"params", std::move(params)}};
}

class ProtocolTest : public ::testing::Test {
protected:
    static std::string tmpdir;
    static std::unique_ptr<mcp::server> srv;
    static int port;

    static void SetUpTestSuite() {
        tmpdir = make_tmpdir();
        {
            FILE* f = std::fopen((tmpdir + "/hello.txt").c_str(), "w");
            std::fputs("hello mcp\n", f);
            std::fclose(f);
        }
        json conf = {
            {"mode", "readonly"},
            {"allow_read", json::array({"/"})},
            {"allow_write", json::array()},
            {"deny", json::array()},
            {"allow_exec", json::array()},
            {"audit", false},
        };
        // These members must outlive the server, so they are function-local
        // statics (leaked intentionally until process exit).
        static rootfs_mcp::security_policy policy =
            rootfs_mcp::security_policy::from_json(conf);
        static rootfs_mcp::audit_log audit(false, "");
        static rootfs_mcp::fs_service fs(policy, audit);
        static rootfs_mcp::exec_service exec(policy, audit);
        static rootfs_mcp::sys_service sys;

        for (int attempt = 0; attempt < 40; ++attempt) {
            int candidate = 23100 + static_cast<int>((getpid() + attempt * 37) % 2000);
            mcp::server::configuration c;
            c.host = "127.0.0.1";
            c.port = candidate;
            c.name = "rootfs-mcp-test";
            c.version = "test";
            c.mcp_endpoint = "/rootfs";
            auto s = std::make_unique<mcp::server>(c);
            rootfs_mcp::tool_registry reg(*s, policy, fs, exec, sys, audit);
            reg.register_all();
            if (s->start(false)) {
                srv = std::move(s);
                port = candidate;
                return;
            }
        }
        FAIL() << "could not bind test server on any candidate port";
    }

    static void TearDownTestSuite() {
        if (srv) srv->stop();
    }

    httplib::Result post(httplib::Client& cli, const json& body,
                         const httplib::Headers& headers = {{"Accept", "application/json"}}) {
        return cli.Post("/rootfs", headers, body.dump(), "application/json");
    }

    std::string initialize_session(httplib::Client& cli) {
        auto res = post(cli, rpc("initialize",
                                 {{"protocolVersion", "2025-03-26"},
                                  {"capabilities", json::object()},
                                  {"clientInfo", {{"name", "proto-test"}, {"version", "0.1"}}}},
                                 1));
        EXPECT_TRUE(res && res->status == 200);
        if (!res || res->status != 200) return "";
        std::string session = res->get_header_value("Mcp-Session-Id");
        EXPECT_FALSE(session.empty());
        json body = json::parse(res->body);
        EXPECT_EQ(body["result"]["protocolVersion"], "2025-03-26");
        EXPECT_EQ(body["result"]["serverInfo"]["name"], "rootfs-mcp-test");
        auto nres = post(cli, {{"jsonrpc", "2.0"}, {"method", "notifications/initialized"}},
                         session_headers(session));
        EXPECT_TRUE(nres && nres->status == 202);
        return session;
    }
};

std::string ProtocolTest::tmpdir;
std::unique_ptr<mcp::server> ProtocolTest::srv;
int ProtocolTest::port = 0;

TEST_F(ProtocolTest, InitializeHandshake) {
    httplib::Client cli("127.0.0.1", port);
    std::string session = initialize_session(cli);
    ASSERT_FALSE(session.empty());
}

TEST_F(ProtocolTest, ToolsListReturnsAllTools) {
    httplib::Client cli("127.0.0.1", port);
    std::string session = initialize_session(cli);
    ASSERT_FALSE(session.empty());
    auto res = post(cli, rpc("tools/list", json::object(), 2), session_headers(session));
    ASSERT_TRUE(res && res->status == 200);
    json body = json::parse(res->body);
    ASSERT_TRUE(body.contains("result"));
    auto& tools = body["result"]["tools"];
    EXPECT_EQ(tools.size(), 15u);
    for (const auto& t : tools) {
        EXPECT_TRUE(t.contains("name"));
        EXPECT_TRUE(t.contains("description"));
        EXPECT_TRUE(t.contains("inputSchema"));
    }
}

TEST_F(ProtocolTest, ToolsCallFsRead) {
    httplib::Client cli("127.0.0.1", port);
    std::string session = initialize_session(cli);
    ASSERT_FALSE(session.empty());
    auto res = post(cli,
                    rpc("tools/call",
                        {{"name", "fs_read"}, {"arguments", {{"path", tmpdir + "/hello.txt"}}}}, 3),
                    session_headers(session));
    ASSERT_TRUE(res && res->status == 200);
    json body = json::parse(res->body);
    ASSERT_TRUE(body.contains("result"));
    EXPECT_EQ(body["result"]["isError"], false);
    json inner = json::parse(body["result"]["content"][0]["text"].get<std::string>());
    EXPECT_EQ(inner["content"], "hello mcp\n");
    EXPECT_EQ(inner["encoding"], "utf-8");
    EXPECT_EQ(inner["has_more"], false);
}

TEST_F(ProtocolTest, InvalidToolArgumentsAreToolErrors) {
    httplib::Client cli("127.0.0.1", port);
    std::string session = initialize_session(cli);
    ASSERT_FALSE(session.empty());
    // Missing required 'path' argument -> tool-level error, not fake success.
    auto res = post(cli, rpc("tools/call", {{"name", "fs_read"}, {"arguments", json::object()}}, 4),
                    session_headers(session));
    ASSERT_TRUE(res && res->status == 200);
    json body = json::parse(res->body);
    ASSERT_TRUE(body.contains("result"));
    EXPECT_EQ(body["result"]["isError"], true);
    EXPECT_NE(body["result"]["content"][0]["text"].get<std::string>().find("path"),
              std::string::npos);
}

TEST_F(ProtocolTest, UnknownToolIsInvalidParams) {
    httplib::Client cli("127.0.0.1", port);
    std::string session = initialize_session(cli);
    ASSERT_FALSE(session.empty());
    auto res = post(cli, rpc("tools/call", {{"name", "no_such_tool"}}, 5), session_headers(session));
    ASSERT_TRUE(res && res->status == 200);
    json body = json::parse(res->body);
    ASSERT_TRUE(body.contains("error"));
    EXPECT_EQ(body["error"]["code"], -32602); // invalid_params
}

TEST_F(ProtocolTest, UnknownMethodIsMethodNotFound) {
    httplib::Client cli("127.0.0.1", port);
    std::string session = initialize_session(cli);
    ASSERT_FALSE(session.empty());
    auto res = post(cli, rpc("bogus/method", json::object(), 6), session_headers(session));
    ASSERT_TRUE(res && res->status == 200);
    json body = json::parse(res->body);
    ASSERT_TRUE(body.contains("error"));
    EXPECT_EQ(body["error"]["code"], -32601); // method_not_found
}

TEST_F(ProtocolTest, InvalidJsonRejected) {
    httplib::Client cli("127.0.0.1", port);
    auto res = cli.Post("/rootfs", {{"Accept", "application/json"}}, "{not json",
                        "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 400);
}

TEST_F(ProtocolTest, MissingSessionIdRejected) {
    httplib::Client cli("127.0.0.1", port);
    auto res = post(cli, rpc("ping", json::object(), 7));
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 400);
}

TEST_F(ProtocolTest, RequestBeforeInitializedNotification) {
    httplib::Client cli("127.0.0.1", port);
    // Initialize but deliberately skip notifications/initialized.
    auto res = post(cli, rpc("initialize",
                             {{"protocolVersion", "2025-03-26"},
                              {"capabilities", json::object()},
                              {"clientInfo", {{"name", "t"}, {"version", "0"}}}},
                             1));
    ASSERT_TRUE(res && res->status == 200);
    std::string session = res->get_header_value("Mcp-Session-Id");
    ASSERT_FALSE(session.empty());
    auto res2 = post(cli, rpc("tools/list", json::object(), 8), session_headers(session));
    ASSERT_TRUE(res2 && res2->status == 200);
    json body = json::parse(res2->body);
    ASSERT_TRUE(body.contains("error"));
    EXPECT_EQ(body["error"]["code"], -32600); // invalid_request: session not initialized
}

TEST_F(ProtocolTest, DeleteSessionTerminatesIt) {
    httplib::Client cli("127.0.0.1", port);
    std::string session = initialize_session(cli);
    ASSERT_FALSE(session.empty());
    auto dres = cli.Delete("/rootfs", session_headers(session));
    ASSERT_TRUE(dres);
    EXPECT_EQ(dres->status, 200);
    auto res = post(cli, rpc("ping", json::object(), 9), session_headers(session));
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 404); // session gone
}

TEST_F(ProtocolTest, GetWithoutSessionRejected) {
    httplib::Client cli("127.0.0.1", port);
    auto res = cli.Get("/rootfs");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 400);
}

TEST_F(ProtocolTest, SequentialMessagesKeepBoundaries) {
    httplib::Client cli("127.0.0.1", port);
    std::string session = initialize_session(cli);
    ASSERT_FALSE(session.empty());
    // Many sequential POSTs on one connection: every response must carry the
    // exact request id, i.e. no message boundary confusion.
    for (int id = 10; id < 20; ++id) {
        auto res = post(cli, rpc(id % 2 ? "ping" : "tools/list", json::object(), id),
                        session_headers(session));
        ASSERT_TRUE(res && res->status == 200) << "id=" << id;
        json body = json::parse(res->body);
        ASSERT_TRUE(body.contains("result")) << "id=" << id << " body=" << res->body;
        EXPECT_EQ(body["id"], id);
    }
}

TEST_F(ProtocolTest, ReadonlyModeRejectsWriteTools) {
    httplib::Client cli("127.0.0.1", port);
    std::string session = initialize_session(cli);
    ASSERT_FALSE(session.empty());
    auto res = post(cli,
                    rpc("tools/call",
                        {{"name", "fs_write"},
                         {"arguments", {{"path", tmpdir + "/x"}, {"content", "x"}}}},
                        30),
                    session_headers(session));
    ASSERT_TRUE(res && res->status == 200);
    json body = json::parse(res->body);
    EXPECT_EQ(body["result"]["isError"], true);
    EXPECT_NE(body["result"]["content"][0]["text"].get<std::string>().find("not permitted"),
              std::string::npos);
}

} // namespace
