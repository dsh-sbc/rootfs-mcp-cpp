cmake_minimum_required(VERSION 3.16)
project(rootfs_mcp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Tests are native-only: GoogleTest is not part of the riscv64 sysroot.
option(ROOTFS_MCP_BUILD_TESTS "Build rootfs-mcp tests" ON)
if(CMAKE_CROSSCOMPILING)
    set(ROOTFS_MCP_BUILD_TESTS OFF CACHE BOOL "Build rootfs-mcp tests" FORCE)
endif()

find_package(Threads REQUIRED)

# ---- cpp-mcp library (vendored in third_party/cpp-mcp) --------------------
# Provides the MCP protocol + Streamable HTTP transport (mcp::server).
set(CPP_MCP_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cpp-mcp)
set(CPP_MCP_SOURCES
    ${CPP_MCP_ROOT}/src/mcp_message.cpp
    ${CPP_MCP_ROOT}/src/mcp_server.cpp
    ${CPP_MCP_ROOT}/src/mcp_resource.cpp
    ${CPP_MCP_ROOT}/src/mcp_tool.cpp)

add_library(cpp_mcp STATIC ${CPP_MCP_SOURCES})
target_include_directories(cpp_mcp PUBLIC
    ${CPP_MCP_ROOT}/include
    ${CPP_MCP_ROOT}/common)
target_compile_definitions(cpp_mcp PUBLIC MCP_MAX_SESSIONS=64 MCP_SESSION_TIMEOUT=300)
target_link_libraries(cpp_mcp PUBLIC Threads::Threads)

# ---- rootfs-mcp core ------------------------------------------------------
add_library(rootfs_mcp_core STATIC
    src/util/util.cpp
    src/util/secure_open.cpp
    src/util/audit_log.cpp
    src/security/security_policy.cpp
    src/fs/fs_service.cpp
    src/exec/exec_service.cpp
    src/sys/sys_service.cpp
    src/mcp/tool_registry.cpp)
target_include_directories(rootfs_mcp_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
# _GNU_SOURCE: pipe2, dprintf, O_PATH, openat2 declarations.
target_compile_definitions(rootfs_mcp_core PRIVATE _GNU_SOURCE)
target_compile_options(rootfs_mcp_core PRIVATE -Wall -Wextra)
target_link_libraries(rootfs_mcp_core PUBLIC cpp_mcp)

add_executable(rootfs-mcp src/main.cpp)
target_compile_options(rootfs-mcp PRIVATE -Wall -Wextra)
target_link_libraries(rootfs-mcp PRIVATE rootfs_mcp_core)

install(TARGETS rootfs-mcp RUNTIME DESTINATION bin)
install(FILES config/rootfs-mcp.json DESTINATION etc/rootfs-mcp)

# ---- make cp: 将 ELF 和默认配置 scp 到目标机 ------------------------------
# 可通过 -DSCP_HOST=... -DSCP_PORT=... -DSCP_USER=... -DSCP_PATH=... 覆盖
if(NOT DEFINED SCP_HOST)
    set(SCP_HOST "192.168.0.113")
endif()
if(NOT DEFINED SCP_PORT)
    set(SCP_PORT "2222")
endif()
if(NOT DEFINED SCP_USER)
    set(SCP_USER "root")
endif()
if(NOT DEFINED SCP_PATH)
    set(SCP_PATH "/root")
endif()

add_custom_target(cp
    COMMAND bash -c "scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P ${SCP_PORT} rootfs-mcp ${CMAKE_CURRENT_SOURCE_DIR}/config/rootfs-mcp.json ${SCP_USER}@${SCP_HOST}:${SCP_PATH}"
    DEPENDS rootfs-mcp
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Copying rootfs-mcp and rootfs-mcp.json to ${SCP_USER}@${SCP_HOST}:${SCP_PATH}..."
    VERBATIM
)

# ---- tests (native only) ---------------------------------------------------
if(ROOTFS_MCP_BUILD_TESTS)
    set(GTEST_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/third_party/googletest)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    add_subdirectory(${GTEST_ROOT} ${CMAKE_BINARY_DIR}/googletest-build)

    enable_testing()
    foreach(t test_protocol test_fs test_exec test_security)
        add_executable(${t} tests/${t}.cpp)
        target_compile_options(${t} PRIVATE -Wall -Wextra)
        target_link_libraries(${t} PRIVATE rootfs_mcp_core GTest::gtest_main)
        add_test(NAME ${t} COMMAND ${t})
        set_tests_properties(${t} PROPERTIES TIMEOUT 60)
    endforeach()
endif()
