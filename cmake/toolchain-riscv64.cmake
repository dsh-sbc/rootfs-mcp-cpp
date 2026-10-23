# rootfs-mcp riscv64 cross toolchain
# Xuantie-900 riscv64 gcc 14.1.1 (glibc), target CPU C908 (K230 CanMV).
# Derived from /build/ai_wh/xiaozhi/protocol_hub/config/toolchain-riscv64.cmake.
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR riscv64)

if(DEFINED TOOLCHAIN_INCLUDED)
    return()
endif()
set(TOOLCHAIN_INCLUDED TRUE)

set(SDK_PATH "/build/k230_huskylens_pack")
set(BOARD_NAME "k230_canmv_huskylens_defconfig")
set(TOOLCHAIN_PATH "${SDK_PATH}/output/${BOARD_NAME}/host")

set(CMAKE_SYSROOT "${TOOLCHAIN_PATH}/riscv64-buildroot-linux-gnu/sysroot")
set(CMAKE_C_COMPILER   "${TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-gcc")
set(CMAKE_CXX_COMPILER "${TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-g++")
set(CMAKE_ADDR2LINE    "${TOOLCHAIN_PATH}/bin/riscv64-unknown-linux-gnu-addr2line")

set(CMAKE_C_FLAGS   "-mcpu=c908v -O3 -Wall -Wextra -Wshadow -Wundef -fno-strict-aliasing -Wformat-security -D_DEFAULT_SOURCE -std=c99")
set(CMAKE_CXX_FLAGS "-mcpu=c908v -O3 -Wall -Wextra -Wshadow -Wundef -fno-strict-aliasing -Wformat-security -D_DEFAULT_SOURCE -std=c++17")

set(CMAKE_EXE_LINKER_FLAGS "-mcpu=c908v")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -L${CMAKE_SYSROOT}/usr/lib64/lp64d -L${CMAKE_SYSROOT}/usr/lib")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
