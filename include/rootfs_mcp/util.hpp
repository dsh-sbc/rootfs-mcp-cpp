#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "json.hpp"

namespace rootfs_mcp {

using json = nlohmann::ordered_json;

// Base64 helpers (RFC 4648, standard alphabet, with padding).
std::string base64_encode(const uint8_t* data, size_t len);
std::string base64_encode(const std::string& s);
// Throws std::invalid_argument on malformed input.
std::string base64_decode(const std::string& s);

// Split a path into components ('/' separators, empty components dropped).
std::vector<std::string> split_path(const std::string& path);

// True when the buffer looks like binary data (NUL byte or a significant
// fraction of non-text bytes in the sampled prefix).
bool looks_binary(const uint8_t* data, size_t len);

// Argument extraction helpers for tool handlers/services. Throw
// std::invalid_argument on missing or ill-typed values.
std::string arg_string(const json& args, const char* name, bool required,
                       const std::string& def = std::string());
uint64_t arg_u64(const json& args, const char* name, uint64_t def);
bool arg_bool(const json& args, const char* name, bool def);

// Format a timespec as ISO-8601 UTC (e.g. 2026-10-22T10:15:30Z).
std::string format_time_utc(int64_t sec);

} // namespace rootfs_mcp
