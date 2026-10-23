#include "rootfs_mcp/util.hpp"

#include <cctype>
#include <ctime>
#include <stdexcept>

namespace rootfs_mcp {

namespace {
const char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int b64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
} // namespace

std::string base64_encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) v |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) v |= data[i + 2];
        out.push_back(kB64[(v >> 18) & 63]);
        out.push_back(kB64[(v >> 12) & 63]);
        out.push_back(i + 1 < len ? kB64[(v >> 6) & 63] : '=');
        out.push_back(i + 2 < len ? kB64[v & 63] : '=');
    }
    return out;
}

std::string base64_encode(const std::string& s) {
    return base64_encode(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

std::string base64_decode(const std::string& s) {
    std::string out;
    out.reserve(s.size() / 4 * 3);
    uint32_t acc = 0;
    int bits = 0;
    for (char c : s) {
        if (c == '=') break;
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        int v = b64_value(c);
        if (v < 0) throw std::invalid_argument("invalid base64 character");
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((acc >> bits) & 0xFF));
        }
    }
    return out;
}

std::vector<std::string> split_path(const std::string& path) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < path.size()) {
        size_t j = path.find('/', i);
        if (j == std::string::npos) j = path.size();
        if (j > i) out.push_back(path.substr(i, j - i));
        i = j + 1;
    }
    return out;
}

bool looks_binary(const uint8_t* data, size_t len) {
    size_t sample = len < 4096 ? len : 4096;
    if (sample == 0) return false;
    size_t non_text = 0;
    for (size_t i = 0; i < sample; ++i) {
        uint8_t c = data[i];
        if (c == 0) return true;
        if (c < 0x09 || (c > 0x0D && c < 0x20)) ++non_text;
    }
    return non_text * 100 > sample * 5; // >5% control bytes -> binary
}

std::string format_time_utc(int64_t sec) {
    time_t t = static_cast<time_t>(sec);
    struct tm tmv;
    if (!gmtime_r(&t, &tmv)) return "";
    char buf[32];
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmv) == 0) return "";
    return buf;
}

std::string arg_string(const json& args, const char* name, bool required,
                       const std::string& def) {
    if (!args.is_object() || !args.contains(name) || args[name].is_null()) {
        if (required)
            throw std::invalid_argument(std::string("missing required argument '") + name + "'");
        return def;
    }
    if (!args[name].is_string())
        throw std::invalid_argument(std::string("argument '") + name + "' must be a string");
    return args[name].get<std::string>();
}

uint64_t arg_u64(const json& args, const char* name, uint64_t def) {
    if (!args.is_object() || !args.contains(name) || args[name].is_null()) return def;
    const json& v = args[name];
    if (v.is_number_unsigned()) return v.get<uint64_t>();
    if (v.is_number_integer()) {
        int64_t i = v.get<int64_t>();
        if (i < 0)
            throw std::invalid_argument(std::string("argument '") + name + "' must be >= 0");
        return static_cast<uint64_t>(i);
    }
    if (v.is_number_float()) {
        double d = v.get<double>();
        if (d < 0) throw std::invalid_argument(std::string("argument '") + name + "' must be >= 0");
        return static_cast<uint64_t>(d);
    }
    throw std::invalid_argument(std::string("argument '") + name + "' must be a number");
}

bool arg_bool(const json& args, const char* name, bool def) {
    if (!args.is_object() || !args.contains(name) || args[name].is_null()) return def;
    if (!args[name].is_boolean())
        throw std::invalid_argument(std::string("argument '") + name + "' must be a boolean");
    return args[name].get<bool>();
}

} // namespace rootfs_mcp
