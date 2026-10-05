#include "config.h"
#include "format.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <string_view>
#include <utility>
#include <sys/stat.h>
#include <unistd.h>

namespace hcd {
namespace {

constexpr size_t max_config_bytes = 64u * 1024u;
constexpr size_t max_line_bytes = 4096;

std::string_view trim(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
        text.remove_prefix(1);
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
        text.remove_suffix(1);
    }
    return text;
}

int hex_digit(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool unsigned_value(std::string_view text, uint64_t& value) {
    uint64_t base = 10;
    if (text.size() >= 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        base = 16;
        text.remove_prefix(2);
    }
    if (text.empty()) return false;
    value = 0;
    for (unsigned char c : text) {
        const int digit = hex_digit(c);
        if (digit < 0 || static_cast<uint64_t>(digit) >= base ||
            value > (std::numeric_limits<uint64_t>::max() - static_cast<uint64_t>(digit)) / base) {
            return false;
        }
        value = value * base + static_cast<uint64_t>(digit);
    }
    return true;
}

bool absolute_path(std::string_view path, bool reject_parent) {
    if (path.empty() || path.front() != '/') return false;
    for (unsigned char c : path) {
        if (c < 0x20 || c == 0x7f) return false;
    }
    if (reject_parent) {
        size_t start = 1;
        while (start < path.size()) {
            size_t end = path.find('/', start);
            if (end == std::string_view::npos) end = path.size();
            if (path.substr(start, end - start) == "..") return false;
            start = end + 1;
        }
    }
    return true;
}

} // namespace

bool load_config(const std::string& path, Config& config, std::string& error) {
    error.clear();
    const auto fail = [&error](const std::string& message) {
        error = message;
        return false;
    };
    if (!absolute_path(path, false)) {
        return fail("config_path must be an absolute path without control characters");
    }

    using File = std::unique_ptr<std::FILE, decltype(&std::fclose)>;
    // Reject special files without waiting for a FIFO writer during open.
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        const int code = errno;
        return fail("Cannot open configuration: " + std::string(std::strerror(code)));
    }
    File file(::fdopen(fd, "rb"), &std::fclose);
    if (!file) {
        const int code = errno;
        ::close(fd);
        return fail("Cannot open configuration stream: " + std::string(std::strerror(code)));
    }
    struct stat info{};
    if (::fstat(::fileno(file.get()), &info) != 0) {
        const int code = errno;
        return fail("Cannot stat configuration: " + std::string(std::strerror(code)));
    }
    if (!S_ISREG(info.st_mode)) {
        return fail("Configuration must be a regular file");
    }
    if (info.st_size < 0 || static_cast<uint64_t>(info.st_size) > max_config_bytes) {
        return fail("Configuration exceeds 64 KiB");
    }
    std::string content(static_cast<size_t>(info.st_size), '\0');
    const size_t read = std::fread(content.data(), 1, content.size(), file.get());
    if (std::ferror(file.get())) {
        return fail("Cannot read configuration: I/O error");
    }
    if (read != content.size()) {
        return fail("Short read while reading configuration");
    }
    const int extra = std::fgetc(file.get());
    if (std::ferror(file.get())) {
        return fail("Cannot read configuration: I/O error");
    }
    if (extra != EOF) {
        return fail(content.size() == max_config_bytes ? "Configuration exceeds 64 KiB" :
                    "Configuration size changed while reading");
    }

    std::set<std::string> required = {
        "stable_window_confirmed", "profile.name", "registry.hot.rva", "registry.aot_vector.rva"
    };
    for (const auto& function : profile::kFunctions) {
        const std::string prefix = std::string("function.") + function.name;
        required.insert(prefix + ".rva");
        required.insert(prefix + ".fingerprint_length");
        required.insert(prefix + ".sha256");
    }
    for (const char* name : profile::kEvidenceNames) {
        const std::string prefix = std::string("evidence.") + name;
        required.insert(prefix + ".rva");
        required.insert(prefix + ".bytes_hex");
    }
    for (const auto& layout : profile::kLayouts) {
        required.insert(std::string("layout.") + layout.name);
    }
    std::set<std::string> allowed = required;
    allowed.insert({"profile.analysis_sha256", "module_name", "initialization_timeout_seconds",
                    "chunk_size", "max_file_size", "dump_pdb", "output_directory"});
    std::map<std::string, std::string_view> values;
    size_t offset = 0;
    size_t line_number = 0;
    while (offset < content.size()) {
        size_t end = content.find('\n', offset);
        const bool newline = end != std::string::npos;
        if (!newline) end = content.size();
        std::string_view line(content.data() + offset, end - offset);
        offset = newline ? end + 1 : end;
        ++line_number;
        if (newline && !line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }
        const std::string context = "Configuration line " + std::to_string(line_number) + ": ";
        if (line.size() > max_line_bytes) {
            return fail(context + "exceeds 4096 bytes");
        }
        for (unsigned char c : line) {
            if (c != '\t' && (c < 0x20 || c > 0x7e)) {
                return fail(context + "not strict ASCII text");
            }
        }
        line = trim(line.substr(0, line.find('#')));
        if (line.empty()) continue;
        const size_t separator = line.find('=');
        if (separator == std::string_view::npos) {
            return fail(context + "must be key=value");
        }
        const std::string key(trim(line.substr(0, separator)));
        const std::string_view value = trim(line.substr(separator + 1));
        if (allowed.count(key) == 0) {
            return fail(context + "unknown key: " + key);
        }
        if (!values.emplace(key, value).second) {
            return fail(context + "duplicate key: " + key);
        }
    }
    // Presence, not a nonzero value, proves that even zero-valued layouts were supplied.
    for (const auto& key : required) {
        if (values.count(key) == 0) {
            return fail("Missing required configuration key: " + key);
        }
    }

    const auto integer = [&](const std::string& key, uint64_t minimum, uint64_t maximum,
                             uint64_t alignment, uint64_t& number) {
        if (!unsigned_value(values.at(key), number) || number < minimum || number > maximum ||
            number % alignment != 0) {
            return fail("Invalid unsigned integer or range/alignment for configuration key: " + key);
        }
        return true;
    };
    const auto hex = [&](const std::string& key, size_t minimum, size_t maximum,
                         size_t alignment, std::string& output) {
        const std::string_view value = values.at(key);
        const size_t bytes = value.size() / 2;
        if (value.size() % 2 != 0 || bytes < minimum || bytes > maximum || bytes % alignment != 0) {
            return fail("Invalid hex length for configuration key: " + key);
        }
        for (unsigned char c : value) {
            if (hex_digit(c) < 0) {
                return fail("Invalid hex text for configuration key: " + key);
            }
        }
        output.assign(value.data(), value.size());
        for (char& c : output) {
            if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
        }
        return true;
    };

    Config parsed;
    uint64_t number = 0;
    if (!integer("stable_window_confirmed", 1, 1, 1, number)) return false;
    parsed.stable_window_confirmed = true;
    const std::string_view name = values.at("profile.name");
    if (name.empty()) return fail("profile.name must be nonempty");
    parsed.profile.name.assign(name.data(), name.size());
    if (values.count("profile.analysis_sha256") != 0 &&
        !hex("profile.analysis_sha256", 32, 32, 1, parsed.profile.analysis_sha256)) {
        return false;
    }
    const uint64_t max_rva = std::numeric_limits<uintptr_t>::max();
    if (!integer("registry.hot.rva", 1, max_rva, 8, number)) return false;
    parsed.profile.hot_registry_rva = static_cast<uintptr_t>(number);
    if (!integer("registry.aot_vector.rva", 1, max_rva, 8, number)) return false;
    parsed.profile.aot_vector_rva = static_cast<uintptr_t>(number);
    for (size_t i = 0; i < profile::FunctionCount; ++i) {
        const std::string prefix = std::string("function.") + profile::kFunctions[i].name;
        auto& function = parsed.profile.functions[i];
        if (!integer(prefix + ".rva", 1, max_rva, 4, number)) return false;
        function.rva = static_cast<uintptr_t>(number);
        if (!integer(prefix + ".fingerprint_length", 4, 4096, 4, number)) return false;
        function.fingerprint_length = static_cast<size_t>(number);
        if (!hex(prefix + ".sha256", 32, 32, 1, function.fingerprint_sha256)) return false;
    }
    for (size_t i = 0; i < profile::EvidenceCount; ++i) {
        const std::string prefix = std::string("evidence.") + profile::kEvidenceNames[i];
        auto& evidence = parsed.profile.evidence[i];
        if (!integer(prefix + ".rva", 1, max_rva, 4, number)) return false;
        evidence.rva = static_cast<uintptr_t>(number);
        if (!hex(prefix + ".bytes_hex", 4, 1024, 4, evidence.bytes_hex)) return false;
    }
    for (const auto& layout : profile::kLayouts) {
        if (!integer(std::string("layout.") + layout.name, 0, 65536, layout.alignment, number)) {
            return false;
        }
        parsed.profile.layout.*layout.member = static_cast<size_t>(number);
    }

    if (values.count("module_name") != 0) {
        const auto value = values.at("module_name");
        parsed.module_name.assign(value.data(), value.size());
    }
    if (parsed.module_name.empty() || parsed.module_name == "." || parsed.module_name == "..") {
        return fail("module_name must be a nonempty module basename");
    }
    for (unsigned char c : parsed.module_name) {
        if (c <= 0x20 || c == 0x7f || c == '/' || c == '\\') {
            return fail("module_name must be a basename without whitespace or controls");
        }
    }
    if (values.count("initialization_timeout_seconds") != 0) {
        if (!integer("initialization_timeout_seconds", 0, 3600, 1, number)) return false;
        if (number != 0) parsed.initialization_timeout_seconds = static_cast<uint32_t>(number);
    }
    if (values.count("chunk_size") != 0) {
        if (!integer("chunk_size", 0, 1024u * 1024u, 1, number)) return false;
        if (number != 0) {
            if (number < 64u * 1024u) return fail("chunk_size must be between 64 KiB and 1 MiB");
            parsed.chunk_size = static_cast<uint32_t>(number);
        }
    }
    if (values.count("max_file_size") != 0) {
        if (!integer("max_file_size", 0, UINT32_MAX, 1, number)) return false;
        if (number != 0) parsed.max_file_size = number;
    }
    if (values.count("dump_pdb") != 0) {
        if (!integer("dump_pdb", 0, 1, 1, number)) return false;
        parsed.dump_pdb = number == 1;
    }
    parsed.output_directory = path.substr(0, path.find_last_of('/')) + "/hybridclr_dll_dump";
    if (values.count("output_directory") != 0) {
        const auto value = values.at("output_directory");
        parsed.output_directory.assign(value.data(), value.size());
    }
    if (!absolute_path(parsed.output_directory, true)) {
        return fail("output_directory must be an absolute path without controls or '..' components");
    }
    parsed.config_path = path;
    parsed.config_sha256 = sha256(content.data(), content.size());
    config = std::move(parsed);
    return true;
}

} // namespace hcd
