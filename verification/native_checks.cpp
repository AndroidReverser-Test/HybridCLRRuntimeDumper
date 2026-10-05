#include "../src/config.h"
#include "../src/format.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <memory>
#include <string_view>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

namespace {
struct TemporaryConfig {
    std::string path;
    int fd = -1;
    ~TemporaryConfig() {
        if (fd >= 0) ::close(fd);
        if (!path.empty()) ::unlink(path.c_str());
    }
};

bool read_file(const char* path, size_t maximum, std::vector<uint8_t>& bytes) {
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return false;
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(::fdopen(fd, "rb"), &std::fclose);
    if (!file) { ::close(fd); return false; }
    struct stat info{};
    if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size < 0 ||
        static_cast<uint64_t>(info.st_size) > maximum) return false;
    bytes.resize(static_cast<size_t>(info.st_size));
    return std::fread(bytes.data(), 1, bytes.size(), file.get()) == bytes.size() &&
           !std::ferror(file.get()) && std::fgetc(file.get()) == EOF && !std::ferror(file.get());
}
} // namespace

int main(int argc, char** argv) {
    unsigned passed = 0, failed = 0;
    const auto check = [&](const char* name, bool ok, const std::string& detail = "") {
        if (ok) ++passed;
        else {
            ++failed;
            std::printf("FAIL %s%s%s\n", name, detail.empty() ? "" : ": ", detail.c_str());
        }
    };
    const auto finish = [&] { std::printf("PASS %u FAIL %u\n", passed, failed); return failed ? 1 : 0; };
    try {
        if (argc != 4) {
            std::printf("Usage: %s config_path DLL_path metadata_table_header_file_offset\n", argv[0]);
            check("arguments", false);
            return finish();
        }
        std::string_view number(argv[3]);
        int base = 10;
        if (number.substr(0, 2) == "0x" || number.substr(0, 2) == "0X") { base = 16; number.remove_prefix(2); }
        size_t table = 0;
        const auto parsed = std::from_chars(number.data(), number.data() + number.size(), table, base);
        if (number.empty() || parsed.ec != std::errc{} || parsed.ptr != number.data() + number.size()) {
            check("offset", false, "expected an unsigned decimal or hexadecimal file offset");
            return finish();
        }
        hcd::Config config;
        std::string error;
        const bool loaded = hcd::load_config(argv[1], config, error);
        const bool baseline_ok = loaded && !config.stable_window_confirmed && config.allow_ungated_capture;
        check("config baseline stable=0 allow=1", baseline_ok && !config.automatic_discovery &&
              config.profile.layout.assembly_image == 0, error);
        if (!baseline_ok) return finish();
        std::vector<uint8_t> config_bytes, dll;
        if (!read_file(argv[1], 64u * 1024u, config_bytes) || !read_file(argv[2], 512u * 1024u * 1024u, dll)) {
            check("read inputs", false, "expected readable regular config <=64 KiB and DLL <=512 MiB");
            return finish();
        }
        if (dll.size() < 64 || table > dll.size() || dll.size() - table < 24) {
            check("mutation bounds", false, "DLL must contain the complete 24-byte tables header");
            return finish();
        }
        const auto baseline = hcd::inspect_file(dll.data(), dll.size(), false);
        check("DLL unchanged DOTween", baseline.valid && baseline.assembly_name == "DOTween", baseline.reason);
        if (!baseline.valid || baseline.assembly_name != "DOTween") return finish();
        if (dll[table + 4] != 2 || dll[table + 5] != 0 || dll[table + 7] != 0x0a) {
            check("Cecil fixture header", false, "expected version 2.0 and Reserved2=0x0a at supplied offset");
            return finish();
        }
        const auto dll_check = [&](const char* name, const std::vector<uint8_t>& bytes, bool accepted,
                                   const char* reason = nullptr) {
            const auto info = hcd::inspect_file(bytes.data(), bytes.size(), false);
            check(name, info.valid == accepted && (!accepted || (info.assembly_name == baseline.assembly_name &&
                  info.mvid == baseline.mvid)) && (!reason || info.reason == reason), info.reason);
        };
        auto changed = dll;
        changed[table + 7] = 1;
        dll_check("DLL Reserved2=1", changed, true);
        changed = dll;
        std::fill_n(changed.data() + table + 16, 8, uint8_t{0});
        dll_check("DLL Sorted cleared", changed, true);
        changed = dll;
        // Valid is the little-endian mask at +8, not the Sorted mask at +16.
        changed[table + 8 + 45 / 8] |= static_cast<uint8_t>(1u << (45 % 8));
        dll_check("DLL Valid bit45", changed, false, "Unsupported metadata table outside 0..44");
        changed = dll;
        changed[table] = 1;
        dll_check("DLL reserved DWORD", changed, false, "Unsupported metadata tables header layout");
        changed = dll;
        changed[0] = 0;
        dll_check("DLL corrupted MZ", changed, false, "Missing or truncated MZ header");
        changed = dll;
        changed.resize(16);
        dll_check("DLL severely truncated", changed, false, "Missing or truncated MZ header");

        const std::string text(config_bytes.begin(), config_bytes.end());
        const auto mutate = [](std::string source, std::string_view key, const char* value) {
            for (size_t start = 0; start < source.size();) {
                size_t end = source.find('\n', start);
                if (end == std::string::npos) end = source.size();
                const std::string_view line(source.data() + start, end - start);
                const size_t equal = line.find('=');
                const auto candidate = line.substr(0, equal);
                const size_t first = candidate.find_first_not_of(" \t"), last = candidate.find_last_not_of(" \t");
                if (equal != std::string_view::npos && first != std::string_view::npos &&
                    candidate.substr(first, last - first + 1) == key) {
                    source.replace(start, end - start + (end < source.size() ? 1 : 0),
                                   value ? std::string(key) + "=" + value + "\n" : "");
                    return source;
                }
                start = end < source.size() ? end + 1 : end;
            }
            return std::string{};
        };
        const std::string parent = std::string(argv[1]).substr(0, std::string(argv[1]).find_last_of('/'));
        unsigned counter = 0;
        const auto config_check = [&](const char* name, const std::string& content, bool accepted,
                                      bool stable = true, bool automatic = false) {
            if (content.empty()) { check(name, false, "mutation key not found"); return; }
            TemporaryConfig temporary;
            for (unsigned attempt = 0; attempt < 128; ++attempt) {
                std::string candidate = parent + "/.hcd-native-checks-" + std::to_string(::getpid()) +
                                        "-" + std::to_string(counter++) + ".conf";
                temporary.fd = ::open(candidate.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
                if (temporary.fd >= 0) { temporary.path.swap(candidate); break; }
                if (errno != EEXIST && errno != EINTR) break;
            }
            if (temporary.fd < 0) { check(name, false, std::strerror(errno)); return; }
            size_t written = 0;
            if (!hcd::write_all(temporary.fd, content.data(), content.size(), written)) {
                check(name, false, "cannot write temporary configuration");
                return;
            }
            hcd::Config result;
            std::string reason;
            const bool valid = hcd::load_config(temporary.path, result, reason);
            const bool removed = ::unlink(temporary.path.c_str()) == 0;
            if (removed) temporary.path.clear();
            check(name, valid == accepted && (!accepted || (result.stable_window_confirmed == stable &&
                   result.allow_ungated_capture == !stable && result.automatic_discovery == automatic)) && removed,
                   removed ? reason : "temporary cleanup failed");
        };
        config_check("config missing opt-in", mutate(text, "allow_ungated_capture", nullptr), false);
        config_check("config allow=0", mutate(text, "allow_ungated_capture", "0"), false);
        config_check("config stable=2", mutate(text, "stable_window_confirmed", "2"), false);
        config_check("config stable=1 allow=0", mutate(mutate(text, "stable_window_confirmed", "1"),
                     "allow_ungated_capture", "0"), true);
        config_check("config missing layout.class_image", mutate(text, "layout.class_image", nullptr), false);
        config_check("config malformed bool", mutate(text, "allow_ungated_capture", "true"), false);
        config_check("config duplicate key", text + "\nallow_ungated_capture=1\n", false);
        const std::string automatic = "discovery_mode=auto\nstable_window_confirmed=0\nallow_ungated_capture=1\ndump_pdb=0\n";
        config_check("auto minimal no RVAs or layouts", automatic, true, false, true);
        config_check("auto real gate declaration", "discovery_mode=auto\nstable_window_confirmed=1\n", true, true, true);
        config_check("auto no gate opt-in", "discovery_mode=auto\nstable_window_confirmed=0\n", false);
        config_check("auto mixed legacy profile", text + "\ndiscovery_mode=auto\n", false);
        config_check("auto mixed zero layout", automatic + "layout.assembly_image=0\n", false);
        config_check("auto mixed registry", automatic + "registry.hot.rva=0x1000\n", false);
        config_check("auto mixed function", automatic + "function.il2cpp_domain_get.rva=0x1000\n", false);
        config_check("auto bad mode", mutate(automatic, "discovery_mode", "guess"), false);
        config_check("auto missing stable", mutate(automatic, "stable_window_confirmed", nullptr), false);
        config_check("auto invalid boolean", mutate(automatic, "dump_pdb", "2"), false);
        config_check("auto duplicate mode", automatic + "discovery_mode=auto\n", false);
        config_check("profile mode explicit", mutate(mutate(text, "stable_window_confirmed", "1"),
                     "allow_ungated_capture", "0") + "discovery_mode=profile\n", true);
        config_check("profile optional assembly field", mutate(mutate(text, "stable_window_confirmed", "1"),
                     "allow_ungated_capture", "0") + "layout.assembly_image=8\n", true);

        hcd::Memory memory;
        const size_t page_size = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
        void* page = ::mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED) { check("payload mmap fixture", false, std::strerror(errno)); return finish(); }
        std::memset(page, 0x5a, page_size);
        uint64_t payload = 0;
        check("payload live kernel read", memory.refresh(error) &&
            memory.copy_payload(reinterpret_cast<uintptr_t>(page), &payload, sizeof(payload)) && payload == UINT64_C(0x5a5a5a5a5a5a5a5a), error);
        check("payload tagged kernel read", memory.copy_payload(reinterpret_cast<uintptr_t>(page) |
            UINT64_C(0xb400000000000000), &payload, sizeof(payload)) && payload == UINT64_C(0x5a5a5a5a5a5a5a5a));
        const bool unmapped = ::munmap(page, page_size) == 0;
        check("payload stale VMA returns failure without memcpy fault", unmapped &&
            !memory.copy_payload(reinterpret_cast<uintptr_t>(page), &payload, sizeof(payload)));
    } catch (const std::exception& exception) { check("exception", false, exception.what()); }
    return finish();
}
