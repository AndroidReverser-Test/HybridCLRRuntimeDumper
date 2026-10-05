#include "platform.h"

#include <android/log.h>
#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <link.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#include <utility>

namespace hcd {

static_assert(sizeof(uintptr_t) == 8, "The verified profile requires ARM64 LP64.");

void log(const char* format, ...) {
    va_list args;
    va_start(args, format);
    __android_log_vprint(ANDROID_LOG_INFO, "HybridCLRDump", format, args);
    va_end(args);
}

uintptr_t untag(uintptr_t address) {
    // Android ARM64 TBI allocation tags only; this is not PAC authentication.
    return address & UINT64_C(0x00ffffffffffffff);
}

bool same_pointer(uintptr_t a, uintptr_t b) { return untag(a) == untag(b); }

std::string pointer_text(uintptr_t address) {
    char buffer[24];
    std::snprintf(buffer, sizeof(buffer), "0x%016llx", static_cast<unsigned long long>(address));
    return buffer;
}

std::string json_string(const std::string& value) {
    std::string result = "\"";
    constexpr const char* digits = "0123456789abcdef";
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') {
            result += '\\';
            result += static_cast<char>(c);
        } else if (c < 0x20) {
            result += "\\u00";
            result += digits[c >> 4];
            result += digits[c & 15];
        } else {
            result += static_cast<char>(c);
        }
    }
    result += '"';
    return result;
}

bool make_directories(const std::string& path, std::string& error) {
    if (path.empty() || path.front() != '/') {
        error = "Output directory must be absolute";
        return false;
    }
    size_t position = 1;
    while (position <= path.size()) {
        size_t slash = path.find('/', position);
        size_t end = slash == std::string::npos ? path.size() : slash;
        std::string component = path.substr(position, end - position);
        if (component == "..") {
            error = "Parent-directory components are not allowed";
            return false;
        }
        if (!component.empty()) {
            std::string prefix = path.substr(0, end);
            if (::mkdir(prefix.c_str(), 0700) != 0 && errno != EEXIST) {
                error = "mkdir " + prefix + ": " + std::strerror(errno);
                return false;
            }
            struct stat st{};
            if (::stat(prefix.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
                error = "Not a directory: " + prefix;
                return false;
            }
        }
        if (slash == std::string::npos) break;
        position = slash + 1;
    }
    return true;
}

bool write_all(int fd, const void* data, size_t size, size_t& written) {
    written = 0;
    const auto* bytes = static_cast<const uint8_t*>(data);
    while (written < size) {
        size_t length = std::min(size - written, static_cast<size_t>(SSIZE_MAX));
        ssize_t n = ::write(fd, bytes + written, length);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        written += static_cast<size_t>(n);
    }
    return true;
}

Memory::Memory() { mem_fd_ = ::open("/proc/self/mem", O_RDONLY | O_CLOEXEC); }
Memory::~Memory() { if (mem_fd_ >= 0) ::close(mem_fd_); }

bool Memory::refresh(std::string& error) {
    FILE* file = std::fopen("/proc/self/maps", "r");
    if (!file) {
        error = "Cannot open /proc/self/maps: " + std::string(std::strerror(errno));
        return false;
    }
    std::vector<Mapping> maps;
    char* line = nullptr;
    size_t capacity = 0;
    while (::getline(&line, &capacity, file) >= 0) {
        unsigned long begin = 0, end = 0;
        char permissions[5]{};
        if (std::sscanf(line, "%lx-%lx %4s", &begin, &end, permissions) == 3 && begin < end) {
            maps.push_back({begin, end, permissions[0] == 'r', permissions[2] == 'x'});
        }
    }
    bool ok = !std::ferror(file) && !maps.empty();
    std::free(line);
    std::fclose(file);
    if (!ok) {
        error = "Failed to read the process mapping list";
        return false;
    }
    std::sort(maps.begin(), maps.end(), [](const Mapping& a, const Mapping& b) {
        return a.begin < b.begin;
    });
    maps_ = std::move(maps);
    return true;
}

bool Memory::covers(uintptr_t address, size_t size, bool require_exec) const {
    uintptr_t cursor = untag(address);
    if (size > UINT64_C(0x00ffffffffffffff) - cursor) return false;
    if (size == 0) return true;
    uintptr_t end = cursor + size;
    for (const auto& map : maps_) {
        if (map.end <= cursor) continue;
        if (map.begin > cursor || !map.readable || (require_exec && !map.executable)) return false;
        cursor = std::min(end, map.end);
        if (cursor == end) return true;
    }
    return false;
}

bool Memory::readable(uintptr_t address, size_t size) const { return covers(address, size, false); }
bool Memory::executable(uintptr_t address, size_t size) const { return covers(address, size, true); }

bool Memory::read(uintptr_t address, void* out, size_t size) const {
    if (!readable(address, size)) return false;
    size_t copied = 0;
    uintptr_t base = untag(address);
    auto* bytes = static_cast<uint8_t*>(out);
    while (copied < size) {
        size_t length = std::min(size - copied, static_cast<size_t>(SSIZE_MAX));
        iovec local{bytes + copied, length};
        iovec remote{reinterpret_cast<void*>(base + copied), length};
        ssize_t n = ::syscall(SYS_process_vm_readv, ::getpid(), &local, 1, &remote, 1, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        copied += static_cast<size_t>(n);
    }
    while (copied < size && mem_fd_ >= 0) {
        size_t length = std::min(size - copied, static_cast<size_t>(SSIZE_MAX));
        ssize_t n = ::pread(mem_fd_, bytes + copied, length, static_cast<off_t>(base + copied));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        copied += static_cast<size_t>(n);
    }
    return copied == size;
}

bool Memory::copy_payload(uintptr_t address, void* out, size_t size) const {
    return read(address, out, size);
}

bool Memory::read_string(uintptr_t address, std::string& out, size_t limit) const {
    out.clear();
    if (!address || limit > 1024 * 1024 || limit > UINT64_C(0x00ffffffffffffff) - untag(address))
        return false;
    for (size_t i = 0; i < limit; ++i) {
        char c;
        if (!value(address + i, c)) return false;
        if (c == '\0') return true;
        out.push_back(c);
    }
    return false;
}

uintptr_t Module::at(uintptr_t rva) const {
    return rva <= std::numeric_limits<uintptr_t>::max() - bias ? bias + rva : 0;
}

bool Module::find(const std::string& name, std::string& error) {
    struct Search {
        const std::string* name;
        Module* module;
        size_t matches = 0;
    } search{&name, this, 0};
    ::dl_iterate_phdr([](dl_phdr_info* info, size_t, void* data) -> int {
        auto& s = *static_cast<Search*>(data);
        const char* full = info->dlpi_name;
        if (!full || !*full || !info->dlpi_phdr || info->dlpi_phnum > 1024) return 0;
        const char* slash = std::strrchr(full, '/');
        const char* base = slash ? slash + 1 : full;
        bool matches = s.name->find('/') == std::string::npos ? *s.name == base : *s.name == full;
        if (!matches) return 0;
        ++s.matches;
        s.module->bias = info->dlpi_addr;
        s.module->path = full;
        s.module->phdrs_.assign(info->dlpi_phdr, info->dlpi_phdr + info->dlpi_phnum);
        return 0;
    }, &search);
    if (search.matches != 1) {
        error = search.matches == 0 ? "Module not loaded: " + name : "Ambiguous module name: " + name;
        return false;
    }
    return true;
}

bool Module::contains(uintptr_t address, size_t size, bool executable) const {
    if (!address || size > std::numeric_limits<uintptr_t>::max() - address) return false;
    for (const auto& ph : phdrs_) {
        if (ph.p_type != PT_LOAD || !(ph.p_flags & PF_R) || (executable && !(ph.p_flags & PF_X)))
            continue;
        uintptr_t begin = at(ph.p_vaddr);
        if (!begin || ph.p_memsz > std::numeric_limits<uintptr_t>::max() - begin) continue;
        uintptr_t end = begin + ph.p_memsz;
        if (address >= begin && address <= end && size <= end - address) return true;
    }
    return false;
}

uintptr_t Module::dynamic_address(uintptr_t value) const {
    if (contains(value, 1)) return value;
    uintptr_t relocated = at(value);
    return contains(relocated, 1) ? relocated : 0;
}

bool Module::initialize_symbols(const Memory& memory, std::string& error) {
    Elf64_Ehdr header{};
    if (!memory.value(at(0), header) || std::memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 ||
        header.e_ident[EI_CLASS] != ELFCLASS64 || header.e_ident[EI_DATA] != ELFDATA2LSB ||
        header.e_machine != EM_AARCH64) {
        error = "The runtime module is not a readable little-endian AArch64 ELF";
        return false;
    }
    symtab_ = strtab_ = sysv_hash_ = gnu_hash_ = 0;
    strsz_ = 0;
    size_t syment = sizeof(Elf64_Sym);
    for (const auto& ph : phdrs_) {
        if (ph.p_type == PT_NOTE && ph.p_memsz <= 1024 * 1024) {
            std::vector<uint8_t> notes(static_cast<size_t>(ph.p_memsz));
            if (memory.read(at(ph.p_vaddr), notes.data(), notes.size())) {
                size_t cursor = 0;
                while (cursor + sizeof(Elf64_Nhdr) <= notes.size()) {
                    Elf64_Nhdr note;
                    std::memcpy(&note, notes.data() + cursor, sizeof(note));
                    cursor += sizeof(note);
                    uint64_t name_size = (uint64_t(note.n_namesz) + 3) & ~UINT64_C(3);
                    uint64_t desc_size = (uint64_t(note.n_descsz) + 3) & ~UINT64_C(3);
                    if (name_size > notes.size() - cursor || desc_size > notes.size() - cursor - name_size)
                        break;
                    if (note.n_type == NT_GNU_BUILD_ID && note.n_namesz == 4 &&
                        std::memcmp(notes.data() + cursor, "GNU\0", 4) == 0) {
                        constexpr const char* digits = "0123456789abcdef";
                        build_id.clear();
                        for (size_t i = 0; i < note.n_descsz; ++i) {
                            uint8_t b = notes[cursor + static_cast<size_t>(name_size) + i];
                            build_id += digits[b >> 4];
                            build_id += digits[b & 15];
                        }
                    }
                    cursor += static_cast<size_t>(name_size + desc_size);
                }
            }
        }
        if (ph.p_type != PT_DYNAMIC) continue;
        if (ph.p_memsz > 1024 * 1024) {
            error = "Oversized ELF dynamic table";
            return false;
        }
        bool terminated = false;
        for (size_t offset = 0; offset + sizeof(Elf64_Dyn) <= ph.p_memsz; offset += sizeof(Elf64_Dyn)) {
            Elf64_Dyn dyn{};
            if (!memory.value(at(ph.p_vaddr) + offset, dyn)) {
                error = "Unreadable ELF dynamic table";
                return false;
            }
            if (dyn.d_tag == DT_NULL) { terminated = true; break; }
            switch (dyn.d_tag) {
                case DT_SYMTAB: symtab_ = dynamic_address(dyn.d_un.d_ptr); break;
                case DT_STRTAB: strtab_ = dynamic_address(dyn.d_un.d_ptr); break;
                case DT_STRSZ: strsz_ = dyn.d_un.d_val; break;
                case DT_SYMENT: syment = dyn.d_un.d_val; break;
                case DT_HASH: sysv_hash_ = dynamic_address(dyn.d_un.d_ptr); break;
                case DT_GNU_HASH: gnu_hash_ = dynamic_address(dyn.d_un.d_ptr); break;
                default: break;
            }
        }
        if (!terminated) { error = "Unterminated ELF dynamic table"; return false; }
    }
    if (symtab_ && (syment != sizeof(Elf64_Sym) || !strtab_ || !strsz_ ||
                    !contains(strtab_, strsz_))) {
        error = "Invalid runtime ELF symbol/string table";
        return false;
    }
    return true;
}

uintptr_t Module::match_symbol(const Memory& memory, uint32_t index, const char* name) const {
    constexpr uint32_t limit = 1024 * 1024;
    if (!symtab_ || index >= limit) return 0;
    uintptr_t address = symtab_ + uint64_t(index) * sizeof(Elf64_Sym);
    Elf64_Sym sym{};
    if (!contains(address, sizeof(sym)) || !memory.value(address, sym) ||
        sym.st_shndx == SHN_UNDEF || sym.st_shndx >= SHN_LORESERVE || sym.st_name >= strsz_ ||
        ELF64_ST_TYPE(sym.st_info) != STT_FUNC ||
        (ELF64_ST_BIND(sym.st_info) != STB_GLOBAL && ELF64_ST_BIND(sym.st_info) != STB_WEAK) ||
        ((sym.st_other & 0x3u) != STV_DEFAULT &&
         (sym.st_other & 0x3u) != STV_PROTECTED)) return 0;
    std::string candidate;
    size_t name_limit = std::min(strsz_ - sym.st_name, std::strlen(name) + 1);
    if (!memory.read_string(strtab_ + sym.st_name, candidate, name_limit) || candidate != name) return 0;
    uintptr_t result = at(sym.st_value);
    return contains(result, 4, true) && memory.executable(result, 4) ? result : 0;
}

uintptr_t Module::symbol(const Memory& memory, const char* name) const {
    constexpr uint32_t limit = 1024 * 1024;
    if (!symtab_ || !strtab_) return 0;
    if (sysv_hash_) {
        uint32_t header[2]{};
        if (!contains(sysv_hash_, sizeof(header)) || !memory.read(sysv_hash_, header, sizeof(header))) return 0;
        uint32_t buckets = header[0], chains = header[1];
        if (!buckets || buckets > limit || !chains || chains > limit ||
            !contains(sysv_hash_, (uint64_t(2) + buckets + chains) * 4)) return 0;
        uint32_t hash = 0;
        for (const auto* p = reinterpret_cast<const unsigned char*>(name); *p; ++p) {
            hash = (hash << 4) + *p;
            uint32_t high = hash & 0xf0000000u;
            if (high) hash ^= high >> 24;
            hash &= ~high;
        }
        uint32_t index = 0;
        if (!memory.value(sysv_hash_ + 8 + uint64_t(hash % buckets) * 4, index)) return 0;
        for (uint32_t attempts = 0; index && index < chains && attempts < chains; ++attempts) {
            uintptr_t match = match_symbol(memory, index, name);
            if (match) return match;
            if (!memory.value(sysv_hash_ + 8 + uint64_t(buckets + index) * 4, index)) return 0;
        }
    }
    if (gnu_hash_) {
        uint32_t header[4]{};
        if (!contains(gnu_hash_, sizeof(header)) || !memory.read(gnu_hash_, header, sizeof(header))) return 0;
        uint32_t buckets = header[0], first = header[1], bloom = header[2];
        if (!buckets || buckets > limit || first >= limit || !bloom || bloom > limit) return 0;
        uintptr_t bucket_base = gnu_hash_ + 16 + uint64_t(bloom) * 8;
        uintptr_t chain_base = bucket_base + uint64_t(buckets) * 4;
        if (!contains(bucket_base, uint64_t(buckets) * 4)) return 0;
        uint32_t hash = 5381;
        for (const auto* p = reinterpret_cast<const unsigned char*>(name); *p; ++p) hash = hash * 33 + *p;
        uint32_t index = 0;
        if (!memory.value(bucket_base + uint64_t(hash % buckets) * 4, index) || !index || index < first) return 0;
        for (; index < limit; ++index) {
            uint32_t chain = 0;
            uintptr_t address = chain_base + uint64_t(index - first) * 4;
            if (!contains(address, sizeof(chain)) || !memory.value(address, chain)) return 0;
            if ((chain | 1u) == (hash | 1u)) {
                uintptr_t match = match_symbol(memory, index, name);
                if (match) return match;
            }
            if (chain & 1u) break;
        }
    }
    return 0;
}

} // namespace hcd
