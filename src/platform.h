#pragma once

#include "profile.h"

#include <cstddef>
#include <cstdint>
#include <elf.h>
#include <string>
#include <vector>

namespace hcd {

void log(const char* format, ...) __attribute__((format(printf, 1, 2)));
uintptr_t untag(uintptr_t address);
bool same_pointer(uintptr_t a, uintptr_t b);
std::string pointer_text(uintptr_t address);
std::string json_string(const std::string& value);
bool make_directories(const std::string& path, std::string& error);
bool write_all(int fd, const void* data, size_t size, size_t& written);

struct Config {
    std::string config_path;
    std::string config_sha256;
    profile::RuntimeProfile profile;
    std::string output_directory;
    std::string module_name = "libil2cpp.so";
    bool stable_window_confirmed = false;
    bool dump_pdb = true;
    uint32_t chunk_size = 256 * 1024;
    uint32_t initialization_timeout_seconds = 30;
    uint64_t max_file_size = 512ull * 1024 * 1024;
};

struct Mapping {
    uintptr_t begin;
    uintptr_t end;
    bool readable;
    bool executable;
};

class Memory {
public:
    Memory();
    ~Memory();
    Memory(const Memory&) = delete;
    Memory& operator=(const Memory&) = delete;
    bool refresh(std::string& error);
    bool readable(uintptr_t address, size_t size) const;
    bool executable(uintptr_t address, size_t size) const;
    /* Failure-reporting reads for descriptors; no direct dereference on failure. */
    bool read(uintptr_t address, void* out, size_t size) const;
    /* Retains the original Android pointer tag when calling libc memcpy. */
    bool copy_payload(uintptr_t address, void* out, size_t size) const;
    bool read_string(uintptr_t address, std::string& out, size_t limit = 1024) const;
    template<typename T> bool value(uintptr_t address, T& out) const {
        return read(address, &out, sizeof(out));
    }

private:
    bool covers(uintptr_t address, size_t size, bool require_exec) const;
    int mem_fd_ = -1;
    std::vector<Mapping> maps_;
};

class Module {
public:
    bool find(const std::string& name, std::string& error);
    bool initialize_symbols(const Memory& memory, std::string& error);
    uintptr_t symbol(const Memory& memory, const char* name) const;
    bool contains(uintptr_t address, size_t size, bool executable = false) const;
    uintptr_t at(uintptr_t rva) const;
    uintptr_t bias = 0;
    std::string path;
    std::string build_id;

private:
    uintptr_t dynamic_address(uintptr_t value) const;
    uintptr_t match_symbol(const Memory& memory, uint32_t index, const char* name) const;
    std::vector<Elf64_Phdr> phdrs_;
    uintptr_t symtab_ = 0;
    uintptr_t strtab_ = 0;
    size_t strsz_ = 0;
    uintptr_t sysv_hash_ = 0;
    uintptr_t gnu_hash_ = 0;
};

} // namespace hcd
