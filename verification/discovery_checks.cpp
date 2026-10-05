#include "../src/discovery.h"
#include "../src/format.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <exception>
#include <limits>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

namespace {
using hcd::discovery_detail::Reader;
constexpr uint32_t kRet = 0xd65f03c0u, kNop = 0xd503201fu, kBti = 0xd503245fu;

unsigned size_code(unsigned width) {
    switch (width) { case 1: return 0; case 2: return 1; case 4: return 2; case 8: return 3; }
    throw std::runtime_error("bad fixture instruction width");
}
uint32_t mov(unsigned rd, unsigned rn, unsigned width = 8) {
    return (width == 8 ? 0xaa0003e0u : 0x2a0003e0u) | (rn << 16) | rd;
}
uint32_t immediate(unsigned rd, unsigned n, unsigned width = 8) {
    return (width == 8 ? 0xd2800000u : 0x52800000u) | (n << 5) | rd;
}
uint32_t add(unsigned rd, unsigned rn, unsigned n) { return 0x91000000u | (n << 10) | (rn << 5) | rd; }
uint32_t add_reg(unsigned rd, unsigned rn, unsigned rm) { return 0x8b000000u | (rm << 16) | (rn << 5) | rd; }
uint32_t load(unsigned rd, unsigned rn, unsigned offset, unsigned width = 8) {
    if (offset % width) throw std::runtime_error("unaligned fixture load");
    return 0x39400000u | (size_code(width) << 30) | ((offset / width) << 10) | (rn << 5) | rd;
}
uint32_t store(unsigned rd, unsigned rn, unsigned offset, unsigned width = 8) {
    if (offset % width) throw std::runtime_error("unaligned fixture store");
    return 0x39000000u | (size_code(width) << 30) | ((offset / width) << 10) | (rn << 5) | rd;
}
uint32_t load_register(unsigned rd, unsigned rn, unsigned rm, unsigned width, bool scaled, bool uxtw = false) {
    return 0x38600800u | (size_code(width) << 30) | (rm << 16) |
           ((uxtw ? 2u : 3u) << 13) | (scaled ? 0x1000u : 0) | (rn << 5) | rd;
}
uint32_t load_post(unsigned rd, unsigned rn, unsigned stride) { return 0xf8400400u | (stride << 12) | (rn << 5) | rd; }
uint32_t pair_load(unsigned rd, unsigned rt2, unsigned rn, unsigned offset = 0) {
    return 0xa9400000u | ((offset / 8) << 15) | (rt2 << 10) | (rn << 5) | rd;
}
uint32_t pair_store(unsigned rd, unsigned rt2, unsigned rn, unsigned offset = 0) {
    return 0xa9000000u | ((offset / 8) << 15) | (rt2 << 10) | (rn << 5) | rd;
}
uint32_t compare(unsigned rn, unsigned rm) { return 0xeb00001fu | (rm << 16) | (rn << 5); }
uint32_t shift_right(unsigned rd, unsigned rn, unsigned shift, unsigned width = 8) {
    return (width == 8 ? 0xd3400000u : 0x53000000u) | (shift << 16) |
           ((width * 8 - 1) << 10) | (rn << 5) | rd;
}
uint32_t and_twelve(unsigned rd, unsigned rn, unsigned width = 8) {
    return (width == 8 ? 0x92400000u : 0x12000000u) | ((width * 8 - 2) << 16) | (1u << 10) | (rn << 5) | rd;
}
uint32_t bic(unsigned rd, unsigned rn, unsigned rm) { return 0x0a200000u | (rm << 16) | (rn << 5) | rd; }
uint32_t branch(uintptr_t pc, uintptr_t target, bool link = false) {
    const int64_t delta = int64_t(target) - int64_t(pc);
    if (delta % 4 || delta < -(INT64_C(1) << 27) || delta >= (INT64_C(1) << 27)) throw std::runtime_error("bad fixture B");
    return (link ? 0x94000000u : 0x14000000u) | (uint32_t(delta / 4) & 0x3ffffffu);
}
uint32_t conditional(uintptr_t pc, uintptr_t target, unsigned cond) {
    const int64_t delta = int64_t(target) - int64_t(pc);
    if (delta % 4 || delta < -(INT64_C(1) << 20) || delta >= (INT64_C(1) << 20)) throw std::runtime_error("bad fixture B.cond");
    return 0x54000000u | ((uint32_t(delta / 4) & 0x7ffffu) << 5) | cond;
}
uint32_t adrp(uintptr_t pc, uintptr_t target, unsigned rd) {
    const int64_t pages = (int64_t(target & ~uintptr_t(4095)) - int64_t(pc & ~uintptr_t(4095))) / 4096;
    if (pages < -(INT64_C(1) << 20) || pages >= (INT64_C(1) << 20)) throw std::runtime_error("bad fixture ADRP");
    const uint32_t bits = uint32_t(pages) & 0x1fffffu;
    return 0x90000000u | ((bits & 3) << 29) | ((bits >> 2) << 5) | rd;
}

struct Segment {
    uintptr_t begin;
    std::vector<uint8_t> bytes;
    bool module, executable;
};
struct Fixture {
    std::vector<Segment> segments;
    uintptr_t code, data, object;
    uintptr_t failed_read = 0, denied_exec = 0, unstable_read = 0;
    mutable size_t reads = 0;
    mutable bool unstable_seen = false;
    explicit Fixture(uintptr_t base = UINT64_C(0x100000000), bool negative_adrp = false)
        : code(base + (negative_adrp ? 0x20000 : 0x1000)),
          data(base + (negative_adrp ? 0x1000 : 0x20000)), object(base + 0x90000) {
        segments.push_back({code, std::vector<uint8_t>(0x10000), true, true});
        segments.push_back({data, std::vector<uint8_t>(0x12000), true, false});
        segments.push_back({object, std::vector<uint8_t>(0x200), false, false});
    }
    const Segment* segment(uintptr_t p, size_t n) const {
        if (n > std::numeric_limits<uintptr_t>::max() - p) return nullptr;
        for (const auto& s : segments)
            if (p >= s.begin && p - s.begin <= s.bytes.size() && n <= s.bytes.size() - size_t(p - s.begin)) return &s;
        return nullptr;
    }
    void put(uintptr_t p, uint64_t n, size_t width) {
        for (auto& s : segments) {
            if (p >= s.begin && p - s.begin <= s.bytes.size() && width <= s.bytes.size() - size_t(p - s.begin)) {
                for (size_t i = 0; i < width; ++i) s.bytes[size_t(p - s.begin) + i] = uint8_t(n >> (8 * i));
                return;
            }
        }
        throw std::runtime_error("fixture write outside backing storage");
    }
    uint32_t word(uintptr_t p) const {
        const Segment* s = segment(p, 4);
        if (!s) throw std::runtime_error("fixture word outside backing storage");
        uint32_t w = 0;
        for (unsigned j = 0; j < 4; ++j) w |= uint32_t(s->bytes[size_t(p - s->begin) + j]) << (8 * j);
        return w;
    }
    Reader reader() const {
        return {this,
            [](const void* context, uintptr_t p, void* out, size_t n) {
                const auto& f = *static_cast<const Fixture*>(context);
                ++f.reads;
                if (f.failed_read && p <= f.failed_read && f.failed_read - p < n) return false;
                const Segment* s = f.segment(p, n);
                if (!s) return false;
                std::memcpy(out, s->bytes.data() + size_t(p - s->begin), n);
                if (f.unstable_read && p <= f.unstable_read && f.unstable_read - p < n) {
                    if (f.unstable_seen) static_cast<uint8_t*>(out)[f.unstable_read - p] ^= 1;
                    f.unstable_seen = true;
                }
                return true;
            },
            [](const void* context, uintptr_t p, size_t n, bool executable) {
                const auto& f = *static_cast<const Fixture*>(context);
                const Segment* s = f.segment(p, n);
                return s && s->module && (!executable || (s->executable &&
                    !(f.denied_exec && p <= f.denied_exec && f.denied_exec - p < n)));
            }};
    }
};
struct Assembly {
    Fixture& f;
    uintptr_t start;
    std::vector<uint32_t> words;
    uintptr_t pc() const { return start + words.size() * 4; }
    size_t emit(uint32_t w) { words.push_back(w); return words.size() - 1; }
    void patch_b(size_t slot, uintptr_t target, bool link = false) { words.at(slot) = branch(start + slot * 4, target, link); }
    void patch_cond(size_t slot, uintptr_t target, unsigned cond) { words.at(slot) = conditional(start + slot * 4, target, cond); }
    void address(unsigned reg, uintptr_t address, bool got, uintptr_t cell) {
        const uintptr_t source = got ? cell : address;
        emit(adrp(pc(), source, reg));
        emit(got ? load(reg, reg, unsigned(source & 4095)) : add(reg, reg, unsigned(source & 4095)));
        if (got) f.put(cell, address, 8);
    }
    void finish() { for (size_t j = 0; j < words.size(); ++j) f.put(start + j * 4, words[j], 4); }
};

struct RegistryOptions {
    bool got = true, scaled_selector = false, inline_vector = false, tail = false, wrapper = false;
    bool split_hot = false, duplicate_vector = false, duplicate_hot = false, large_unrelated = false, vector_padding = false;
    unsigned token = 8, index = 9, mask = 10, table = 9, image = 8;
    unsigned cursor = 8, end = 9, element = 20, target = 10, saved_assembly = 19;
    unsigned token_field = 0x54, owner_field = 0x28, target_field = 0xc0, class_image_field = 0;
};
struct RegistryFixture {
    Fixture f;
    RegistryOptions options;
    uintptr_t entry = 0, real_root = 0, hot = 0, vector = 0, masks = 0;
    uintptr_t shift_pc = 0, vector_back_pc = 0, stride_pc = 0, target_pc = 0, owner_pc = 0, hot_load_pc = 0;

    RegistryFixture(RegistryOptions o = {}, uintptr_t base = UINT64_C(0x100000000), bool negative = false)
        : f(base, negative), options(o) {
        entry = real_root = f.code + 0x100;
        masks = f.data + 0x80; vector = f.data + 0x160; hot = f.data + 0x2000;
        constexpr uint32_t table[] = {0x0fffffffu, 0x03ffffffu, 0x00ffffffu, 0x003fffffu};
        for (size_t j = 0; j < 4; ++j) f.put(masks + j * 4, table[j], 4);
        f.put(f.code + 0x7800, kRet, 4); // Opaque lock call, never executed or followed.
        const uintptr_t helper = f.code + 0x2400, other_helper = f.code + 0x3400;
        if (!o.inline_vector) {
            Assembly a{f, helper, {}};
            vector_body(a, vector, o.target_field);
            a.finish();
            if (o.duplicate_vector) {
                Assembly b{f, other_helper, {}};
                vector_body(b, vector + 0x40, o.target_field + 8);
                b.finish();
            }
        }
        uintptr_t call_helper = helper;
        if (o.tail) {
            Assembly tail{f, f.code + 0x6000, {}};
            tail.emit(kBti); tail.emit(kNop); tail.emit(branch(tail.pc(), helper)); tail.finish();
            call_helper = tail.start;
        }
        Assembly root{f, real_root, {}};
        root.emit(kBti);
        root.emit(0xf81e0ffeu); // STR X30, [SP, #-32]!
        root.emit(pair_store(20, 19, 31, 16));
        root.emit(mov(19, 0));
        if (o.large_unrelated) {
            const uintptr_t unrelated = f.code + 0x7000;
            for (size_t j = 0; j < 140; ++j) f.put(unrelated + j * 4, kNop, 4);
            f.put(unrelated + 140 * 4, kRet, 4);
            root.emit(branch(root.pc(), unrelated, true));
            root.emit(mov(0, 19));
        }
        if (o.split_hot) {
            Assembly lookup{f, f.code + 0x1400, {}};
            hot_body(lookup, hot);
            lookup.emit(kRet); lookup.finish();
            root.emit(branch(root.pc(), lookup.start, true));
        } else hot_body(root, hot);
        if (o.duplicate_hot) {
            root.emit(mov(0, 19)); hot_body(root, hot + 0x2000);
        }
        // CSEL class/corlib variant from the supported root, with no class/rank
        // offset built into discovery. One arm has the token image provenance.
        root.emit(load(o.token, 19, 0x13b, 1));
        root.address(o.table, f.data + 0x180, true, f.data + 0x318);
        root.emit(0x7100001fu | (o.token << 5)); // CMP Wtoken, #0
        root.emit(0x9a800000u | (o.table << 16) | (19u << 5) | o.image);
        root.emit(load(o.image, o.image, o.class_image_field));
        owner_pc = root.pc(); root.emit(load(0, o.image, o.owner_field));
        if (o.inline_vector) vector_body(root, vector, o.target_field, false);
        else root.emit(branch(root.pc(), call_helper, true));
        if (o.duplicate_vector) {
            root.emit(load(o.image, 19, o.class_image_field));
            root.emit(load(0, o.image, o.owner_field));
            root.emit(branch(root.pc(), other_helper, true));
        }
        root.emit(immediate(0, 1, 4));
        root.emit(pair_load(20, 19, 31, 16));
        root.emit(0xf84207feu); // LDR X30, [SP], #32
        root.emit(kRet); root.finish();
        if (o.wrapper) {
            Assembly wrapper{f, f.code + 0x8000, {}};
            wrapper.emit(kBti); wrapper.emit(0xf81f0ffeu);
            wrapper.emit(branch(wrapper.pc(), real_root, true)); wrapper.emit(0xf84107feu); wrapper.emit(kRet);
            wrapper.finish(); entry = wrapper.start;
        }
    }
    void hot_body(Assembly& a, uintptr_t registry) {
        const auto& o = options;
        a.emit(load(o.image, 0, o.class_image_field));
        a.emit(load(o.token, o.image, o.token_field, 4));
        a.emit(0x3100041fu | (o.token << 5)); // CMN Wtoken, #1
        const size_t sentinel = a.emit(0);
        a.address(o.mask, masks, o.got, f.data + 0x300);
        a.emit(shift_right(o.index, o.token, o.scaled_selector ? 30 : 28, o.scaled_selector ? 4 : 8));
        if (!o.scaled_selector) a.emit(and_twelve(o.index, o.index));
        a.emit(load_register(o.index, o.mask, o.index, 4, o.scaled_selector, o.scaled_selector));
        a.emit(bic(o.token, o.token, o.index));
        shift_pc = a.pc(); a.emit(shift_right(o.token, o.token, 22, 4));
        const size_t skip = a.emit(0);
        a.patch_cond(sentinel, a.pc(), 0);
        a.emit(mov(o.token, 31));
        a.patch_b(skip, a.pc());
        a.address(o.table, registry, o.got, f.data + (registry == hot ? 0x308 : 0x310));
        hot_load_pc = a.pc(); a.emit(load_register(o.token, o.table, o.token, 8, true));
    }
    void vector_body(Assembly& a, uintptr_t registry, unsigned target_field, bool function = true) {
        const auto& o = options;
        if (function) { a.emit(0xf81e0ffeu); a.emit(pair_store(o.element, o.saved_assembly, 31, 16)); }
        a.emit(mov(o.saved_assembly, 0));
        a.emit(add(0, 31, 8)); a.emit(branch(a.pc(), f.code + 0x7800, true));
        a.address(o.end, registry, o.got, f.data + (registry == vector ? 0x320 : 0x328));
        a.emit(pair_load(o.cursor, o.end, o.end));
        a.emit(compare(o.cursor, o.end));
        const size_t empty = a.emit(0);
        const uintptr_t loop = a.pc();
        if (o.vector_padding) a.emit(kNop);
        stride_pc = a.pc(); a.emit(load_post(o.element, o.cursor, 8));
        target_pc = a.pc(); a.emit(load(o.target, o.element, target_field));
        a.emit(compare(o.target, o.saved_assembly));
        const size_t found = a.emit(0);
        a.emit(compare(o.end, o.cursor));
        vector_back_pc = a.pc(); a.emit(conditional(a.pc(), loop, 1));
        a.patch_cond(empty, a.pc(), 0);
        if (o.vector_padding) a.emit(kNop);
        a.emit(mov(o.element, 31));
        a.patch_cond(found, a.pc(), 0);
        if (o.vector_padding) a.emit(kBti);
        a.emit(add(0, 31, 8)); a.emit(branch(a.pc(), f.code + 0x7800, true));
        a.emit(mov(0, o.element));
        if (function) { a.emit(pair_load(o.element, o.saved_assembly, 31, 16)); a.emit(0xf84207feu); a.emit(kRet); }
    }
};

struct RawFixture {
    Fixture f;
    uintptr_t loader, vtable;
    unsigned data_field, length_field, end_field;
    RawFixture(bool moves = false, unsigned d = 0x28, unsigned l = 0x40, unsigned e = 0x58,
               uintptr_t base = UINT64_C(0x300000000))
        : f(base), loader(f.code + 0x100), vtable(f.data + 0x800), data_field(d), length_field(l), end_field(e) {
        f.put(f.object, vtable, 8);
        const uintptr_t other = f.code + 0x800;
        f.put(other, kRet, 4);
        for (size_t j = 0; j < 16; ++j) f.put(vtable + j * 8, j == 2 ? loader : other, 8);
        make_loader(loader, moves, d, l, e);
    }
    void make_loader(uintptr_t address, bool moves, unsigned d, unsigned l, unsigned e, unsigned length_width = 4) {
        Assembly a{f, address, {}};
        a.emit(kBti); a.emit(0xd10083ffu); a.emit(pair_store(30, 19, 31, 16));
        unsigned self = 0, data = 1, length = 2, end = 8;
        if (moves) {
            self = 19; data = 11; length = 12; end = 13;
            a.emit(mov(self, 0)); a.emit(mov(data, 1)); a.emit(mov(length, 2, 4));
        }
        a.emit(add_reg(end, data, length));
        a.emit(store(data, self, d)); a.emit(store(length, self, l, length_width)); a.emit(store(end, self, e));
        a.emit(store(31, 31, 8));
        a.emit(load(8, self, 0)); a.emit(add(1, self, 0x80)); a.emit(load(8, 8, 0x60));
        a.emit(0xd63f0100u); // BLR X8 ends the analyzed prefix; never called.
        a.emit(kRet); a.finish();
    }
};

bool evidence_valid(const Fixture& f, const std::vector<hcd::DiscoveryEvidence>& evidence) {
    if (evidence.empty()) return false;
    for (const auto& e : evidence) {
        const Segment* s = f.segment(e.address, e.length);
        if (!s || e.name.empty() || !e.length || e.sha256.size() != 64 ||
            hcd::sha256(s->bytes.data() + size_t(e.address - s->begin), e.length) != e.sha256) return false;
    }
    return true;
}
bool registry_ok(RegistryFixture& fixture, std::string& error) {
    hcd::RegistryDiscovery out;
    const bool ok = hcd::discovery_detail::discover_registries(fixture.f.reader(), fixture.entry, out, error);
    return ok && error.empty() && out.hot_registry == fixture.hot && out.aot_vector == fixture.vector &&
        out.image_token == fixture.options.token_field && out.image_assembly == fixture.options.owner_field &&
        out.aot_target_assembly == fixture.options.target_field && evidence_valid(fixture.f, out.evidence) && fixture.f.reads < 4096;
}
bool registry_rejected(RegistryFixture& fixture, std::string& error) {
    hcd::RegistryDiscovery out; out.hot_registry = 1; out.image_token = 1;
    out.evidence.push_back({"sentinel", 1, 1, "sentinel"});
    return !hcd::discovery_detail::discover_registries(fixture.f.reader(), fixture.entry, out, error) &&
        !error.empty() && !out.hot_registry && !out.aot_vector && !out.image_token && out.evidence.empty();
}

// Optional offline check of a reconstructed base-zero ELF. Inputs, including
// the vtable address, are CLI arguments; no sample RVA is embedded in fixtures.
// PT_LOAD data is read from the file (BSS is zero-filled), never dlopen'd/called.
struct OfflineElf {
    std::vector<uint8_t> bytes;
    std::vector<Elf64_Phdr> loads;
    std::array<uint8_t, 8> raw_vptr{};
    static constexpr uintptr_t raw_object = UINT64_C(0x00fe000000000000);
    bool open(const char* path, uintptr_t vtable) {
        std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(path, "rb"), &std::fclose);
        if (!file || std::fseek(file.get(), 0, SEEK_END) != 0) return false;
        const long size = std::ftell(file.get());
        if (size < long(sizeof(Elf64_Ehdr)) || size > 512 * 1024 * 1024 || std::fseek(file.get(), 0, SEEK_SET) != 0) return false;
        bytes.resize(size_t(size));
        if (std::fread(bytes.data(), 1, bytes.size(), file.get()) != bytes.size() || std::ferror(file.get())) return false;
        Elf64_Ehdr header;
        std::memcpy(&header, bytes.data(), sizeof(header));
        if (std::memcmp(header.e_ident, ELFMAG, SELFMAG) || header.e_ident[EI_CLASS] != ELFCLASS64 ||
            header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_machine != EM_AARCH64 ||
            header.e_phnum == 0 || header.e_phnum > 256 || header.e_phentsize != sizeof(Elf64_Phdr) ||
            header.e_phoff > bytes.size() || size_t(header.e_phnum) * sizeof(Elf64_Phdr) > bytes.size() - header.e_phoff) return false;
        for (size_t i = 0; i < header.e_phnum; ++i) {
            Elf64_Phdr ph;
            std::memcpy(&ph, bytes.data() + header.e_phoff + i * sizeof(ph), sizeof(ph));
            if (ph.p_type != PT_LOAD) continue;
            if (ph.p_offset > bytes.size() || ph.p_filesz > bytes.size() - ph.p_offset || ph.p_memsz < ph.p_filesz ||
                ph.p_memsz > std::numeric_limits<uintptr_t>::max() - ph.p_vaddr) return false;
            loads.push_back(ph);
        }
        for (size_t i = 0; i < 8; ++i) raw_vptr[i] = uint8_t(vtable >> (i * 8));
        return !loads.empty();
    }
    const Elf64_Phdr* range(uintptr_t p, size_t n, bool exec) const {
        for (const auto& ph : loads)
            if ((ph.p_flags & PF_R) && (!exec || (ph.p_flags & PF_X)) && p >= ph.p_vaddr &&
                p - ph.p_vaddr <= ph.p_memsz && n <= ph.p_memsz - (p - ph.p_vaddr)) return &ph;
        return nullptr;
    }
    Reader reader() const {
        return {this,
            [](const void* context, uintptr_t p, void* out, size_t n) {
                const auto& elf = *static_cast<const OfflineElf*>(context);
                if (p >= raw_object && p - raw_object <= 8 && n <= 8 - (p - raw_object)) {
                    std::memcpy(out, elf.raw_vptr.data() + (p - raw_object), n); return true;
                }
                const auto* ph = elf.range(p, n, false);
                if (!ph) return false;
                const size_t offset = size_t(p - ph->p_vaddr);
                const size_t available = offset < ph->p_filesz ? std::min(n, size_t(ph->p_filesz) - offset) : 0;
                if (available) std::memcpy(out, elf.bytes.data() + ph->p_offset + offset, available);
                if (available < n) std::memset(static_cast<uint8_t*>(out) + available, 0, n - available);
                return true;
            },
            [](const void* context, uintptr_t p, size_t n, bool exec) {
                return static_cast<const OfflineElf*>(context)->range(p, n, exec) != nullptr;
            }};
    }
};
int offline_check(int argc, char** argv) {
    if (argc != 7 || std::strcmp(argv[1], "--elf")) {
        std::printf("Usage: %s [--elf file pre_jit_class getter1 getter2 raw_vtable]\n", argv[0]); return 1;
    }
    std::array<uintptr_t, 4> addresses{};
    for (size_t i = 0; i < addresses.size(); ++i) {
        char* end = nullptr;
        errno = 0;
        const char* text = argv[i + 3];
        const unsigned long long value = std::strtoull(text, &end, 0);
        if (!*text || *text == '-' || !end || *end || errno || value > std::numeric_limits<uintptr_t>::max()) return 1;
        addresses[i] = uintptr_t(value);
    }
    OfflineElf elf;
    if (!elf.open(argv[2], addresses[3])) { std::printf("FAIL offline ELF input\n"); return 1; }
    std::string error;
    hcd::RegistryDiscovery registry;
    bool ok = hcd::discovery_detail::discover_registries(elf.reader(), addresses[0], registry, error);
    std::printf("%s registry hot=%llx vector=%llx token=%zx owner=%zx target=%zx evidence=%zu %s\n",
                ok ? "PASS" : "FAIL", static_cast<unsigned long long>(registry.hot_registry),
                static_cast<unsigned long long>(registry.aot_vector), registry.image_token, registry.image_assembly,
                registry.aot_target_assembly, registry.evidence.size(), error.c_str());
    for (size_t i = 1; i <= 2; ++i) {
        size_t field = 0;
        std::vector<hcd::DiscoveryEvidence> evidence;
        const bool found = hcd::discovery_detail::discover_pointer_getter(elf.reader(), addresses[i], field, evidence, error);
        std::printf("%s getter%zu field=%zx evidence=%zu %s\n", found ? "PASS" : "FAIL", i, field, evidence.size(), error.c_str());
        ok &= found;
    }
    hcd::profile::Layout layout;
    std::vector<hcd::DiscoveryEvidence> evidence;
    const bool found = hcd::discovery_detail::discover_raw_layout(elf.reader(), OfflineElf::raw_object, layout, evidence, error);
    std::printf("%s raw data=%zx length=%zx end=%zx evidence=%zu %s\n", found ? "PASS" : "FAIL",
                layout.raw_data, layout.raw_length, layout.raw_end, evidence.size(), error.c_str());
    return ok && found ? 0 : 1;
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 1) {
        try { return offline_check(argc, argv); }
        catch (const std::exception& e) { std::printf("FAIL offline exception: %s\n", e.what()); return 1; }
    }
    unsigned passed = 0, failed = 0;
    const auto check = [&](const char* name, bool ok, const std::string& detail = "") {
        if (ok) ++passed;
        else { ++failed; std::printf("FAIL %s%s%s\n", name, detail.empty() ? "" : ": ", detail.c_str()); }
    };
    try {
        std::string error;
        RegistryFixture baseline;
        check("registry GOT / sentinel / CSEL / lock calls", registry_ok(baseline, error), error);
        RegistryOptions direct; direct.got = false;
        RegistryFixture relocated(direct, UINT64_C(0x7a00000000), true);
        check("registry relocated direct ADRP+ADD / negative ADRP", registry_ok(relocated, error), error);
        RegistryOptions registers;
        registers.token = 12; registers.index = 13; registers.mask = 14; registers.table = 15; registers.image = 16;
        registers.cursor = 11; registers.end = 12; registers.element = 22; registers.target = 13; registers.saved_assembly = 23;
        registers.token_field = 0xa4; registers.owner_field = 0x68; registers.target_field = 0x158; registers.class_image_field = 0x18;
        RegistryFixture varied(registers, UINT64_C(0x2b80000000));
        check("registry changed fields / registers / class image field", registry_ok(varied, error), error);
        RegistryOptions scaled; scaled.scaled_selector = true;
        RegistryFixture alternate_selector(scaled);
        check("registry equivalent token>>30 with UXTW#2 mask indexing", registry_ok(alternate_selector, error), error);
        RegistryOptions inline_options; inline_options.inline_vector = true;
        RegistryFixture inlined(inline_options);
        check("registry fully inlined vector walk", registry_ok(inlined, error), error);
        RegistryOptions padded_options; padded_options.vector_padding = true;
        RegistryFixture padded(padded_options);
        check("registry BTI/NOP vector branch landing pads", registry_ok(padded, error), error);
        RegistryOptions tail_options; tail_options.tail = true; tail_options.wrapper = true;
        RegistryFixture wrapped(tail_options);
        check("registry direct-call root wrapper / BTI NOP B helper thunk", registry_ok(wrapped, error), error);
        RegistryOptions split_options; split_options.split_hot = true;
        RegistryFixture split(split_options);
        check("registry hot lookup in small direct helper", registry_ok(split, error), error);
        RegistryOptions bounded_options; bounded_options.large_unrelated = true;
        RegistryFixture bounded(bounded_options);
        check("registry does not recurse into large unrelated runtime helper", registry_ok(bounded, error), error);
        for (unsigned iteration = 0; iteration < 12; ++iteration) {
            RegistryOptions o = iteration & 1 ? registers : RegistryOptions{};
            o.got = iteration % 3 != 0; o.tail = iteration % 4 == 0;
            o.token_field += iteration * 4; o.owner_field += 0x100 + iteration * 8; o.target_field += iteration * 8;
            RegistryFixture f(o, UINT64_C(0x400000000) + uint64_t(iteration) * 0x123000, iteration & 1);
            check("registry relocation/encoding matrix", registry_ok(f, error), error);
        }
        {
            RegistryFixture f; f.f.put(f.masks + 8, 0x000fffffu, 4);
            check("registry unsupported mask table", registry_rejected(f, error), error);
        }
        {
            RegistryFixture f; f.f.put(f.shift_pc, shift_right(f.options.token, f.options.token, 21, 4), 4);
            check("registry requires shift22", registry_rejected(f, error), error);
        }
        {
            RegistryFixture f; f.f.put(f.hot_load_pc, load_register(8, 9, 8, 8, false), 4);
            check("registry requires 64-bit pointer slot stride", registry_rejected(f, error), error);
        }
        {
            RegistryFixture f; f.f.put(f.hot_load_pc, load_register(8, 9, 8, 8, true, true), 4);
            check("registry unsigned W index extension for pointer slots", registry_ok(f, error), error);
        }
        {
            RegistryFixture f; f.f.put(f.vector_back_pc, conditional(f.vector_back_pc, f.stride_pc + 4, 1), 4);
            check("registry random LDP / wrong vector back edge", registry_rejected(f, error), error);
        }
        {
            RegistryFixture f; f.f.put(f.stride_pc, load_post(20, 8, 16), 4);
            check("registry wrong vector stride", registry_rejected(f, error), error);
        }
        {
            RegistryFixture f; f.f.put(f.target_pc, load(10, 20, f.options.target_field, 4), 4);
            check("registry target field must be a pointer", registry_rejected(f, error), error);
        }
        {
            RegistryFixture f;
            uintptr_t cursor = f.f.code + 0x2400;
            while (f.f.word(cursor) != mov(0, f.options.element)) cursor += 4;
            f.f.put(cursor, immediate(0, 1, 4), 4);
            check("registry rejects complete vector walk returning bool", registry_rejected(f, error), error);
        }
        {
            RegistryFixture f;
            uintptr_t cursor = f.f.code + 0x2400;
            while (f.f.word(cursor) != mov(0, f.options.element)) cursor += 4;
            f.f.put(cursor, mov(0, 19), 4);
            check("registry rejects vector walk returning original assembly", registry_rejected(f, error), error);
        }
        {
            RegistryFixture f; f.f.put(f.owner_pc, load(0, 19, f.options.owner_field), 4);
            check("registry owner must come from the token's native image", registry_rejected(f, error), error);
        }
        {
            RegistryOptions o; o.duplicate_vector = true; RegistryFixture f(o);
            check("registry ambiguous AOT vectors", registry_rejected(f, error), error);
        }
        {
            RegistryOptions o; o.duplicate_hot = true; RegistryFixture f(o);
            check("registry ambiguous hot registries", registry_rejected(f, error), error);
        }
        {
            RegistryFixture f; f.f.failed_read = f.masks;
            check("registry unreadable mask table", registry_rejected(f, error), error);
        }
        {
            RegistryFixture f; f.f.failed_read = f.f.data + 0x308;
            check("registry unreadable GOT cell", registry_rejected(f, error), error);
        }
        {
            RegistryFixture f; f.f.unstable_read = f.real_root + 4;
            check("registry changing code fails before publication", registry_rejected(f, error), error);
        }
        {
            RegistryFixture f;
            Assembly a{f.f, f.f.code + 0x80, {}};
            a.emit(immediate(5, 0, 4));
            a.emit(0x35000000u | ((uint32_t((f.real_root - a.pc()) / 4) & 0x7ffffu) << 5) | 5); // CBNZ W5
            a.emit(kRet); a.finish(); f.entry = a.start;
            check("registry ignores provably dead CB branch", registry_rejected(f, error), error);
        }
        {
            RegistryFixture f;
            Assembly a{f.f, f.f.code + 0x80, {}};
            a.emit(immediate(5, 1, 4)); a.emit(0x7100001fu | (5u << 5));
            a.emit(conditional(a.pc(), f.real_root, 0)); a.emit(kRet); a.finish(); f.entry = a.start;
            check("registry ignores provably dead comparison branch", registry_rejected(f, error), error);
        }
        {
            const auto constant_branch = [&](const char* name, std::vector<uint32_t> prefix, uint32_t opcode, bool accepted) {
                RegistryFixture f;
                Assembly a{f.f, f.f.code + 0x80, std::move(prefix)};
                a.emit(opcode | ((uint32_t((f.real_root - a.pc()) / 4) & 0x7ffffu) << 5));
                a.emit(kRet); a.finish(); f.entry = a.start;
                check(name, accepted ? registry_ok(f, error) :
                    (registry_rejected(f, error) && error.find("No complete supported") == 0), error);
            };
            constexpr uint32_t cbnz_w5 = 0x35000005u, cbnz_x5 = 0xb5000005u;
            constexpr uint32_t cbz_w5 = 0x34000005u, cbz_x5 = 0xb4000005u;
            const uint32_t high_one = immediate(5, 1) | (2u << 21); // MOVZ X5, #1, LSL #32
            const uint32_t high_four = immediate(5, 4) | (2u << 21);
            const uint32_t and_high = (and_twelve(5, 5) & ~(63u << 16)) | (30u << 16); // AND X5, X5, #0xc00000000
            constant_branch("registry dead W constant LSR branch",
                {immediate(5, 1, 4), shift_right(5, 5, 1, 4)}, cbnz_w5, false);
            constant_branch("registry dead X constant LSR branch",
                {immediate(5, 1), shift_right(5, 5, 1)}, cbnz_x5, false);
            constant_branch("registry W LSR truncates X input before shifting and zero extends",
                {high_one, shift_right(5, 5, 1, 4)}, cbnz_x5, false);
            constant_branch("registry X LSR preserves high input bits",
                {high_one, shift_right(5, 5, 31)}, cbnz_x5, true);
            constant_branch("registry dead W constant AND branch",
                {immediate(5, 1, 4), and_twelve(5, 5, 4)}, cbnz_w5, false);
            constant_branch("registry dead X constant AND branch",
                {immediate(5, 1), and_twelve(5, 5)}, cbnz_x5, false);
            constant_branch("registry W AND nonzero result survives X branch read",
                {immediate(5, 4, 4), and_twelve(5, 5, 4)}, cbnz_x5, true);
            constant_branch("registry X AND preserves high result bits",
                {high_four, and_high}, cbnz_x5, true);
            constant_branch("registry nonzero W LSR makes CBZ semantic block dead",
                {immediate(5, 2, 4), shift_right(5, 5, 1, 4)}, cbz_w5, false);
            constant_branch("registry nonzero X AND makes CBZ semantic block dead",
                {immediate(5, 4), and_twelve(5, 5)}, cbz_x5, false);
            constant_branch("registry W constant ADD wraps and zero extends",
                {immediate(5, 1, 4), 0x12800006u, add_reg(5, 5, 6) & ~0x80000000u}, cbnz_x5, false);
            constant_branch("registry X constant ADD wraps at 64 bits",
                {immediate(5, 1), 0x92800006u, add_reg(5, 5, 6)}, cbnz_x5, false);
            constant_branch("registry dead W constant BIC branch",
                {immediate(5, 1, 4), bic(5, 5, 5)}, cbnz_w5, false);
            constant_branch("registry X constant BIC preserves high result bits",
                {high_one, immediate(6, 0), bic(5, 5, 6) | 0x80000000u}, cbnz_x5, true);
        }
        {
            RegistryFixture f; f.f.denied_exec = f.real_root;
            check("registry nonexecutable entry", registry_rejected(f, error), error);
        }
        {
            RegistryFixture f; f.entry |= UINT64_C(0xa500000000000000);
            check("registry tagged/signed entry pointer is not silently stripped", registry_rejected(f, error), error);
        }
        {
            RegistryFixture f; f.f.put(f.real_root + 4, 0xd503233fu, 4); // PACIASP
            check("registry unsupported PAC shape", registry_rejected(f, error), error);
        }
        {
            RegistryFixture f;
            f.entry = f.f.code + 0x8000;
            f.f.put(f.entry, branch(f.entry, f.entry), 4);
            check("registry cyclic tail stub", registry_rejected(f, error), error);
        }
        {
            RegistryFixture f;
            f.entry = f.f.code + 0x8000;
            for (unsigned j = 0; j < 129; ++j) f.f.put(f.entry + j * 4, kNop, 4);
            f.f.put(f.entry + 129 * 4, kRet, 4);
            check("registry bounded oversized root", registry_rejected(f, error), error);
        }
        {
            RegistryFixture f;
            uintptr_t target = f.real_root;
            for (unsigned j = 0; j < 4; ++j) {
                Assembly a{f.f, f.f.code + 0x8000 + j * 0x100, {}};
                a.emit(0xf81f0ffeu); a.emit(branch(a.pc(), target, true)); a.emit(0xf84107feu); a.emit(kRet); a.finish();
                target = a.start;
            }
            f.entry = target;
            check("registry bounded helper call depth", registry_rejected(f, error), error);
        }
        {
            RegistryFixture f;
            // Replace RET with repeated reconverging branches. Even when code
            // bytes are few, abstract path visits must still be bounded.
            uintptr_t cursor = f.real_root;
            while (f.f.word(cursor) != kRet) cursor += 4;
            for (unsigned j = 0; j < 13; ++j) {
                f.f.put(cursor, conditional(cursor, cursor + 4, 0), 4); cursor += 4;
            }
            f.f.put(cursor, kRet, 4);
            check("registry bounded path explosion", registry_rejected(f, error) && error.find("visit budget") != std::string::npos, error);
        }
        {
            RegistryFixture f;
            Assembly a{f.f, f.f.code + 0x8000, {}};
            for (unsigned j = 0; j < 33; ++j) {
                const uintptr_t callee = f.f.code + 0x9000 + j * 16;
                f.f.put(callee, kRet, 4); a.emit(branch(a.pc(), callee, true));
            }
            a.emit(kRet); a.finish(); f.entry = a.start;
            check("registry bounded function probes", registry_rejected(f, error) && error.find("function budget") != std::string::npos, error);
        }
        {
            Fixture f;
            const uintptr_t entry = f.code + 0x100, body = f.code + 0x400;
            Assembly thunk{f, entry, {}}; thunk.emit(kBti); thunk.emit(kNop); thunk.emit(branch(thunk.pc(), body)); thunk.finish();
            Assembly a{f, body, {}};
            a.emit(kBti); a.emit(mov(11, 0)); a.emit(load(13, 11, 0x78)); a.emit(mov(0, 13)); a.emit(kRet); a.finish();
            size_t field = 999;
            std::vector<hcd::DiscoveryEvidence> evidence;
            check("getter B / BTI / MOV register provenance", hcd::discovery_detail::discover_pointer_getter(f.reader(), entry, field, evidence, error) &&
                  field == 0x78 && error.empty() && evidence_valid(f, evidence), error);
            a.words = {load(0, 0, 0), kRet}; a.finish();
            evidence.clear();
            check("getter zero field offset is valid", hcd::discovery_detail::discover_pointer_getter(f.reader(), body, field, evidence, error) && field == 0, error);
            const auto rejected = [&](const char* name, std::vector<uint32_t> words) {
                a.words = std::move(words); a.finish(); field = 999; evidence.clear();
                evidence.push_back({"sentinel", 1, 1, "sentinel"});
                check(name, !hcd::discovery_detail::discover_pointer_getter(f.reader(), body, field, evidence, error) &&
                      !field && evidence.size() == 1 && !error.empty(), error);
            };
            rejected("getter rejects uint32 field", {load(0, 0, 0x40, 4), kRet});
            rejected("getter rejects nested dereference", {load(0, 0, 0x40), load(0, 0, 0), kRet});
            rejected("getter rejects unrelated input", {load(0, 1, 0x40), kRet});
            rejected("getter rejects hidden call", {branch(body, f.code + 0x800, true), load(0, 0, 0x40), kRet});
            rejected("getter rejects multiple fields", {mov(8, 0), load(9, 8, 0x40), load(0, 8, 0x48), kRet});
            rejected("getter rejects width-truncating moves", {mov(8, 0, 4), load(0, 8, 0x40), kRet});
            rejected("getter rejects BR thunk", {0xd61f0100u});
            rejected("getter rejects PAC", {0xd503233fu, load(0, 0, 0x40), kRet});
            rejected("getter rejects thunk cycle", {branch(body, body)});
            std::vector<uint32_t> too_long(33, kNop); too_long.push_back(load(0, 0, 0x40)); too_long.push_back(kRet);
            rejected("getter bounded padding", std::move(too_long));
            a.words = {load(0, 0, 0x40), kRet}; a.finish(); f.failed_read = body;
            field = 999;
            check("getter failed reads report error", !hcd::discovery_detail::discover_pointer_getter(f.reader(), body, field, evidence, error) && !field && !error.empty(), error);
            f.failed_read = 0; f.unstable_read = body; evidence.resize(1); field = 999;
            check("getter changing code is transactional", !hcd::discovery_detail::discover_pointer_getter(f.reader(), body, field, evidence, error) &&
                  !field && evidence.size() == 1 && !error.empty(), error);
        }
        {
            const auto raw_check = [&](const char* name, RawFixture& f, bool accepted) {
                hcd::profile::Layout layout; layout.image_raw = 0x100; layout.raw_data = 0x180;
                layout.raw_length = 0x184; layout.raw_end = 0x188;
                std::vector<hcd::DiscoveryEvidence> evidence{{"sentinel", 1, 1, "sentinel"}};
                const bool ok = hcd::discovery_detail::discover_raw_layout(f.f.reader(), f.f.object, layout, evidence, error);
                bool valid = ok == accepted && layout.image_raw == 0x100;
                if (accepted) {
                    std::vector<hcd::DiscoveryEvidence> added(evidence.begin() + 1, evidence.end());
                    valid &= error.empty() && layout.raw_data == f.data_field && layout.raw_length == f.length_field &&
                             layout.raw_end == f.end_field && evidence_valid(f.f, added);
                } else valid &= !error.empty() && evidence.size() == 1 && layout.raw_data == 0x180 &&
                                layout.raw_length == 0x184 && layout.raw_end == 0x188;
                check(name, valid, error);
            };
            RawFixture baseline_raw;
            raw_check("raw loader canonical pointer/u32/end prefix", baseline_raw, true);
            RawFixture moved(true, 0x80, 0xb4, 0xd8, UINT64_C(0x7300000000));
            raw_check("raw loader relocated MOV / W length / altered offsets", moved, true);
            RawFixture alias;
            const uintptr_t thunk = alias.f.code + 0x1000;
            alias.f.put(thunk, kBti, 4); alias.f.put(thunk + 4, branch(thunk + 4, alias.loader), 4);
            alias.f.put(alias.vtable + 3 * 8, thunk, 8);
            raw_check("raw duplicate method alias through B thunk", alias, true);
            RawFixture wide;
            wide.make_loader(wide.loader, false, wide.data_field, wide.length_field, wide.end_field, 8);
            raw_check("raw rejects 64-bit length store", wide, false);
            RawFixture ambiguous;
            const uintptr_t second = ambiguous.f.code + 0x1800;
            ambiguous.make_loader(second, true, 0x68, 0x84, 0xa8);
            ambiguous.f.put(ambiguous.vtable + 4 * 8, second, 8);
            raw_check("raw rejects two loader methods", ambiguous, false);
            RawFixture same_offsets;
            same_offsets.make_loader(second, true, same_offsets.data_field, same_offsets.length_field, same_offsets.end_field);
            same_offsets.f.put(same_offsets.vtable + 4 * 8, second, 8);
            raw_check("raw rejects two distinct methods even with same offsets", same_offsets, false);
            RawFixture partial;
            Assembly partial_loader{partial.f, second, {}};
            partial_loader.emit(store(1, 0, 0x68)); partial_loader.emit(kRet); partial_loader.finish();
            partial.f.put(partial.vtable + 4 * 8, second, 8);
            raw_check("raw rejects a second partial loader-like method", partial, false);
            const std::array<unsigned, 3> pair_sources{{1, 2, 8}};
            const std::array<const char*, 3> pair_names{{
                "raw rejects STP second Data source alongside valid loader",
                "raw rejects STP second Length source alongside valid loader",
                "raw rejects STP second End source alongside valid loader"}};
            for (size_t i = 0; i < pair_sources.size(); ++i) {
                RawFixture paired;
                Assembly pair_loader{paired.f, second, {}};
                pair_loader.emit(add_reg(8, 1, 2));
                pair_loader.emit(pair_store(31, pair_sources[i], 0, 0x60));
                pair_loader.emit(kRet); pair_loader.finish();
                paired.f.put(paired.vtable + 4 * 8, second, 8);
                raw_check(pair_names[i], paired, false);
            }
            RawFixture adjusted;
            Assembly adjusted_loader{adjusted.f, second, {}};
            adjusted_loader.emit(add(3, 0, 0x20)); adjusted_loader.emit(store(1, 3, 0x68));
            adjusted_loader.emit(kRet); adjusted_loader.finish();
            adjusted.f.put(adjusted.vtable + 4 * 8, second, 8);
            raw_check("raw rejects loader stores through unsupported this adjustment", adjusted, false);
            RawFixture overlap(false, 0x28, 0x2c, 0x58);
            raw_check("raw rejects overlapping fields", overlap, false);
            RawFixture large(false, 0x208, 0x220, 0x238);
            raw_check("raw rejects large fields", large, false);
            RawFixture no_method;
            no_method.f.put(no_method.vtable + 2 * 8, no_method.f.code + 0x800, 8);
            raw_check("raw rejects no matching loader", no_method, false);
            RawFixture bad_slot;
            bad_slot.f.put(bad_slot.vtable + 15 * 8, bad_slot.f.data + 0x100, 8);
            raw_check("raw every inspected slot must be executable", bad_slot, false);
            RawFixture signed_slot;
            signed_slot.f.put(signed_slot.vtable + 2 * 8, signed_slot.loader | UINT64_C(0xa500000000000000), 8);
            raw_check("raw rejects tagged/signed vtable code pointers", signed_slot, false);
            RawFixture unreadable;
            unreadable.f.failed_read = unreadable.f.object;
            raw_check("raw unreadable object vptr", unreadable, false);
            RawFixture heap_vtable;
            heap_vtable.f.put(heap_vtable.f.object, heap_vtable.f.object + 8, 8);
            raw_check("raw rejects heap/non-module vtable", heap_vtable, false);
            RawFixture clobbered;
            clobbered.f.put(clobbered.loader + 3 * 4, mov(1, 0), 4);
            raw_check("raw input data provenance is required", clobbered, false);
            RawFixture alias_store;
            // The valid stores precede this unmodeled this+offset alias write.
            alias_store.f.put(alias_store.loader + 7 * 4, add(3, 0, alias_store.data_field), 4);
            alias_store.f.put(alias_store.loader + 8 * 4, store(31, 3, 0), 4);
            raw_check("raw rejects unmodeled alias overwrites", alias_store, false);
            RawFixture pair_overwrite;
            pair_overwrite.f.put(pair_overwrite.loader + 7 * 4, pair_store(31, 31, 0, pair_overwrite.data_field), 4);
            raw_check("raw rejects pair-store overwrites", pair_overwrite, false);
            RawFixture unaligned;
            unaligned.f.put(unaligned.f.object, unaligned.vtable + 1, 8);
            raw_check("raw unaligned vptr reports an error", unaligned, false);
            RawFixture changing;
            changing.f.unstable_read = changing.f.object;
            raw_check("raw changing object vptr is transactional", changing, false);
        }
        {
            Reader invalid{};
            hcd::RegistryDiscovery out;
            check("missing reader fails closed", !hcd::discovery_detail::discover_registries(invalid, 1, out, error) && !error.empty());
        }
    } catch (const std::exception& e) { check("fixture exception", false, e.what()); }
    std::printf("PASS %u FAIL %u\n", passed, failed);
    return failed ? 1 : 0;
}
