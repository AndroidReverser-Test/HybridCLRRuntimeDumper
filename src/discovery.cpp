#include "discovery.h"
#include "format.h"
#include "platform.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <tuple>
#include <utility>

namespace hcd {
namespace {

using discovery_detail::Reader;
constexpr size_t kInstructions = 128, kFunctions = 32, kVisits = 4096;
constexpr unsigned kDepth = 3, kThunks = 8, kTinyInstructions = 32;
constexpr size_t kVtableSlots = 16, kFieldLimit = 0x1000;
static_assert(profile::kHotSlots == 1024, "Only the 1024-slot hot registry ABI is supported.");

uintptr_t canonical(uintptr_t p) { return p & UINT64_C(0x00ffffffffffffff); }
bool add_address(uintptr_t base, int64_t delta, uintptr_t& result) {
    if (delta >= 0) {
        if (uint64_t(delta) > std::numeric_limits<uintptr_t>::max() - base) return false;
        result = base + uintptr_t(delta);
    } else {
        const uint64_t magnitude = uint64_t(-(delta + 1)) + 1;
        if (magnitude > base) return false;
        result = base - uintptr_t(magnitude);
    }
    return true;
}
int64_t signed_bits(uint32_t value, unsigned bits) {
    return (value & (uint32_t(1) << (bits - 1))) ? int64_t(value) - (INT64_C(1) << bits) : value;
}
uint64_t little(const uint8_t* p, size_t n) {
    uint64_t result = 0;
    for (size_t i = 0; i < n; ++i) result |= uint64_t(p[i]) << (8 * i);
    return result;
}
bool valid_field(int64_t offset, size_t alignment, size_t limit = kFieldLimit) {
    return offset >= 0 && uint64_t(offset) + alignment <= limit && size_t(offset) % alignment == 0;
}
bool overlaps(size_t a, size_t an, size_t b, size_t bn) { return a < b + bn && b < a + an; }

int comparison_flags(uint64_t a, uint64_t b, unsigned width, bool subtract) {
    const uint64_t mask = width == 4 ? UINT32_MAX : UINT64_MAX;
    const uint64_t sign = UINT64_C(1) << (width * 8 - 1);
    a &= mask; b &= mask;
    const uint64_t result = (subtract ? a - b : a + b) & mask;
    const bool carry = subtract ? a >= b : result < a;
    const bool overflow = ((subtract ? a ^ b : ~(a ^ b)) & (a ^ result) & sign) != 0;
    return ((result & sign) ? 8 : 0) | (result == 0 ? 4 : 0) | (carry ? 2 : 0) | (overflow ? 1 : 0);
}
bool condition_true(int flags, unsigned condition) {
    const bool n = flags & 8, z = flags & 4, c = flags & 2, v = flags & 1;
    bool result = false;
    switch (condition >> 1) {
        case 0: result = z; break;
        case 1: result = c; break;
        case 2: result = n; break;
        case 3: result = v; break;
        case 4: result = c && !z; break;
        case 5: result = n == v; break;
        case 6: result = n == v && !z; break;
        default: break;
    }
    return condition & 1 ? !result : result;
}

enum class Op {
    Unsupported, Padding, Ret, Branch, Call, Cond, CompareZero, TestBit, Indirect,
    Adr, Mov, Immediate, AddImmediate, AddRegister, Compare, CompareImmediate,
    Select, ShiftRight, AndImmediate, Bic, Load, Store, PairLoad, PairStore
};
struct Insn {
    Op op = Op::Unsupported;
    uint32_t word = 0;
    unsigned rd = 0, rn = 0, rm = 0, width = 0, mode = 0, option = 0, shift = 0, condition = 0;
    int64_t imm = 0;
    uintptr_t target = 0;
};

bool logical_immediate(uint32_t word, unsigned width, uint64_t& result) {
    const unsigned n = (word >> 22) & 1, r = (word >> 16) & 63, s = (word >> 10) & 63;
    if (width == 32 && n) return false;
    const unsigned discriminator = (n << 6) | ((~s) & 63);
    unsigned length = 0;
    for (unsigned i = 0; i <= 6; ++i) if (discriminator & (1u << i)) length = i;
    if (length < 1) return false;
    const unsigned size = 1u << length, levels = size - 1;
    if (size > width || (s & levels) == levels) return false;
    const unsigned ones = (s & levels) + 1, rotation = r & levels;
    uint64_t bits = (UINT64_C(1) << ones) - 1;
    const uint64_t mask = size == 64 ? UINT64_MAX : (UINT64_C(1) << size) - 1;
    if (rotation) bits = ((bits >> rotation) | (bits << (size - rotation))) & mask;
    result = 0;
    for (unsigned i = 0; i < width; i += size) result |= bits << i;
    return true;
}

Insn decode(uintptr_t pc, uint32_t w) {
    Insn i;
    i.word = w; i.rd = w & 31; i.rn = (w >> 5) & 31; i.rm = (w >> 16) & 31;
    i.width = (w >> 31) ? 8 : 4;
    if (w == 0xd503201fu || (w & 0xffffff3fu) == 0xd503241fu) i.op = Op::Padding;
    else if ((w & 0xfffffc1fu) == 0xd65f0000u) i.op = Op::Ret;
    else if ((w & 0xfffffc1fu) == 0xd61f0000u || (w & 0xfffffc1fu) == 0xd63f0000u)
        i.op = Op::Indirect;
    else if ((w & 0x7c000000u) == 0x14000000u) {
        i.op = w >> 31 ? Op::Call : Op::Branch;
        if (!add_address(pc, signed_bits(w & 0x3ffffffu, 26) * 4, i.target)) i.op = Op::Unsupported;
    } else if ((w & 0xff000010u) == 0x54000000u) {
        i.op = Op::Cond; i.condition = w & 15;
        if (i.condition >= 14 || !add_address(pc, signed_bits((w >> 5) & 0x7ffffu, 19) * 4, i.target))
            i.op = Op::Unsupported;
    } else if ((w & 0x7e000000u) == 0x34000000u || (w & 0x7e000000u) == 0x36000000u) {
        i.op = (w & 0x02000000u) ? Op::TestBit : Op::CompareZero;
        i.condition = (w >> 24) & 1;
        const unsigned bits = i.op == Op::TestBit ? 14 : 19;
        i.imm = ((w >> 19) & 31) | ((w >> 26) & 32);
        if (!add_address(pc, signed_bits((w >> 5) & ((1u << bits) - 1), bits) * 4, i.target))
            i.op = Op::Unsupported;
    } else if ((w & 0x1f000000u) == 0x10000000u) {
        i.op = Op::Adr;
        const int64_t displacement = signed_bits(((w >> 5) & 0x7ffffu) << 2 | ((w >> 29) & 3), 21);
        const bool page = (w >> 31) != 0;
        if (!add_address(page ? pc & ~uintptr_t(4095) : pc, displacement * (page ? 4096 : 1), i.target))
            i.op = Op::Unsupported;
        i.width = 8;
    } else if ((w & 0x7fe0ffe0u) == 0x2a0003e0u) {
        i.op = Op::Mov; i.rn = i.rm;
    } else if ((w & 0x7f800000u) == 0x52800000u || (w & 0x7f800000u) == 0x12800000u) {
        const unsigned shift = ((w >> 21) & 3) * 16;
        if (shift < i.width * 8) {
            i.op = Op::Immediate;
            uint64_t value = uint64_t((w >> 5) & 65535) << shift;
            if (!(w & 0x40000000u)) value = ~value;
            if (i.width == 4) value &= UINT32_MAX;
            std::memcpy(&i.imm, &value, sizeof(value));
        }
    } else if ((w & 0x1f800000u) == 0x11000000u) {
        i.imm = int64_t((w >> 10) & 4095) << ((w & 0x00400000u) ? 12 : 0);
        if (w & 0x40000000u) i.imm = -i.imm;
        i.op = (w & 0x20000000u) && i.rd == 31 ? Op::CompareImmediate : Op::AddImmediate;
    } else if ((w & 0x7fe0fc00u) == 0x0b000000u) i.op = Op::AddRegister;
    else if ((w & 0x7fe0fc1fu) == 0x6b00001fu) i.op = Op::Compare;
    else if ((w & 0x7fe00c00u) == 0x1a800000u) {
        i.op = Op::Select; i.condition = (w >> 12) & 15;
        if (i.condition >= 14) i.op = Op::Unsupported;
    } else if ((w & 0x7f800000u) == 0x53000000u) {
        const unsigned bits = i.width * 8;
        if (((w >> 22) & 1) == (w >> 31) && ((w >> 10) & 63) == bits - 1 && ((w >> 16) & 63) < bits) {
            i.op = Op::ShiftRight; i.imm = (w >> 16) & 63;
        }
    } else if ((w & 0x7f800000u) == 0x12000000u) {
        uint64_t mask = 0;
        if (logical_immediate(w, i.width * 8, mask)) {
            i.op = Op::AndImmediate;
            std::memcpy(&i.imm, &mask, sizeof(mask));
        }
    } else if ((w & 0x7fe0fc00u) == 0x0a200000u) i.op = Op::Bic;
    else if ((w & 0x3f000000u) == 0x39000000u ||
             (w & 0x3f200000u) == 0x38000000u || (w & 0x3f200c00u) == 0x38200800u) {
        const unsigned opc = (w >> 22) & 3;
        i.width = 1u << (w >> 30);
        if (opc <= 1) {
            i.op = opc ? Op::Load : Op::Store;
            if ((w & 0x3f000000u) == 0x39000000u) i.imm = int64_t((w >> 10) & 4095) * i.width;
            else if (w & 0x00200000u) {
                i.mode = 2; i.option = (w >> 13) & 7;
                i.shift = (w & 0x1000u) ? (w >> 30) : 0;
                if (i.option != 2 && i.option != 3 && i.option != 6 && i.option != 7) i.op = Op::Unsupported;
            } else {
                i.imm = signed_bits((w >> 12) & 511, 9); i.mode = (w >> 10) & 3;
                if (i.mode == 2) i.op = Op::Unsupported;
            }
        }
    } else if ((w & 0x3e000000u) == 0x28000000u) {
        const unsigned opc = w >> 30;
        i.mode = (w >> 23) & 3;
        if ((opc == 0 || opc == 2) && i.mode != 0) {
            i.width = opc == 2 ? 8 : 4;
            i.op = (w & 0x00400000u) ? Op::PairLoad : Op::PairStore;
            i.rm = (w >> 10) & 31;
            i.imm = signed_bits((w >> 15) & 127, 7) * i.width;
        }
    }
    return i;
}

struct Snapshot {
    const Reader& reader;
    std::string& error;
    std::map<uintptr_t, uint32_t> words;
    std::vector<DiscoveryEvidence> evidence;
    size_t visits = 0;
    std::vector<std::pair<bool, bool>> checks{};

    bool fail(const char* message) { if (error.empty()) error = message; return false; }
    bool tick() { return ++visits <= kVisits || fail("ARM64 discovery visit budget exceeded"); }
    bool valid() { return (reader.read && reader.contains) || fail("Missing discovery reader callbacks"); }
    bool range(uintptr_t p, size_t n, bool exec = false) const {
        return p && n <= std::numeric_limits<uintptr_t>::max() - p && reader.contains(reader.context, p, n, exec);
    }
    bool data_range(uintptr_t p, size_t n) const { return range(p, n) && !range(p, 1, true); }
    bool instruction(uintptr_t pc, Insn& out) {
        if (!tick()) return false;
        if (pc != canonical(pc) || (pc & 3) || !range(pc, 4, true))
            return fail("Instruction is outside readable executable module ranges or has an unsupported code pointer tag");
        auto existing = words.find(pc);
        if (existing == words.end()) {
            uint8_t bytes[4];
            if (!reader.read(reader.context, pc, bytes, sizeof(bytes))) return fail("Cannot read ARM64 instruction");
            existing = words.emplace(pc, uint32_t(little(bytes, 4))).first;
        }
        out = decode(pc, existing->second);
        return true;
    }
    bool record(const char* name, uintptr_t p, const void* data, size_t n, bool executable = false, bool in_module = true) {
        const std::string digest = sha256(data, n);
        for (const auto& e : evidence) {
            if (e.address == p && e.length == n) {
                if (e.sha256 != digest) return fail("Discovery evidence changed during analysis");
                return true;
            }
        }
        if (evidence.size() >= 128) return fail("Discovery evidence budget exceeded");
        evidence.push_back({name, p, n, digest});
        checks.emplace_back(executable, in_module);
        return true;
    }
    bool data(const char* name, uintptr_t p, void* out, size_t n, bool in_module = true) {
        if ((in_module && !data_range(p, n)) || !p || n > std::numeric_limits<uintptr_t>::max() - p ||
            !reader.read(reader.context, p, out, n)) return fail("Cannot read module data or raw object descriptor");
        return record(name, p, out, n, false, in_module);
    }
    bool code(const char* name, const std::set<uintptr_t>& addresses) {
        auto it = addresses.begin();
        while (it != addresses.end()) {
            const uintptr_t begin = *it;
            uintptr_t end = begin;
            std::vector<uint8_t> bytes;
            do {
                const uint32_t w = words.at(*it);
                for (unsigned j = 0; j < 4; ++j) bytes.push_back(uint8_t(w >> (j * 8)));
                end = *it + 4;
                ++it;
            } while (it != addresses.end() && *it == end);
            if (!record(name, begin, bytes.data(), bytes.size(), true)) return false;
        }
        return true;
    }
    bool verify() {
        // A second bounded read catches code/GOT/vptr changes before publishing.
        // It does not replace the caller's stable-window/lifetime guarantees.
        for (size_t i = 0; i < evidence.size(); ++i) {
            const auto& e = evidence[i];
            const auto check = checks[i];
            if (check.second && !(check.first ? range(e.address, e.length, true) : data_range(e.address, e.length)))
                return fail("Discovery evidence mapping changed during analysis");
            std::vector<uint8_t> bytes(e.length);
            if (!reader.read(reader.context, e.address, bytes.data(), bytes.size()) || sha256(bytes.data(), bytes.size()) != e.sha256)
                return fail("Discovery evidence changed during analysis");
        }
        return true;
    }
};

// Tiny ABI-preserving B thunks only. PAC, BR/PLT thunks and adjusting thunks
// are deliberately unsupported. Hash every branch and optional BTI/NOP read.
bool follow_thunks(Snapshot& s, uintptr_t& entry, std::set<uintptr_t>& code) {
    std::set<uintptr_t> seen;
    for (unsigned hop = 0; hop <= kThunks; ++hop) {
        if (!seen.insert(entry).second) return s.fail("Cyclic ARM64 tail thunk");
        uintptr_t pc = entry;
        Insn i;
        unsigned padding = 0;
        do {
            if (!s.instruction(pc, i)) return false;
            code.insert(pc);
            if (i.op != Op::Padding) break;
            pc += 4;
        } while (++padding < kTinyInstructions);
        if (i.op == Op::Padding) return s.fail("ARM64 thunk padding budget exceeded");
        if (i.op != Op::Branch) return true;
        if (hop == kThunks) return s.fail("ARM64 tail thunk depth exceeded");
        entry = i.target;
    }
    return false;
}

enum class Kind { Unknown, Argument, Arguments, Opaque, Constant, Stack, Offset, PointerField, WordField,
                  Shift, And, Mask, Cleared, Index, VectorElement };
struct Value {
    Kind kind = Kind::Unknown;
    unsigned a = 0, b = 0, width = 8;
    uint64_t imm = 0;
    bool operator==(const Value& other) const {
        return std::tie(kind, a, b, width, imm) == std::tie(other.kind, other.a, other.b, other.width, other.imm);
    }
};
using Registers = std::array<unsigned, 31>;
struct HotCandidate { uintptr_t address; unsigned image; size_t token; };
struct VectorCandidate { uintptr_t address; unsigned assembly; size_t target; };
struct Function {
    uintptr_t entry = 0;
    std::map<uintptr_t, Insn> code;
    bool complete = true, token_shape = false, vector_shape = false, forwarding = false, used = false;
};

struct RegistryParser {
    Snapshot s;
    std::vector<Value> values{{}};
    std::map<uintptr_t, Function> functions;
    std::set<uintptr_t> active;
    std::vector<HotCandidate> hot;
    std::vector<VectorCandidate> vectors;

    unsigned value(Kind kind, unsigned a = 0, unsigned b = 0, unsigned width = 8, uint64_t imm = 0) {
        const Value v{kind, a, b, width, imm};
        for (unsigned i = 0; i < values.size(); ++i) if (values[i] == v) return i;
        if (values.size() >= kVisits) { s.fail("ARM64 symbolic value budget exceeded"); return 0; }
        values.push_back(v);
        return unsigned(values.size() - 1);
    }
    unsigned constant(uint64_t n, unsigned width = 8) {
        return value(Kind::Constant, 0, 0, width, width == 4 ? n & UINT32_MAX : n);
    }
    unsigned get(const Registers& r, unsigned reg, bool sp = false) {
        return reg == 31 ? (sp ? value(Kind::Stack) : constant(0)) : r[reg];
    }
    bool object(unsigned id) const {
        if (!id) return false;
        const auto& v = values[id];
        return v.width == 8 && (v.kind == Kind::Argument || v.kind == Kind::Opaque ||
               v.kind == Kind::PointerField || v.kind == Kind::Offset);
    }
    unsigned narrow(unsigned id, unsigned width) {
        if (!id || width == 8 || values[id].width == 4) return id;
        if (values[id].kind == Kind::Constant) return constant(values[id].imm & UINT32_MAX, 4);
        return 0;
    }
    unsigned offset(unsigned id, int64_t n, unsigned width = 8) {
        if (!id) return 0;
        const Value v = values[id];
        if (v.kind == Kind::Stack) return id;
        if (v.kind == Kind::Constant) {
            const uint64_t result = v.imm + uint64_t(n);
            return constant(width == 4 ? result & UINT32_MAX : result, width);
        }
        if (width != 8 || !object(id)) return 0;
        if (v.kind == Kind::Offset) { n += int64_t(v.imm); id = v.a; }
        return valid_field(n, 1) ? value(Kind::Offset, id, 0, 8, uint64_t(n)) : 0;
    }
    bool owner(unsigned id) const {
        if (!id || values[id].kind != Kind::PointerField) return false;
        for (const auto& h : hot) if (values[id].a == h.image) return true;
        return false;
    }
    Function* inspect(uintptr_t entry) {
        auto previous = functions.find(entry);
        if (previous != functions.end()) return &previous->second;
        if (functions.size() >= kFunctions) { s.fail("ARM64 discovery function budget exceeded"); return nullptr; }
        Function f; f.entry = entry;
        std::vector<uintptr_t> pending{entry};
        while (!pending.empty() && s.error.empty()) {
            uintptr_t pc = pending.back(); pending.pop_back();
            while (!f.code.count(pc)) {
                if (pc < entry || pc - entry >= kInstructions * 4 || f.code.size() >= kInstructions) {
                    f.complete = false; break;
                }
                Insn i;
                if (!s.instruction(pc, i)) return nullptr;
                f.code.emplace(pc, i);
                f.token_shape |= i.op == Op::ShiftRight && i.width == 4 && i.imm == 22;
                f.vector_shape |= i.op == Op::PairLoad && i.width == 8 && i.rn != 31 && i.mode == 2;
                if (i.op == Op::Unsupported || i.op == Op::Indirect) { f.complete = false; break; }
                if (i.op == Op::Ret) { f.complete &= i.rn == 30; break; }
                if (i.op == Op::Branch) {
                    // Nonlocal B is a tail edge; do not scan neighboring functions.
                    if (pc == entry || i.target < entry || i.target - entry >= kInstructions * 4) break;
                    pc = i.target; continue;
                }
                if (i.op == Op::Cond || i.op == Op::CompareZero || i.op == Op::TestBit) pending.push_back(i.target);
                pc += 4;
            }
        }
        unsigned calls = 0;
        bool forwarding = f.complete && f.code.size() <= 16;
        for (const auto& item : f.code) {
            const Insn& i = item.second;
            if (i.op == Op::Call || i.op == Op::Branch) ++calls;
            else if (i.op != Op::Padding && i.op != Op::Ret && i.op != Op::Mov &&
                     !(i.op == Op::Load && i.width == 8 && i.mode == 0) &&
                     !((i.op == Op::Store || i.op == Op::PairStore || i.op == Op::PairLoad ||
                        i.op == Op::AddImmediate) && (i.rn == 31 || i.rd == 31))) forwarding = false;
        }
        f.forwarding = forwarding && calls == 1;
        return &functions.emplace(entry, std::move(f)).first->second;
    }
    bool masks(uintptr_t address) {
        uint8_t bytes[16];
        if (address & 3) return s.fail("Unaligned token mask table");
        if (!s.data("metadata_v2_token_masks", address, bytes, sizeof(bytes))) return false;
        // A supported HybridCLR metadata-v2 ABI, NOT arbitrary-version inference.
        constexpr uint32_t expected[] = {0x0fffffffu, 0x03ffffffu, 0x00ffffffu, 0x003fffffu};
        for (unsigned i = 0; i < 4; ++i)
            if (little(bytes + i * 4, 4) != expected[i]) return s.fail("Unsupported metadata-v2 token mask table");
        return true;
    }
    unsigned load(const Insn& i, const Registers& r) {
        unsigned base = get(r, i.rn, true);
        if (i.mode == 2) {
            const unsigned index = get(r, i.rm);
            if (!index) return 0;
            const Value x = values[index];
            const Value b = values[base];
            if (i.width == 4 && (i.option == 3 || i.option == 2)) {
                unsigned token = 0;
                // (token >> 28) & 12 is the byte index for masks[token >> 30].
                if (i.shift == 0 && x.kind == Kind::And && x.imm == 12) {
                    const Value shifted = values[x.a];
                    if (shifted.kind == Kind::Shift && shifted.imm == 28) token = shifted.a;
                } else if (i.shift == 2 && x.kind == Kind::Shift && x.imm == 30) token = x.a;
                if (token && values[token].kind == Kind::WordField) {
                    if (b.kind != Kind::Constant) { s.fail("Unresolved token mask table address"); return 0; }
                    if (!masks(b.imm)) return 0;
                    return value(Kind::Mask, token, 0, 4, b.imm);
                }
            }
            if (x.kind == Kind::Index) {
                if (i.width != 8 || (i.option != 3 && i.option != 2) || i.shift != 3 || b.kind != Kind::Constant) {
                    s.fail("Unsupported hot registry pointer indexing"); return 0;
                }
                const Value token = values[x.a];
                // 1024 slots is the ONLY supported container ABI, not a guessed size.
                if ((b.imm & 7) || !s.data_range(b.imm, profile::kHotSlots * 8)) {
                    s.fail("Hot registry is outside the supported 1024-slot module container"); return 0;
                }
                const HotCandidate candidate{uintptr_t(b.imm), token.a, size_t(token.imm)};
                if (std::none_of(hot.begin(), hot.end(), [&](const HotCandidate& h) {
                    return h.address == candidate.address && h.image == candidate.image && h.token == candidate.token;
                })) hot.push_back(candidate);
                return 0;
            }
            return 0;
        }
        if (!base) return 0;
        Value b = values[base];
        if (i.mode == 1 || i.mode == 3) return 0;
        int64_t displacement = i.imm;
        if (b.kind == Kind::Offset) { displacement += int64_t(b.imm); base = b.a; b = values[base]; }
        if (b.kind == Kind::Constant && i.width == 8) {
            uintptr_t address;
            uint8_t bytes[8];
            if (!add_address(b.imm, displacement, address) || (address & 7) ||
                !s.data("module_pointer_cell", address, bytes, sizeof(bytes))) return 0;
            const uintptr_t pointer = canonical(little(bytes, sizeof(bytes)));
            return s.range(pointer, 1) ? constant(pointer) : 0;
        }
        if (!object(base) || !valid_field(displacement, i.width)) return 0;
        if (i.width == 8) return value(Kind::PointerField, base, 0, 8, uint64_t(displacement));
        if (i.width == 4 && b.kind == Kind::PointerField)
            return value(Kind::WordField, base, 0, 4, uint64_t(displacement));
        return 0;
    }
    // Require the entire canonical vector search, including empty check, stride,
    // field comparison, found edge, exhaustion comparison, back edge and null arm.
    // Merely seeing an LDP or a pointer comparison is never sufficient.
    bool vector_walk(const Function& f, uintptr_t pc, Registers& r) {
        const Insn& pair = f.code.at(pc);
        const unsigned base = get(r, pair.rn, true);
        if (!base || values[base].kind != Kind::Constant) return true;
        const bool anchored = std::any_of(r.begin(), r.end(), [&](unsigned id) {
            return id && values[id].kind == Kind::PointerField && values[values[id].a].kind == Kind::PointerField;
        });
        const auto unsupported = [&] { return !anchored || s.fail("Unsupported image-owner vector walk shape"); };
        if (pair.width != 8 || pair.mode != 2 || pair.rd == 31 || pair.rm == 31 || pair.rd == pair.rm) return unsupported();
        uintptr_t address;
        if (!add_address(values[base].imm, pair.imm, address)) return unsupported();
        auto next = [&](uintptr_t& cursor) -> const Insn* {
            do { cursor += 4; } while (f.code.count(cursor) && f.code.at(cursor).op == Op::Padding);
            auto it = f.code.find(cursor);
            return it == f.code.end() ? nullptr : &it->second;
        };
        const auto landing = [&](uintptr_t target) {
            while (f.code.count(target) && f.code.at(target).op == Op::Padding) target += 4;
            return target;
        };
        const unsigned begin = pair.rd, end = pair.rm;
        auto compare_bounds = [&](const Insn* i) {
            return i && i->op == Op::Compare && i->width == 8 &&
                   ((i->rn == begin && i->rm == end) || (i->rn == end && i->rm == begin));
        };
        uintptr_t cursor = pc;
        if (!compare_bounds(next(cursor))) return unsupported();
        const Insn* empty = next(cursor);
        if (!empty || empty->op != Op::Cond || empty->condition != 0) return unsupported();
        const Insn* element = next(cursor); const uintptr_t loop = cursor;
        if (!element || element->op != Op::Load || element->width != 8 || element->mode != 1 ||
            element->rn != begin || element->imm != 8 || element->rd == 31 || element->rd == begin || element->rd == end)
            return unsupported();
        const Insn* target = next(cursor);
        if (!target || target->op != Op::Load || target->width != 8 || target->mode != 0 ||
            target->rn != element->rd || target->rd == 31 || target->rd == begin || target->rd == end ||
            target->rd == element->rd || !valid_field(target->imm, 8)) return unsupported();
        const Insn* cmp = next(cursor);
        if (!cmp || cmp->op != Op::Compare || cmp->width != 8) return unsupported();
        unsigned assembly_reg = 31;
        if (cmp->rn == target->rd) assembly_reg = cmp->rm;
        else if (cmp->rm == target->rd) assembly_reg = cmp->rn;
        if (assembly_reg == 31 || assembly_reg == begin || assembly_reg == end ||
            assembly_reg == element->rd || assembly_reg == target->rd) return unsupported();
        const unsigned assembly = get(r, assembly_reg);
        if (!assembly || values[assembly].kind != Kind::PointerField) return unsupported();
        const Insn* found = next(cursor);
        if (!found || found->op != Op::Cond || found->condition != 0) return unsupported();
        if (!compare_bounds(next(cursor))) return unsupported();
        const Insn* back = next(cursor);
        if (!back || back->op != Op::Cond || back->condition != 1 || landing(back->target) != loop) return unsupported();
        const Insn* zero = next(cursor);
        if (!zero || landing(empty->target) != cursor || zero->rd != element->rd ||
            !((zero->op == Op::Mov && zero->rn == 31 && zero->width == 8) ||
              (zero->op == Op::Immediate && zero->imm == 0))) return unsupported();
        const Insn* join = next(cursor);
        if (!join || landing(found->target) != cursor) return unsupported();
        if ((address & 7) || !s.data_range(address, 3 * 8)) return s.fail("AOT vector is not a module-owned three-pointer container");
        const VectorCandidate candidate{address, assembly, size_t(target->imm)};
        if (std::none_of(vectors.begin(), vectors.end(), [&](const VectorCandidate& v) {
            return std::tie(v.address, v.assembly, v.target) == std::tie(candidate.address, candidate.assembly, candidate.target);
        })) vectors.push_back(candidate);
        // Seed only the element load site proved by the complete walk. Empty
        // paths clear this register in the already-verified null arm.
        r[element->rd] = value(Kind::VectorElement, constant(loop), 0, 8, address);
        return true;
    }
    unsigned analyze(Function& f, Registers initial, unsigned depth) {
        if (!f.complete) { s.fail("Unsupported or oversized ARM64 discovery function"); return 0; }
        if (!active.insert(f.entry).second) { s.fail("Recursive ARM64 discovery helper"); return 0; }
        f.used = true;
        struct State { uintptr_t pc; Registers r; std::set<uintptr_t> seen; int flags = -1; };
        std::vector<State> pending{{f.entry, initial, {}, -1}};
        std::set<unsigned> returns;
        while (!pending.empty() && s.error.empty()) {
            State state = std::move(pending.back()); pending.pop_back();
            while (s.error.empty() && state.seen.insert(state.pc).second) {
                if (!s.tick()) break;
                auto location = f.code.find(state.pc);
                if (location == f.code.end()) { s.fail("ARM64 control flow escaped its bounded function"); break; }
                const Insn i = location->second;
                auto put = [&](unsigned reg, unsigned id) { if (reg < 31) state.r[reg] = id; };
                const unsigned a = get(state.r, i.rn), b = get(state.r, i.rm);
                if (i.op == Op::Ret) { returns.insert(state.r[0]); break; }
                if (i.op == Op::Branch || i.op == Op::Call) {
                    const bool tail = i.op == Op::Branch && !f.code.count(i.target);
                    if (i.op == Op::Branch && !tail) { state.pc = i.target; continue; }
                    const Registers call_arguments = state.r;
                    unsigned result = 0;
                    const bool required = owner(state.r[0]);
                    if (tail || object(state.r[0])) {
                        Function* child = inspect(i.target);
                        if (!child) break;
                        if (!child->complete && (child->token_shape || child->vector_shape)) {
                            s.fail("Unsupported token/vector-bearing helper"); break;
                        }
                        const bool eligible = tail || required || (child->complete &&
                                              (child->token_shape || child->vector_shape || child->forwarding));
                        if (eligible) {
                            if (depth >= kDepth) { s.fail("ARM64 discovery call depth exceeded"); break; }
                            if (!tail && required && !child->vector_shape && !child->forwarding) {
                                s.fail("Unsupported image-owner helper shape"); break;
                            }
                            result = analyze(*child, state.r, depth + 1);
                        }
                    }
                    if (tail) { returns.insert(result); break; }
                    for (unsigned reg = 0; reg <= 18; ++reg) state.r[reg] = 0;
                    state.r[30] = 0;
                    if (!result) {
                        // Do not merge opaque returns from different argument
                        // contexts merely because the machine callsite is equal.
                        unsigned arguments = 0;
                        for (unsigned reg = 0; reg < 8; ++reg)
                            arguments = value(Kind::Arguments, arguments, call_arguments[reg], 8, reg);
                        result = value(Kind::Opaque, arguments, 0, 8, state.pc);
                    }
                    state.r[0] = result;
                    state.flags = -1;
                } else if (i.op == Op::Cond || i.op == Op::CompareZero || i.op == Op::TestBit) {
                    int take = -1;
                    if (i.op == Op::Cond && state.flags >= 0) take = condition_true(state.flags, i.condition);
                    if (i.op != Op::Cond) {
                        const unsigned id = get(state.r, i.rd);
                        if (id && values[id].kind == Kind::Constant) {
                            const uint64_t bits = values[id].imm & (i.width == 4 ? UINT32_MAX : UINT64_MAX);
                            const bool nonzero = i.op == Op::TestBit ? ((bits >> i.imm) & 1) != 0 : bits != 0;
                            take = nonzero == bool(i.condition);
                        }
                    }
                    if (take == 1) { state.pc = i.target; continue; }
                    if (take < 0) {
                        State taken = state; taken.pc = i.target;
                        pending.push_back(std::move(taken));
                    }
                } else if (i.op == Op::Select) {
                    if (state.flags >= 0) put(i.rd, narrow(condition_true(state.flags, i.condition) ? a : b, i.width));
                    else {
                        State other = state; other.pc += 4;
                        if (i.rd < 31) other.r[i.rd] = narrow(b, i.width);
                        pending.push_back(std::move(other)); put(i.rd, narrow(a, i.width));
                    }
                } else if (i.op == Op::Mov) put(i.rd, narrow(a, i.width));
                else if (i.op == Op::Immediate) put(i.rd, constant(uint64_t(i.imm), i.width));
                else if (i.op == Op::Adr) put(i.rd, constant(i.target));
                else if (i.op == Op::AddImmediate) {
                    const unsigned source = get(state.r, i.rn, true);
                    if (i.word & 0x20000000u)
                        state.flags = source && values[source].kind == Kind::Constant ?
                            comparison_flags(values[source].imm, uint64_t(i.imm < 0 ? -i.imm : i.imm), i.width,
                                             (i.word & 0x40000000u) != 0) : -1;
                    put(i.rd, offset(source, i.imm, i.width));
                }
                else if (i.op == Op::AddRegister) {
                    put(i.rd, a && b && values[a].kind == Kind::Constant && values[b].kind == Kind::Constant ?
                        constant(values[a].imm + values[b].imm, i.width) : 0);
                }
                else if (i.op == Op::ShiftRight) {
                    unsigned result = 0;
                    if (a && values[a].kind == Kind::Constant) {
                        const uint64_t source = values[a].imm & (i.width == 4 ? UINT32_MAX : UINT64_MAX);
                        result = constant(source >> unsigned(i.imm), i.width);
                    } else if (a && values[a].kind == Kind::Cleared) {
                        if (i.width != 4 || i.imm != 22) { s.fail("Unsupported token index shift or width"); break; }
                        result = value(Kind::Index, values[a].a, 0, 4);
                    }
                    else if (a && values[a].kind == Kind::WordField && (i.imm == 28 || i.imm == 30))
                        result = value(Kind::Shift, a, 0, i.width, uint64_t(i.imm));
                    put(i.rd, result);
                } else if (i.op == Op::AndImmediate) {
                    put(i.rd, a ? (values[a].kind == Kind::Constant ?
                        constant(values[a].imm & uint64_t(i.imm), i.width) :
                        value(Kind::And, a, 0, i.width, uint64_t(i.imm))) : 0);
                } else if (i.op == Op::Bic) {
                    const bool token_like = (a && values[a].kind == Kind::WordField) || (b && values[b].kind == Kind::Mask);
                    if (token_like && (i.width != 4 || !a || !b || values[a].kind != Kind::WordField ||
                        values[b].kind != Kind::Mask || values[b].a != a)) {
                        s.fail("Unsupported token clearing width or provenance"); break;
                    }
                    if (a && b && values[a].kind == Kind::Constant && values[b].kind == Kind::Constant)
                        put(i.rd, constant(values[a].imm & ~values[b].imm, i.width));
                    else put(i.rd, i.width == 4 && a && b && values[a].kind == Kind::WordField &&
                        values[b].kind == Kind::Mask && values[b].a == a ? value(Kind::Cleared, a, b, 4) : 0);
                } else if (i.op == Op::Load) {
                    const unsigned prior = get(state.r, i.rd);
                    const bool selected = prior && values[prior].kind == Kind::VectorElement &&
                        i.width == 8 && i.mode == 1 && i.imm == 8 && values[values[prior].a].imm == state.pc;
                    const unsigned loaded = selected ? prior : load(i, state.r); put(i.rd, loaded);
                    if (i.mode == 1 || i.mode == 3) put(i.rn, 0);
                } else if (i.op == Op::PairLoad) {
                    if (!vector_walk(f, state.pc, state.r)) break;
                    put(i.rd, 0); put(i.rm, 0);
                    if (i.mode != 2) put(i.rn, 0);
                } else if (i.op == Op::Store || i.op == Op::PairStore) {
                    if ((i.op == Op::Store && (i.mode == 1 || i.mode == 3)) || (i.op == Op::PairStore && i.mode != 2))
                        put(i.rn, 0);
                } else if (i.op == Op::Compare || i.op == Op::CompareImmediate) {
                    const bool immediate = i.op == Op::CompareImmediate;
                    const unsigned source = get(state.r, i.rn, immediate);
                    const bool known = source && values[source].kind == Kind::Constant &&
                                       (immediate || (b && values[b].kind == Kind::Constant));
                    const uint64_t rhs = immediate ? uint64_t(i.imm < 0 ? -i.imm : i.imm) : values[b].imm;
                    state.flags = known ? comparison_flags(values[source].imm, rhs, i.width,
                                   !immediate || (i.word & 0x40000000u)) : -1;
                } else if (i.op != Op::Padding) {
                    s.fail("Unsupported ARM64 semantic instruction"); break;
                }
                state.pc += 4;
            }
        }
        active.erase(f.entry);
        if (s.error.empty() && owner(initial[0])) {
            unsigned image = 0;
            for (unsigned returned : returns) {
                const Value v = values[returned];
                if (v.kind == Kind::Constant && v.imm == 0) continue;
                const bool selected = v.kind == Kind::VectorElement && std::any_of(vectors.begin(), vectors.end(), [&](const VectorCandidate& candidate) {
                    return candidate.assembly == initial[0] && candidate.address == v.imm;
                });
                if (!selected) { s.fail("AOT assembly helper does not return the searched image"); return 0; }
                if (image && values[image].imm != v.imm) { s.fail("Ambiguous AOT helper return images"); return 0; }
                image = returned;
            }
            if (!image) { s.fail("AOT assembly helper has no proved image return"); return 0; }
            // Null remains possible: the marker is not a known nonzero constant.
            return image;
        }
        return returns.size() == 1 ? *returns.begin() : 0;
    }
    bool run(uintptr_t entry, RegistryDiscovery& out) {
        if (!s.valid()) return false;
        std::set<uintptr_t> thunks;
        if (!follow_thunks(s, entry, thunks)) return false;
        Function* root = inspect(entry);
        if (!root) return false;
        Registers initial{}; initial[0] = value(Kind::Argument);
        analyze(*root, initial, 0);
        if (!s.error.empty()) return false;
        using Match = std::tuple<uintptr_t, uintptr_t, size_t, size_t, size_t>;
        std::set<Match> matches;
        std::set<std::pair<uintptr_t, size_t>> hot_layouts;
        for (const auto& h : hot) {
            hot_layouts.emplace(h.address, h.token);
            for (const auto& v : vectors) {
                const Value assembly = values[v.assembly];
                if (assembly.kind == Kind::PointerField && assembly.a == h.image && valid_field(assembly.imm, 8) &&
                    !overlaps(h.token, 4, size_t(assembly.imm), 8))
                    matches.emplace(h.address, v.address, h.token, size_t(assembly.imm), v.target);
            }
        }
        if (hot_layouts.size() > 1 || matches.size() > 1) return s.fail("Ambiguous registry or field discovery candidates");
        if (matches.empty()) return s.fail("No complete supported token/registry/image-owner/vector semantic match");
        if (!s.code("pre_jit_entry_chain", thunks)) return false;
        for (const auto& item : functions) {
            std::set<uintptr_t> pcs;
            for (const auto& instruction : item.second.code) pcs.insert(instruction.first);
            const char* name = item.first == entry ? "pre_jit_class_code" :
                               item.second.used ? "registry_helper_code" : "registry_probe_code";
            if (!s.code(name, pcs)) return false;
        }
        if (!s.verify()) return false;
        const auto& match = *matches.begin();
        out.hot_registry = std::get<0>(match); out.aot_vector = std::get<1>(match);
        out.image_token = std::get<2>(match); out.image_assembly = std::get<3>(match);
        out.aot_target_assembly = std::get<4>(match); out.evidence = std::move(s.evidence);
        return true;
    }
};

enum class RawValue { Unknown, This, Data, Length, End, Stack };
struct RawFields {
    size_t data = 0, length = 0, end = 0;
    uintptr_t entry = 0;
    std::set<uintptr_t> code;
};

bool raw_prefix(Snapshot& s, uintptr_t entry, RawFields& result, bool& match) {
    match = false;
    std::set<uintptr_t> code;
    if (!follow_thunks(s, entry, code)) return false;
    std::array<RawValue, 31> r{};
    r[0] = RawValue::This; r[1] = RawValue::Data; r[2] = RawValue::Length;
    const auto get = [&](unsigned reg, bool sp = false) { return reg == 31 ? (sp ? RawValue::Stack : RawValue::Unknown) : r[reg]; };
    std::array<bool, 3> found{};
    std::array<size_t, 3> fields{};
    bool invalid = false, boundary = false, loader_like = false;
    for (unsigned n = 0; n < kTinyInstructions; ++n) {
        const uintptr_t pc = entry + n * 4;
        Insn i;
        if (!s.instruction(pc, i)) return false;
        code.insert(pc);
        const auto put = [&](unsigned reg, RawValue v) { if (reg < 31) r[reg] = v; };
        if ((i.op == Op::Ret && i.rn != 30) || (i.op == Op::Indirect && (i.word & 0xfffffc1fu) != 0xd63f0000u)) {
            invalid = true; break;
        }
        if (i.op == Op::Ret || i.op == Op::Call || i.op == Op::Indirect || i.op == Op::Branch ||
            i.op == Op::Cond || i.op == Op::CompareZero || i.op == Op::TestBit) { boundary = true; break; }
        if (i.op == Op::Mov) {
            const RawValue v = get(i.rn);
            put(i.rd, i.width == 8 || v == RawValue::Length ? v : RawValue::Unknown);
        } else if (i.op == Op::AddRegister) {
            const RawValue a = get(i.rn), b = get(i.rm);
            put(i.rd, i.width == 8 && ((a == RawValue::Data && b == RawValue::Length) ||
                (b == RawValue::Data && a == RawValue::Length)) ? RawValue::End : RawValue::Unknown);
        } else if (i.op == Op::AddImmediate) {
            put(i.rd, i.width == 8 && get(i.rn, true) == RawValue::Stack ? RawValue::Stack :
                (i.imm == 0 && i.width == 8 ? get(i.rn) : RawValue::Unknown));
        } else if (i.op == Op::Store && get(i.rn, true) == RawValue::This) {
            if (i.mode != 0) invalid = true;
            const RawValue v = get(i.rd);
            int role = v == RawValue::Data ? 0 : v == RawValue::Length ? 1 : v == RawValue::End ? 2 : -1;
            if (role >= 0) {
                loader_like = true;
                const size_t width = role == 1 ? 4 : 8;
                if (i.mode != 0 || i.width != width || i.imm < 8 || !valid_field(i.imm, width, 0x200)) invalid = true;
                else if (found[size_t(role)] && fields[size_t(role)] != size_t(i.imm)) invalid = true;
                else { found[size_t(role)] = true; fields[size_t(role)] = size_t(i.imm); }
            } else {
                for (size_t j = 0; j < 3; ++j)
                    if (found[j] && i.mode == 0 && i.imm >= 0 && overlaps(fields[j], j == 1 ? 4 : 8, size_t(i.imm), i.width)) invalid = true;
            }
            if (i.mode == 1 || i.mode == 3) put(i.rn, RawValue::Unknown);
        } else if (i.op == Op::Load || i.op == Op::Immediate || i.op == Op::Adr || i.op == Op::AndImmediate ||
                   i.op == Op::ShiftRight || i.op == Op::Bic || i.op == Op::Select) {
            put(i.rd, RawValue::Unknown);
            if (i.op == Op::Load && (i.mode == 1 || i.mode == 3)) put(i.rn, RawValue::Unknown);
        } else if (i.op == Op::PairLoad) {
            put(i.rd, RawValue::Unknown); put(i.rm, RawValue::Unknown);
            if (i.mode != 2) put(i.rn, RawValue::Unknown);
        } else if (i.op == Op::PairStore || i.op == Op::Store) {
            // Non-object stores are supported only to SP-derived stack memory.
            // An unmodeled alias must not hide a second loader-like candidate.
            if (get(i.rn, true) != RawValue::Stack) {
                invalid = true;
                for (unsigned reg : {i.rd, i.op == Op::PairStore ? i.rm : 31u}) {
                    const RawValue v = get(reg);
                    loader_like |= v == RawValue::Data || v == RawValue::Length || v == RawValue::End;
                }
            }
            if ((i.op == Op::Store && (i.mode == 1 || i.mode == 3)) || (i.op == Op::PairStore && i.mode != 2))
                put(i.rn, RawValue::Unknown);
        } else if (i.op != Op::Padding && i.op != Op::Compare && i.op != Op::CompareImmediate) {
            invalid = true; break;
        }
    }
    const unsigned count = unsigned(found[0]) + unsigned(found[1]) + unsigned(found[2]);
    if ((invalid || !boundary || count != 3) && loader_like)
        return s.fail("Unsupported or incomplete raw loader store prefix");
    if (invalid || !boundary || count != 3) return true;
    if (overlaps(fields[0], 8, fields[1], 4) || overlaps(fields[0], 8, fields[2], 8) || overlaps(fields[1], 4, fields[2], 8))
        return s.fail("Overlapping raw loader fields");
    result = {fields[0], fields[1], fields[2], entry, std::move(code)};
    match = true;
    return true;
}

struct LiveReader { const Memory& memory; const Module& module; };
Reader live_reader(const LiveReader& live) {
    return {&live,
        [](const void* context, uintptr_t p, void* out, size_t n) {
            return static_cast<const LiveReader*>(context)->memory.read(p, out, n);
        },
        [](const void* context, uintptr_t p, size_t n, bool executable) {
            const auto& c = *static_cast<const LiveReader*>(context);
            return c.module.contains(p, n, executable) &&
                   (executable ? c.memory.executable(p, n) : c.memory.readable(p, n));
        }};
}

} // namespace

namespace discovery_detail {

bool discover_registries(const Reader& reader, uintptr_t entry, RegistryDiscovery& out, std::string& error) {
    out = {}; error.clear();
    RegistryParser parser{{reader, error, {}, {}, 0, {}}, {{}}, {}, {}, {}, {}};
    return parser.run(entry, out);
}

bool discover_pointer_getter(const Reader& reader, uintptr_t entry, size_t& field,
                            std::vector<DiscoveryEvidence>& evidence, std::string& error) {
    field = 0; error.clear();
    Snapshot s{reader, error, {}, {}, 0, {}};
    if (!s.valid()) return false;
    std::set<uintptr_t> code;
    if (!follow_thunks(s, entry, code)) return false;
    struct Origin { bool self = false, loaded = false; size_t offset = 0; };
    std::array<Origin, 31> r{}; r[0].self = true;
    std::set<size_t> fields;
    for (unsigned n = 0; n < kTinyInstructions; ++n) {
        const uintptr_t pc = entry + n * 4;
        Insn i;
        if (!s.instruction(pc, i)) return false;
        code.insert(pc);
        if (i.op == Op::Padding) continue;
        if (i.op == Op::Ret) {
            if (i.rn != 30 || !r[0].loaded || fields.size() != 1) return s.fail("Pointer getter does not return a unique 64-bit this field");
            if (!s.code("pointer_getter_code", code) || !s.verify()) return false;
            field = r[0].offset;
            evidence.insert(evidence.end(), s.evidence.begin(), s.evidence.end());
            return true;
        }
        if (i.op == Op::Mov && i.width == 8 && i.rd < 31 && i.rn < 31) r[i.rd] = r[i.rn];
        else if (i.op == Op::Load && i.width == 8 && i.mode == 0 && i.rn < 31 && i.rd < 31 &&
                 r[i.rn].self && valid_field(i.imm, 8)) {
            fields.insert(size_t(i.imm)); r[i.rd] = {false, true, size_t(i.imm)};
        } else return s.fail("Unsupported pointer getter instruction or provenance");
    }
    return s.fail("Pointer getter instruction budget exceeded");
}

bool discover_raw_layout(const Reader& reader, uintptr_t raw_object, profile::Layout& layout,
                         std::vector<DiscoveryEvidence>& evidence, std::string& error) {
    error.clear();
    Snapshot s{reader, error, {}, {}, 0, {}};
    if (!s.valid()) return false;
    uint8_t pointer[8], slots[kVtableSlots * 8];
    raw_object = canonical(raw_object);
    // Itanium C++ vptr at +0 is the supported ABI; no RTTI/heap search is made.
    if (raw_object & 7) return s.fail("Unaligned raw object vptr");
    if (!s.data("raw_object_vptr", raw_object, pointer, sizeof(pointer), false)) return false;
    const uintptr_t vptr = canonical(little(pointer, 8));
    if (vptr & 7) return s.fail("Unaligned raw vtable pointer");
    if (!s.data("raw_vtable_slots", vptr, slots, sizeof(slots))) return false;
    std::map<uintptr_t, RawFields> candidates;
    std::set<uintptr_t> entries;
    for (size_t slot = 0; slot < kVtableSlots; ++slot) {
        const uintptr_t entry = uintptr_t(little(slots + slot * 8, 8));
        if (entry != canonical(entry) || (entry & 3) || !s.range(entry, 4, true))
            return s.fail("Raw vtable slot is not readable module executable code or has an unsupported code pointer tag");
        if (!entries.insert(entry).second) continue;
        RawFields candidate;
        bool match;
        if (!raw_prefix(s, entry, candidate, match)) return false;
        if (match) candidates.emplace(candidate.entry, std::move(candidate));
    }
    if (candidates.size() != 1) return s.fail(candidates.empty() ? "No supported raw loader prefix in bounded vtable" : "Ambiguous raw loader methods");
    const RawFields& found = candidates.begin()->second;
    std::set<uintptr_t> inspected;
    for (const auto& word : s.words) inspected.insert(word.first);
    if (!s.code("raw_loader_prefix", found.code) || !s.code("raw_vtable_code_probes", inspected) || !s.verify()) return false;
    layout.raw_data = found.data; layout.raw_length = found.length; layout.raw_end = found.end;
    evidence.insert(evidence.end(), s.evidence.begin(), s.evidence.end());
    return true;
}

} // namespace discovery_detail

bool discover_registries(const Memory& memory, const Module& module, uintptr_t entry,
                         RegistryDiscovery& out, std::string& error) {
    const LiveReader live{memory, module};
    return discovery_detail::discover_registries(live_reader(live), entry, out, error);
}
bool discover_pointer_getter(const Memory& memory, const Module& module, uintptr_t entry, size_t& field,
                            std::vector<DiscoveryEvidence>& evidence, std::string& error) {
    const LiveReader live{memory, module};
    return discovery_detail::discover_pointer_getter(live_reader(live), entry, field, evidence, error);
}
bool discover_raw_layout(const Memory& memory, const Module& module, uintptr_t raw_object, profile::Layout& layout,
                         std::vector<DiscoveryEvidence>& evidence, std::string& error) {
    const LiveReader live{memory, module};
    return discovery_detail::discover_raw_layout(live_reader(live), raw_object, layout, evidence, error);
}

} // namespace hcd
