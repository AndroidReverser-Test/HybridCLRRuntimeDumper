#include "format.h"

#include <algorithm>
#include <array>
#include <vector>

namespace hcd {
namespace {

struct Bytes {
    const uint8_t* data = nullptr;
    uint64_t size = 0;

    bool contains(uint64_t offset, uint64_t length) const {
        return offset <= size && length <= size - offset;
    }

    // Reads and slices require a previously bounded record or contains().
    uint8_t u8(uint64_t offset) const { return data[static_cast<size_t>(offset)]; }
    uint16_t u16(uint64_t offset) const {
        return static_cast<uint16_t>(uint16_t(u8(offset)) | (uint16_t(u8(offset + 1)) << 8));
    }
    uint32_t u32(uint64_t offset) const {
        return uint32_t(u8(offset)) | (uint32_t(u8(offset + 1)) << 8) |
               (uint32_t(u8(offset + 2)) << 16) | (uint32_t(u8(offset + 3)) << 24);
    }
    uint64_t u64(uint64_t offset) const {
        return uint64_t(u32(offset)) | (uint64_t(u32(offset + 4)) << 32);
    }
    uint32_t index(uint64_t offset, unsigned width) const {
        return width == 2 ? u16(offset) : u32(offset);
    }
    Bytes slice(uint64_t offset, uint64_t length) const {
        return {data + static_cast<size_t>(offset), length};
    }
};

bool fail(FileInfo& info, const std::string& reason) {
    info.reason = reason;
    return false;
}

bool overlaps(uint64_t a, uint64_t an, uint64_t b, uint64_t bn) {
    return an != 0 && bn != 0 && a < b + bn && b < a + an;
}

uint64_t align_up(uint64_t value, uint64_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

enum StreamKind { Tables, Strings, UserStrings, Guids, Blobs, Pdb, StreamCount };

struct Stream {
    bool present = false;
    uint64_t offset = 0;
    Bytes bytes;
};

struct Metadata {
    std::array<Stream, StreamCount> streams{};
    bool uncompressed = false;
};

bool read_root(Bytes root, bool pdb, Metadata& metadata, FileInfo& info) {
    if (!root.contains(0, 16) || root.u32(0) != 0x424a5342u) {
        return fail(info, "Missing or truncated BSJB metadata root");
    }
    if (root.u16(4) != 1 || root.u16(6) != 1 || root.u32(8) != 0) {
        return fail(info, "Unsupported metadata root version or reserved fields");
    }
    const uint64_t version_size = root.u32(12);
    if (version_size == 0 || (version_size & 3) != 0 || !root.contains(16, version_size)) {
        return fail(info, "Invalid metadata version string range or alignment");
    }
    uint64_t terminator = 0;
    while (terminator < version_size && root.u8(16 + terminator) != 0) ++terminator;
    if (terminator == version_size) return fail(info, "Unterminated metadata version string");
    for (uint64_t i = terminator; i < version_size; ++i) {
        if (root.u8(16 + i) != 0) return fail(info, "Nonzero metadata version padding");
    }
    uint64_t cursor = 16 + version_size;
    if (!root.contains(cursor, 4)) return fail(info, "Truncated metadata storage header");
    if (root.u16(cursor) != 0) return fail(info, "Unsupported metadata storage flags");
    const unsigned count = root.u16(cursor + 2);
    if (count == 0 || count > StreamCount) return fail(info, "Unsupported metadata stream count");
    cursor += 4;

    for (unsigned i = 0; i < count; ++i) {
        if (!root.contains(cursor, 8)) return fail(info, "Truncated metadata stream header");
        const uint64_t offset = root.u32(cursor);
        const uint64_t length = root.u32(cursor + 4);
        cursor += 8;
        uint64_t name_size = 0;
        while (name_size < 32 && root.contains(cursor + name_size, 1) &&
               root.u8(cursor + name_size) != 0) {
            ++name_size;
        }
        if (name_size == 0 || name_size == 32 || !root.contains(cursor + name_size, 1)) {
            return fail(info, "Invalid metadata stream name");
        }
        const std::string name(reinterpret_cast<const char*>(root.data + static_cast<size_t>(cursor)),
                               static_cast<size_t>(name_size));
        const uint64_t padded_name = align_up(name_size + 1, 4);
        if (!root.contains(cursor, padded_name)) return fail(info, "Truncated stream name padding");
        for (uint64_t j = name_size; j < padded_name; ++j) {
            if (root.u8(cursor + j) != 0) return fail(info, "Nonzero stream name padding");
        }
        cursor += padded_name;

        StreamKind kind;
        if (name == "#~" || name == "#-") {
            kind = Tables;
            metadata.uncompressed = name == "#-";
        } else if (name == "#Strings") {
            kind = Strings;
        } else if (name == "#US") {
            kind = UserStrings;
        } else if (name == "#GUID") {
            kind = Guids;
        } else if (name == "#Blob") {
            kind = Blobs;
        } else if (name == "#Pdb" && pdb) {
            kind = Pdb;
        } else {
            return fail(info, "Unsupported metadata stream: " + name);
        }
        Stream& stream = metadata.streams[kind];
        if (stream.present) return fail(info, "Duplicate metadata stream: " + name);
        if ((offset & 3) != 0 || !root.contains(offset, length)) {
            return fail(info, "Invalid metadata stream range: " + name);
        }
        stream = {true, offset, root.slice(offset, length)};
    }

    for (unsigned i = 0; i < StreamCount; ++i) {
        const Stream& stream = metadata.streams[i];
        if (!stream.present) continue;
        if (stream.offset < cursor) return fail(info, "Metadata stream overlaps root headers");
        for (unsigned j = 0; j < i; ++j) {
            const Stream& other = metadata.streams[j];
            if (other.present && overlaps(stream.offset, stream.bytes.size, other.offset, other.bytes.size)) {
                return fail(info, "Overlapping metadata streams");
            }
        }
    }
    if (!metadata.streams[Tables].present || !metadata.streams[Tables].bytes.contains(0, 24)) {
        return fail(info, "Missing or truncated metadata tables stream");
    }
    for (StreamKind kind : {Strings, UserStrings, Blobs}) {
        const Bytes heap = metadata.streams[kind].bytes;
        if (heap.size != 0 && heap.u8(0) != 0) return fail(info, "Invalid metadata heap null entry");
    }
    const Bytes strings = metadata.streams[Strings].bytes;
    if (strings.size != 0 && strings.u8(strings.size - 1) != 0) {
        return fail(info, "Unterminated Strings heap");
    }
    if ((metadata.streams[Guids].bytes.size & 15) != 0) {
        return fail(info, "GUID heap size is not a multiple of 16");
    }
    return true;
}

constexpr uint64_t kTableMask = (uint64_t(1) << 45) - 1;
constexpr uint64_t kPointerMask = (uint64_t(1) << 3) | (uint64_t(1) << 5) |
    (uint64_t(1) << 7) | (uint64_t(1) << 19) | (uint64_t(1) << 22);
constexpr uint64_t kEncMask = (uint64_t(1) << 30) | (uint64_t(1) << 31);

bool read_pdb(const Metadata& metadata, FileInfo& info) {
    const Stream& stream = metadata.streams[Pdb];
    if (!stream.present || !stream.bytes.contains(0, 32)) {
        return fail(info, "Missing or truncated Portable PDB #Pdb stream");
    }
    const Bytes pdb = stream.bytes;
    const uint32_t entry = pdb.u32(20);
    const uint64_t mask = pdb.u64(24);
    if ((mask & ~(kTableMask & ~kPointerMask & ~kEncMask)) != 0) {
        return fail(info, "Unsupported Portable PDB referenced tables");
    }
    uint64_t cursor = 32;
    uint32_t methods = 0;
    for (unsigned table = 0; table < 45; ++table) {
        if ((mask & (uint64_t(1) << table)) == 0) continue;
        if (!pdb.contains(cursor, 4)) return fail(info, "Truncated #Pdb external row counts");
        const uint32_t rows = pdb.u32(cursor);
        if (rows > 0x00ffffffu) return fail(info, "Invalid #Pdb external row count");
        if (table == 6) methods = rows;
        cursor += 4;
    }
    if (cursor != pdb.size) return fail(info, "Unsupported #Pdb stream trailing layout");
    if (entry != 0 && ((entry >> 24) != 6 || (entry & 0x00ffffffu) == 0 ||
                       (entry & 0x00ffffffu) > methods)) {
        return fail(info, "Invalid Portable PDB entry point token");
    }
    // Debug tables (0x30 and above) are intentionally not interpreted here.
    return true;
}

enum Column : uint8_t { End, U16, U32, StringIndex, GuidIndex, BlobIndex };
constexpr uint8_t table_column(unsigned table) { return static_cast<uint8_t>(16 + table); }
constexpr uint8_t list_column(unsigned table) { return static_cast<uint8_t>(64 + table); }
constexpr uint8_t coded_column(unsigned coded) { return static_cast<uint8_t>(112 + coded); }

enum CodedKind {
    TypeDefOrRef, HasConstant, HasCustomAttribute, HasFieldMarshal, HasDeclSecurity,
    MemberRefParent, HasSemantics, MethodDefOrRef, MemberForwarded, Implementation,
    CustomAttributeType, ResolutionScope, TypeOrMethodDef, CodedCount
};

struct CodedIndex {
    unsigned bits;
    unsigned count;
    std::array<int8_t, 22> tables;
};

constexpr CodedIndex kCoded[CodedCount] = {
    {2, 3, {2, 1, 27}},
    {2, 3, {4, 8, 23}},
    {5, 22, {6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35,
             38, 39, 40, 42, 44, 43}},
    {1, 2, {4, 8}},
    {2, 3, {2, 6, 32}},
    {3, 5, {2, 1, 26, 6, 27}},
    {1, 2, {20, 23}},
    {1, 2, {6, 10}},
    {1, 2, {4, 6}},
    {2, 3, {38, 35, 39}},
    {3, 4, {-1, -1, 6, 10}},
    {2, 4, {0, 26, 35, 1}},
    {1, 2, {2, 6}}
};

constexpr uint8_t kColumns[45][10] = {
    {U16, StringIndex, GuidIndex, GuidIndex, GuidIndex}, // 0: Module
    {coded_column(ResolutionScope), StringIndex, StringIndex}, // 1: TypeRef
    {U32, StringIndex, StringIndex, coded_column(TypeDefOrRef), list_column(4), list_column(6)}, // 2: TypeDef
    {table_column(4)}, // 3: FieldPtr
    {U16, StringIndex, BlobIndex}, // 4: Field
    {table_column(6)}, // 5: MethodPtr
    {U32, U16, U16, StringIndex, BlobIndex, list_column(8)}, // 6: MethodDef
    {table_column(8)}, // 7: ParamPtr
    {U16, U16, StringIndex}, // 8: Param
    {table_column(2), coded_column(TypeDefOrRef)}, // 9: InterfaceImpl
    {coded_column(MemberRefParent), StringIndex, BlobIndex}, // 10: MemberRef
    {U16, coded_column(HasConstant), BlobIndex}, // 11: Constant
    {coded_column(HasCustomAttribute), coded_column(CustomAttributeType), BlobIndex}, // 12: CustomAttribute
    {coded_column(HasFieldMarshal), BlobIndex}, // 13: FieldMarshal
    {U16, coded_column(HasDeclSecurity), BlobIndex}, // 14: DeclSecurity
    {U16, U32, table_column(2)}, // 15: ClassLayout
    {U32, table_column(4)}, // 16: FieldLayout
    {BlobIndex}, // 17: StandAloneSig
    {table_column(2), list_column(20)}, // 18: EventMap
    {table_column(20)}, // 19: EventPtr
    {U16, StringIndex, coded_column(TypeDefOrRef)}, // 20: Event
    {table_column(2), list_column(23)}, // 21: PropertyMap
    {table_column(23)}, // 22: PropertyPtr
    {U16, StringIndex, BlobIndex}, // 23: Property
    {U16, table_column(6), coded_column(HasSemantics)}, // 24: MethodSemantics
    {table_column(2), coded_column(MethodDefOrRef), coded_column(MethodDefOrRef)}, // 25: MethodImpl
    {StringIndex}, // 26: ModuleRef
    {BlobIndex}, // 27: TypeSpec
    {U16, coded_column(MemberForwarded), StringIndex, table_column(26)}, // 28: ImplMap
    {U32, table_column(4)}, // 29: FieldRVA
    {U32, U32}, // 30: EncLog
    {U32}, // 31: EncMap
    {U32, U16, U16, U16, U16, U32, BlobIndex, StringIndex, StringIndex}, // 32: Assembly
    {U32}, // 33: AssemblyProcessor
    {U32, U32, U32}, // 34: AssemblyOS
    {U16, U16, U16, U16, U32, BlobIndex, StringIndex, StringIndex, BlobIndex}, // 35: AssemblyRef
    {U32, table_column(35)}, // 36: AssemblyRefProcessor
    {U32, U32, U32, table_column(35)}, // 37: AssemblyRefOS
    {U32, StringIndex, BlobIndex}, // 38: File
    {U32, U32, StringIndex, StringIndex, coded_column(Implementation)}, // 39: ExportedType
    {U32, U32, StringIndex, coded_column(Implementation)}, // 40: ManifestResource
    {table_column(2), table_column(2)}, // 41: NestedClass
    {U16, U16, coded_column(TypeOrMethodDef), StringIndex}, // 42: GenericParam
    {coded_column(MethodDefOrRef), BlobIndex}, // 43: MethodSpec
    {table_column(42), coded_column(TypeDefOrRef)} // 44: GenericParamConstraint
};

unsigned pointer_table(unsigned table) {
    switch (table) {
        case 4: return 3;
        case 6: return 5;
        case 8: return 7;
        case 20: return 19;
        case 23: return 22;
        default: return table;
    }
}

bool blob_in_range(Bytes heap, uint32_t index) {
    if (index == 0) return true;
    if (!heap.contains(index, 1)) return false;
    const uint8_t first = heap.u8(index);
    uint64_t length;
    unsigned prefix;
    if ((first & 0x80) == 0) {
        prefix = 1;
        length = first;
    } else if ((first & 0xc0) == 0x80) {
        if (!heap.contains(index, 2)) return false;
        prefix = 2;
        length = (uint64_t(first & 0x3f) << 8) | heap.u8(uint64_t(index) + 1);
        if (length < 0x80) return false;
    } else if ((first & 0xe0) == 0xc0) {
        if (!heap.contains(index, 4)) return false;
        prefix = 4;
        length = (uint64_t(first & 0x1f) << 24) | (uint64_t(heap.u8(uint64_t(index) + 1)) << 16) |
                 (uint64_t(heap.u8(uint64_t(index) + 2)) << 8) | heap.u8(uint64_t(index) + 3);
        if (length < 0x4000) return false;
    } else {
        return false;
    }
    return heap.contains(uint64_t(index) + prefix, length);
}

bool valid_utf8(const std::string& text) {
    size_t cursor = 0;
    while (cursor < text.size()) {
        const uint8_t first = static_cast<uint8_t>(text[cursor++]);
        if (first < 0x80) continue;
        unsigned count;
        uint32_t value;
        uint32_t minimum;
        if (first >= 0xc2 && first <= 0xdf) {
            count = 1; value = first & 0x1f; minimum = 0x80;
        } else if (first >= 0xe0 && first <= 0xef) {
            count = 2; value = first & 0x0f; minimum = 0x800;
        } else if (first >= 0xf0 && first <= 0xf4) {
            count = 3; value = first & 7; minimum = 0x10000;
        } else {
            return false;
        }
        if (count > text.size() - cursor) return false;
        for (unsigned i = 0; i < count; ++i) {
            const uint8_t next = static_cast<uint8_t>(text[cursor++]);
            if ((next & 0xc0) != 0x80) return false;
            value = (value << 6) | (next & 0x3f);
        }
        if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return false;
    }
    return true;
}

bool read_tables(const Metadata& metadata, uint32_t entry_token, FileInfo& info) {
    const Bytes tables = metadata.streams[Tables].bytes;
    if (!tables.contains(0, 24)) return fail(info, "Truncated metadata tables header");
    // Cecil uses Reserved2=0x0a; it does not change the table layout.
    if (tables.u32(0) != 0 || tables.u8(4) != 2 || tables.u8(5) != 0) {
        return fail(info, "Unsupported metadata tables header layout");
    }
    const uint8_t heap_flags = tables.u8(6);
    if ((heap_flags & ~7u) != 0) return fail(info, "Unsupported metadata heap-size flags");
    const uint64_t valid = tables.u64(8);
    // Only Valid describes stored tables; Sorted can also name absent tables.
    if ((valid & ~kTableMask) != 0) return fail(info, "Unsupported metadata table outside 0..44");
    if (!metadata.uncompressed && (valid & (kPointerMask | kEncMask)) != 0) {
        return fail(info, "Pointer or EnC tables require an uncompressed metadata stream");
    }
    std::array<uint32_t, 45> rows{};
    std::array<uint64_t, 45> offsets{};
    std::array<uint64_t, 45> row_sizes{};
    std::array<std::array<unsigned, 10>, 45> widths{};
    uint64_t cursor = 24;
    for (unsigned table = 0; table < rows.size(); ++table) {
        if ((valid & (uint64_t(1) << table)) == 0) continue;
        if (!tables.contains(cursor, 4)) return fail(info, "Truncated metadata table row counts");
        rows[table] = tables.u32(cursor);
        if (rows[table] > 0x00ffffffu) return fail(info, "Metadata table row count exceeds token range");
        cursor += 4;
    }
    if (rows[0] != 1 || rows[32] > 1) return fail(info, "Invalid Module or Assembly row count");

    const unsigned string_width = (heap_flags & 1) != 0 ? 4 : 2;
    const unsigned guid_width = (heap_flags & 2) != 0 ? 4 : 2;
    const unsigned blob_width = (heap_flags & 4) != 0 ? 4 : 2;
    const Bytes strings = metadata.streams[Strings].bytes;
    const Bytes guids = metadata.streams[Guids].bytes;
    const Bytes blobs = metadata.streams[Blobs].bytes;
    if ((strings.size > 0xffff && string_width == 2) ||
        (guids.size > 0xffff && guid_width == 2) || (blobs.size > 0xffff && blob_width == 2)) {
        return fail(info, "Heap size exceeds declared metadata index width");
    }
    for (unsigned table = 0; table < rows.size(); ++table) {
        for (unsigned column = 0; column < 10 && kColumns[table][column] != End; ++column) {
            const uint8_t kind = kColumns[table][column];
            unsigned width;
            if (kind == U16) width = 2;
            else if (kind == U32) width = 4;
            else if (kind == StringIndex) width = string_width;
            else if (kind == GuidIndex) width = guid_width;
            else if (kind == BlobIndex) width = blob_width;
            else if (kind >= 112) {
                const CodedIndex& coded = kCoded[kind - 112];
                uint32_t largest = 0;
                for (unsigned tag = 0; tag < coded.count; ++tag) {
                    if (coded.tables[tag] >= 0) largest = std::max(largest, rows[coded.tables[tag]]);
                }
                width = largest < (uint32_t(1) << (16 - coded.bits)) ? 2 : 4;
            } else {
                const unsigned target = kind >= 64 ? kind - 64 : kind - 16;
                uint32_t largest = rows[target];
                if (kind >= 64) largest = std::max(largest, rows[pointer_table(target)]);
                width = largest < 0x10000u ? 2 : 4;
            }
            widths[table][column] = width;
            row_sizes[table] += width;
        }
        const uint64_t length = uint64_t(rows[table]) * row_sizes[table];
        if (!tables.contains(cursor, length)) {
            return fail(info, "Metadata table range exceeds stream: " + std::to_string(table));
        }
        offsets[table] = cursor;
        cursor += length;
    }
    if (tables.size - cursor > 4) return fail(info, "Unsupported metadata tables trailing layout");
    for (uint64_t i = cursor; i < tables.size; ++i) {
        if (tables.u8(i) != 0) return fail(info, "Nonzero metadata tables trailing padding");
    }

    for (unsigned table = 0; table < rows.size(); ++table) {
        std::array<uint32_t, 10> previous_list{};
        for (uint64_t row = 0; row < rows[table]; ++row) {
            uint64_t position = offsets[table] + row * row_sizes[table];
            for (unsigned column = 0; column < 10 && kColumns[table][column] != End; ++column) {
                const uint8_t kind = kColumns[table][column];
                const unsigned width = widths[table][column];
                const uint32_t value = tables.index(position, width);
                position += width;
                bool in_range = true;
                if (kind == StringIndex) {
                    in_range = value == 0 || value < strings.size;
                } else if (kind == GuidIndex) {
                    in_range = uint64_t(value) <= guids.size / 16;
                } else if (kind == BlobIndex) {
                    in_range = blob_in_range(blobs, value);
                } else if (kind >= 112) {
                    if (value == 0) {
                        in_range = (table == 1 && column == 0) || (table == 2 && column == 3) ||
                                   (table == 40 && column == 3);
                    } else {
                        const CodedIndex& coded = kCoded[kind - 112];
                        const unsigned tag = value & ((1u << coded.bits) - 1);
                        const uint32_t rid = value >> coded.bits;
                        in_range = tag < coded.count && coded.tables[tag] >= 0 && rid != 0 &&
                                   rid <= rows[coded.tables[tag]];
                    }
                } else if (kind >= 64 && kind < 112) {
                    unsigned target = kind - 64;
                    const unsigned pointer = pointer_table(target);
                    if (rows[pointer] != 0) target = pointer;
                    in_range = value != 0 && uint64_t(value) <= uint64_t(rows[target]) + 1 &&
                               value >= previous_list[column];
                    previous_list[column] = value;
                } else if (kind >= 16 && kind < 64) {
                    in_range = value != 0 && value <= rows[kind - 16];
                }
                if (!in_range) {
                    return fail(info, "Invalid heap or table index in metadata table " + std::to_string(table));
                }
                if (table == 11 && column == 0 && (value & 0xff00u) != 0) {
                    return fail(info, "Nonzero Constant table reserved byte");
                }
                if (table == 0 && column == 1 && (value == 0 || strings.u8(value) == 0)) {
                    return fail(info, "Missing Module name");
                }
            }
        }
    }
    if (entry_token != 0) {
        const unsigned table = entry_token >> 24;
        const uint32_t rid = entry_token & 0x00ffffffu;
        if ((table != 6 && table != 38) || rid == 0 || rid > rows[table]) {
            return fail(info, "Invalid CLI entry point token");
        }
    }

    const uint64_t mvid_position = offsets[0] + 2 + string_width;
    const uint32_t mvid_index = tables.index(mvid_position, guid_width);
    if (mvid_index == 0 || !guids.contains((uint64_t(mvid_index) - 1) * 16, 16)) {
        return fail(info, "Missing or invalid Module MVID");
    }
    constexpr unsigned order[16] = {3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15};
    constexpr char hex[] = "0123456789abcdef";
    const uint64_t guid_offset = (uint64_t(mvid_index) - 1) * 16;
    std::string mvid;
    mvid.reserve(36);
    for (unsigned i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) mvid.push_back('-');
        const uint8_t value = guids.u8(guid_offset + order[i]);
        mvid.push_back(hex[value >> 4]);
        mvid.push_back(hex[value & 15]);
    }
    info.mvid = mvid;
    if (rows[32] != 0) {
        const uint32_t name_index = tables.index(offsets[32] + 16 + blob_width, string_width);
        if (name_index == 0 || !strings.contains(name_index, 1)) {
            return fail(info, "Missing Assembly name");
        }
        uint64_t end = name_index;
        while (end < strings.size && strings.u8(end) != 0) ++end;
        if (end == strings.size || end == name_index) return fail(info, "Invalid Assembly name range");
        info.assembly_name.assign(reinterpret_cast<const char*>(strings.data + name_index),
                                  static_cast<size_t>(end - name_index));
        if (!valid_utf8(info.assembly_name)) return fail(info, "Assembly name is not valid UTF-8");
    }
    return true;
}

struct Section {
    uint64_t rva;
    uint64_t mapped_size;
    uint64_t raw;
    uint64_t raw_size;
};

bool read_pe(Bytes file, FileInfo& info) {
    if (!file.contains(0, 64) || file.u16(0) != 0x5a4du) return fail(info, "Missing or truncated MZ header");
    const uint64_t pe = file.u32(0x3c);
    if (pe < 64 || pe > 0x7fffffffu || !file.contains(pe, 24) || file.u32(pe) != 0x00004550u) {
        return fail(info, "Invalid e_lfanew, PE signature, or COFF header range");
    }
    const uint64_t coff = pe + 4;
    const unsigned section_count = file.u16(coff + 2);
    const uint64_t optional_size = file.u16(coff + 16);
    if (file.u16(coff) == 0 || section_count == 0 || (file.u16(coff + 18) & 2) == 0) {
        return fail(info, "Invalid COFF machine, sections, or executable characteristics");
    }
    const uint64_t symbol_offset = file.u32(coff + 8);
    const uint64_t symbol_count = file.u32(coff + 12);
    if (symbol_offset == 0 && symbol_count != 0) return fail(info, "Missing COFF symbol table pointer");
    if (symbol_offset != 0) {
        const uint64_t symbol_size = symbol_count * 18;
        if (!file.contains(symbol_offset, symbol_size) || !file.contains(symbol_offset + symbol_size, 4)) {
            return fail(info, "Truncated COFF symbol or string table");
        }
        const uint64_t string_size = file.u32(symbol_offset + symbol_size);
        if (string_size < 4 || !file.contains(symbol_offset + symbol_size, string_size)) {
            return fail(info, "Invalid COFF string table range");
        }
    }
    const uint64_t optional_offset = coff + 20;
    if (!file.contains(optional_offset, optional_size) || optional_size < 2) {
        return fail(info, "Truncated PE optional header");
    }
    const Bytes optional = file.slice(optional_offset, optional_size);
    const uint16_t magic = optional.u16(0);
    const uint64_t directory_offset = magic == 0x10bu ? 96 : magic == 0x20bu ? 112 : 0;
    if (directory_offset == 0 || !optional.contains(0, directory_offset)) {
        return fail(info, "Unsupported or truncated PE32/PE32+ optional header");
    }
    const uint64_t directory_count = optional.u32(directory_offset - 4);
    if (directory_count > 16 || !optional.contains(directory_offset, directory_count * 8)) {
        return fail(info, "Unsupported or truncated PE data directory array");
    }
    if (directory_count <= 14) return fail(info, "Missing CLI data directory");
    const uint64_t section_alignment = optional.u32(32);
    const uint64_t file_alignment = optional.u32(36);
    const uint64_t image_size = optional.u32(56);
    const uint64_t header_size = optional.u32(60);
    const auto power_of_two = [](uint64_t value) { return value != 0 && (value & (value - 1)) == 0; };
    if (!power_of_two(section_alignment) || !power_of_two(file_alignment) ||
        section_alignment < file_alignment || file_alignment > 65536 ||
        (section_alignment < 4096 ? file_alignment != section_alignment : file_alignment < 512)) {
        return fail(info, "Invalid PE section or file alignment");
    }
    const uint64_t sections_offset = optional_offset + optional_size;
    const uint64_t sections_size = uint64_t(section_count) * 40;
    if (!file.contains(sections_offset, sections_size) || header_size < sections_offset + sections_size ||
        !file.contains(0, header_size) || header_size % file_alignment != 0 ||
        image_size == 0 || image_size % section_alignment != 0 ||
        align_up(header_size, section_alignment) > image_size) {
        return fail(info, "Invalid complete section table, SizeOfHeaders, or SizeOfImage range");
    }

    std::vector<Section> sections;
    sections.reserve(section_count);
    for (unsigned i = 0; i < section_count; ++i) {
        const uint64_t position = sections_offset + uint64_t(i) * 40;
        const uint64_t virtual_size = file.u32(position + 8);
        const uint64_t rva = file.u32(position + 12);
        const uint64_t raw_size = file.u32(position + 16);
        const uint64_t raw = file.u32(position + 20);
        const uint64_t mapped_size = align_up(std::max(virtual_size, raw_size), section_alignment);
        if (rva % section_alignment != 0 || rva < align_up(header_size, section_alignment) ||
            rva > image_size || mapped_size > image_size - rva ||
            raw_size % file_alignment != 0 || (raw != 0 && raw % file_alignment != 0) ||
            !file.contains(raw, raw_size) || (raw_size != 0 && raw < header_size) ||
            (section_alignment < 4096 && raw_size != 0 && raw != rva)) {
            return fail(info, "Invalid section virtual or original-file range: " + std::to_string(i));
        }
        if ((file.u32(position + 36) & 0x01000000u) != 0) {
            return fail(info, "Unsupported extended COFF section relocation layout");
        }
        for (unsigned auxiliary = 0; auxiliary < 2; ++auxiliary) {
            const uint64_t pointer = file.u32(position + 24 + uint64_t(auxiliary) * 4);
            const uint64_t count = file.u16(position + 32 + uint64_t(auxiliary) * 2);
            const uint64_t length = count * (auxiliary == 0 ? 10 : 6);
            if ((count != 0 && pointer == 0) || !file.contains(pointer, length)) {
                return fail(info, "Invalid section COFF relocation or line-number range");
            }
        }
        sections.push_back({rva, mapped_size, raw, raw_size});
    }
    std::sort(sections.begin(), sections.end(), [](const Section& a, const Section& b) { return a.raw < b.raw; });
    uint64_t end = header_size;
    for (const Section& section : sections) {
        if (section.raw_size == 0) continue;
        if (section.raw < end) return fail(info, "Overlapping section original-file ranges");
        end = section.raw + section.raw_size;
    }
    std::sort(sections.begin(), sections.end(), [](const Section& a, const Section& b) { return a.rva < b.rva; });
    end = align_up(header_size, section_alignment);
    for (const Section& section : sections) {
        if (section.mapped_size == 0) continue;
        if (section.rva < end) return fail(info, "Overlapping section virtual ranges");
        end = section.rva + section.mapped_size;
    }

    const auto map_rva = [&](uint64_t rva, uint64_t length, uint64_t& offset) {
        if (length == 0 || rva >= image_size || length > image_size - rva) return false;
        uint64_t cursor = rva;
        uint64_t remaining = length;
        bool mapped = false;
        if (rva < header_size) {
            offset = rva;
            const uint64_t part = std::min(remaining, header_size - cursor);
            cursor += part;
            remaining -= part;
            mapped = true;
            if (remaining == 0) return file.contains(offset, length);
        }
        for (const Section& section : sections) {
            if (cursor < section.rva) return false;
            if (cursor - section.rva >= section.mapped_size) continue;
            const uint64_t delta = cursor - section.rva;
            // A virtual/zero-filled tail is not backed by the original file.
            if (delta >= section.raw_size) return false;
            const uint64_t part_offset = section.raw + delta;
            if (!mapped) {
                offset = part_offset;
                mapped = true;
            } else if (part_offset != offset + (length - remaining)) {
                return false;
            }
            const uint64_t part = std::min(remaining, section.raw_size - delta);
            cursor += part;
            remaining -= part;
            if (remaining == 0) return file.contains(offset, length);
        }
        return false;
    };

    uint64_t cli_offset = 0;
    uint64_t cli_size = 0;
    for (uint64_t i = 0; i < directory_count; ++i) {
        const uint64_t position = directory_offset + i * 8;
        const uint64_t rva = optional.u32(position);
        const uint64_t length = optional.u32(position + 4);
        if (rva == 0 && length == 0) continue;
        if (i == 7 || i == 15) return fail(info, "Nonzero reserved PE data directory");
        uint64_t offset = 0;
        if (i == 8) {
            if (rva == 0 || length != 0 || !map_rva(rva, 1, offset)) {
                return fail(info, "Invalid PE global pointer directory");
            }
            continue;
        }
        if (rva == 0 || length == 0) return fail(info, "Incomplete PE data directory range");
        if (i == 4) {
            if ((rva & 7) != 0 || (length & 7) != 0 || !file.contains(rva, length) || rva < header_size) {
                return fail(info, "Invalid file-offset certificate directory");
            }
            for (const Section& section : sections) {
                if (overlaps(rva, length, section.raw, section.raw_size)) {
                    return fail(info, "Certificate directory overlaps section data");
                }
            }
        } else if (!map_rva(rva, length, offset)) {
            return fail(info, "PE directory is not a contiguous file-backed RVA range: " + std::to_string(i));
        }
        if (i == 14) {
            cli_offset = offset;
            cli_size = length;
        }
    }
    if (cli_size < 72 || !file.contains(cli_offset, cli_size)) return fail(info, "Missing or truncated CLI header");
    const Bytes cli = file.slice(cli_offset, cli_size);
    if (cli.u32(0) != 72) return fail(info, "Unsupported CLI header size");
    if (cli.u16(4) != 2 || cli.u16(6) > 5) return fail(info, "Unsupported CLI runtime version");
    const uint64_t metadata_rva = cli.u32(8);
    const uint64_t metadata_size = cli.u32(12);
    uint64_t metadata_offset = 0;
    if (metadata_rva == 0 || !map_rva(metadata_rva, metadata_size, metadata_offset) ||
        overlaps(cli_offset, cli_size, metadata_offset, metadata_size)) {
        return fail(info, "Invalid or overlapping CLI metadata range");
    }
    std::array<uint64_t, 6> auxiliary_offsets{};
    std::array<uint64_t, 6> auxiliary_sizes{};
    for (unsigned i = 0; i < auxiliary_offsets.size(); ++i) {
        const uint64_t position = 24 + uint64_t(i) * 8;
        const uint64_t rva = cli.u32(position);
        const uint64_t length = cli.u32(position + 4);
        if (rva == 0 && length == 0) continue;
        uint64_t offset = 0;
        if (rva == 0 || !map_rva(rva, length, offset) ||
            overlaps(offset, length, cli_offset, cli_size) ||
            overlaps(offset, length, metadata_offset, metadata_size) || (i == 3 && length % 8 != 0)) {
            return fail(info, "Invalid or overlapping auxiliary CLI directory");
        }
        for (unsigned j = 0; j < i; ++j) {
            if (overlaps(offset, length, auxiliary_offsets[j], auxiliary_sizes[j])) {
                return fail(info, "Overlapping auxiliary CLI directories");
            }
        }
        auxiliary_offsets[i] = offset;
        auxiliary_sizes[i] = length;
    }
    const uint32_t flags = cli.u32(16);
    if ((flags & ~0x0003001fu) != 0) return fail(info, "Unsupported CLI header flags");
    const uint32_t entry = cli.u32(20);
    if ((flags & 0x10) != 0) {
        uint64_t entry_offset = 0;
        if (entry == 0 || !map_rva(entry, 1, entry_offset)) return fail(info, "Invalid native CLI entry point RVA");
    }
    Metadata metadata;
    return read_root(file.slice(metadata_offset, metadata_size), false, metadata, info) &&
           read_tables(metadata, (flags & 0x10) != 0 ? 0 : entry, info);
}

} // namespace

FileInfo inspect_file(const uint8_t* data, size_t size, bool expect_pdb) {
    FileInfo info;
    if (data == nullptr || size == 0) {
        info.reason = "Empty or null file buffer";
        return info;
    }
    const Bytes file{data, static_cast<uint64_t>(size)};
    if (expect_pdb) {
        Metadata metadata;
        info.valid = read_root(file, true, metadata, info) && read_pdb(metadata, info);
        info.portable_pdb = info.valid;
    } else {
        info.valid = read_pe(file, info);
    }
    if (!info.valid) {
        info.assembly_name.clear();
        info.mvid.clear();
    }
    return info;
}

} // namespace hcd
