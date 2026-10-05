#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace hcd {

class Sha256 {
public:
    Sha256();
    void update(const void* data, size_t size);
    std::string finish();

private:
    void transform(const uint8_t* block);
    uint32_t state_[8];
    uint8_t block_[64]{};
    uint64_t total_ = 0;
    size_t used_ = 0;
};

std::string sha256(const void* data, size_t size);

struct FileInfo {
    bool valid = false;
    bool portable_pdb = false;
    std::string reason;
    std::string assembly_name;
    std::string mvid;
};

/* Bounded, independent PE/CLI/metadata structural inspection, not IL verification. */
FileInfo inspect_file(const uint8_t* data, size_t size, bool expect_pdb);

} // namespace hcd
