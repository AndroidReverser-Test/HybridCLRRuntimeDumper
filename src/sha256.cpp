#include "format.h"

#include <algorithm>
#include <cstring>

namespace hcd {
namespace {

constexpr uint32_t kRound[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

uint32_t rotate_right(uint32_t value, unsigned bits) {
    return (value >> bits) | (value << (32 - bits));
}

} // namespace

Sha256::Sha256()
    : state_{0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
             0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u} {}

void Sha256::transform(const uint8_t* block) {
    uint32_t words[64];
    for (size_t i = 0; i < 16; ++i) {
        const uint8_t* p = block + i * 4;
        words[i] = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
                   (uint32_t(p[2]) << 8) | uint32_t(p[3]);
    }
    for (size_t i = 16; i < 64; ++i) {
        const uint32_t x = words[i - 15];
        const uint32_t y = words[i - 2];
        const uint32_t s0 = rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3);
        const uint32_t s1 = rotate_right(y, 17) ^ rotate_right(y, 19) ^ (y >> 10);
        words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }

    uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    for (size_t i = 0; i < 64; ++i) {
        const uint32_t s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
        const uint32_t choose = (e & f) ^ (~e & g);
        const uint32_t t1 = h + s1 + choose + kRound[i] + words[i];
        const uint32_t s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
        const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = s0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void Sha256::update(const void* data, size_t size) {
    if (size == 0) return;
    const auto* p = static_cast<const uint8_t*>(data);
    total_ += static_cast<uint64_t>(size);
    while (size != 0) {
        if (used_ == 0 && size >= sizeof(block_)) {
            transform(p);
            p += sizeof(block_);
            size -= sizeof(block_);
        } else {
            const size_t count = std::min(size, sizeof(block_) - used_);
            std::memcpy(block_ + used_, p, count);
            used_ += count;
            p += count;
            size -= count;
            if (used_ == sizeof(block_)) {
                transform(block_);
                used_ = 0;
            }
        }
    }
}

std::string Sha256::finish() {
    // Finalize a snapshot so repeated finish() calls do not alter the stream.
    Sha256 digest = *this;
    const uint64_t bits = digest.total_ << 3;
    digest.block_[digest.used_++] = 0x80;
    if (digest.used_ > 56) {
        std::memset(digest.block_ + digest.used_, 0, 64 - digest.used_);
        digest.transform(digest.block_);
        digest.used_ = 0;
    }
    std::memset(digest.block_ + digest.used_, 0, 56 - digest.used_);
    for (unsigned i = 0; i < 8; ++i) {
        digest.block_[63 - i] = static_cast<uint8_t>(bits >> (i * 8));
    }
    digest.transform(digest.block_);

    constexpr char hex[] = "0123456789abcdef";
    std::string result(64, '0');
    for (size_t i = 0; i < 8; ++i) {
        for (unsigned j = 0; j < 8; ++j) {
            result[i * 8 + j] = hex[(digest.state_[i] >> (28 - j * 4)) & 15];
        }
    }
    return result;
}

std::string sha256(const void* data, size_t size) {
    Sha256 digest;
    digest.update(data, size);
    return digest.finish();
}

} // namespace hcd
