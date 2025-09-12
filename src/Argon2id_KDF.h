#pragma once

#include <cstring>
#include <vector>
#include <cstdint>
#include "ErrorCodes.h"
#include "Logger.h"
#include <Core_BLAKE2b.h>


class Argon2id {
public:

    /**
    * @param Password: The input password
    * @param Salt: The cryptographic salt
    * @param MemoryKB: Memory cost in kB
    * @param Iterations: Number of iterations
    * @param outputSize: Desired size of the output key in bytes
    * @param output: Pointer to store the derived key
    */
    ErrorCode deriveKey(std::vector<uint8_t> &Password, std::vector<uint8_t> &Salt, uint32_t MemoryKB, uint32_t Iterations, uint32_t outputSize, uint8_t* output);


private:
    // ---- Parameters / constants ----
    static constexpr uint32_t BLOCK_SIZE = 1024;                 // 1 KiB
    static constexpr uint32_t QWORDS_IN_BLOCK = BLOCK_SIZE / 8;  // 128
    static constexpr uint32_t ARGON2_VERSION = 0x13;             // RFC 9106
    enum { ARGON2_TYPE_ID = 2 };                                 // Argon2id
    static constexpr uint32_t LANES = 1;                         // p = 1 (due to use in microcontrollers)
    static constexpr uint32_t SLICES = 4; // Argon2 uses 4 slices per pass

    struct Block1k {
        uint64_t v[QWORDS_IN_BLOCK];
    };

    // Tracks address generation state for Argon2i (pseudorandom J1/J2 stream)
    struct AddrGen {
        Block1k addr_block;   // 128 qwords of addresses
        Block1k input_block;  // input to G to make the next address_block
        uint32_t offset = 128;// next qword to consume [0..127], start "empty" to force first refill
        uint64_t ctr   = 0;   // how many address blocks we've generated for this pass/slice
    };

    // ---- State ----
    Core_BLAKE2b blake;
    uint32_t _m_cost = 0;   // memory in KiB == number of blocks
    uint32_t _t_cost = 0;   // iterations (passes)
    uint32_t _out_len = 0;  // output length


    // ---- Top-level phases ----
    ErrorCode initialize(const std::vector<uint8_t>& pwd, const std::vector<uint8_t>& salt, Block1k* mem);
    ErrorCode fillMemory(Block1k* mem);
    ErrorCode finalize(const Block1k* mem, uint8_t* output);



    // ---- Helpers ----
    static void blockXor(const Block1k& a, const Block1k& b, Block1k& out);
    static void blockCopy(const Block1k& src, Block1k& dst);
    static inline void blockZero(Block1k& b);
    static inline void memZero(std::vector<Block1k> &memory);

    // Argon2 compression G: applies Blake2b-like round to a 1-KiB block
    static void G_permute(Block1k& state);

    // Variable-length hash H' per spec (uses BLAKE2b as engine)
    void Hprime(const uint8_t* in, size_t inlen, uint8_t* out, uint32_t outlen);


    void addrgen_init(AddrGen& ag, uint32_t pass, uint32_t slice);
    void addrgen_refill(AddrGen& ag);

    uint32_t map_index_alpha(uint32_t pass, uint32_t slice, uint32_t index_in_segment, uint32_t segment_length, uint32_t lane_length, uint32_t J1) const;

    uint32_t index_argon2i(uint32_t pass, uint32_t slice, uint32_t index_in_segment, uint32_t segment_length, uint32_t lane_length, AddrGen& ag);

    uint32_t index_argon2d(uint32_t pass, uint32_t slice, uint32_t index_in_segment, uint32_t segment_length, uint32_t lane_length, const Block1k* mem, uint32_t curr_abs_index) const;


    void hashH0(const std::vector<uint8_t>& pwd, const std::vector<uint8_t>& salt, std::vector<uint8_t>& outH0);

    // little-endian append helpers
    static void append_u32(std::vector<uint8_t>& v, uint32_t x);
    static void append_u64(std::vector<uint8_t>& v, uint64_t x);
};
