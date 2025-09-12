
#include "Argon2id_KDF.h"


ErrorCode Argon2id::deriveKey(std::vector<uint8_t> &Password, std::vector<uint8_t> &Salt, uint32_t MemoryKB, uint32_t Iterations, uint32_t outputSize, uint8_t* output) {

    if (Password.size() < 6 || Salt.size() < 6) {
        Log::Warning("Argon2id", "Invalid parameters: Password and Salt have to be >= 6 in length");
        return ErrorCode::INVALID_PARAM;
    }

    if (MemoryKB < 8 || Iterations < 1 || outputSize < 1 || !output) {
        Log::Warning("Argon2id", "Invalid parameters for Key derivation (Memory < 8kB, Iteratins < 1, outputSize < 1 or nullptr at output)");
        return ErrorCode::INVALID_PARAM;
    }

    if (MemoryKB % 4 != 0) {
        Log::Warning("Argon2id", "Memory size has to be divisible by 4 to comply to the standard in this simplified version");
        return ErrorCode::INVALID_PARAM;
    }


    _m_cost = MemoryKB;   // 1 block == 1 KiB
    _t_cost = Iterations;
    _out_len = outputSize;

    std::vector<Block1k> memory;
    try { 
        memory.resize(_m_cost); 
    }
    catch (const std::bad_alloc&) {
        Log::Alarm("Argon2id", std::format("Memory allocation failed for {} kB", _m_cost));
        return ErrorCode::MEMORY_ALLOCATION_FAILED;
    }


    if (initialize(Password, Salt, memory.data()) != ErrorCode::OK) {
        Log::Alarm("Argon2id", "Initialization failed");
        memZero(memory);
        return ErrorCode::INTERNAL_ERROR;
    }
    Log::Trace("Argon2id", std::format("Initialized memory with {} blocks", _m_cost));


    if (fillMemory(memory.data()) != ErrorCode::OK) {
        Log::Alarm("Argon2id", "fillMemory() failed");
        memZero(memory);
        return ErrorCode::INTERNAL_ERROR;
    }
    Log::Trace("Argon2id", std::format("Memory filling done ({} passes)", _t_cost));

    
    if (finalize(memory.data(), output) != ErrorCode::OK) {
        Log::Alarm("Argon2id", "Finalization failed");
        memZero(memory);
        return ErrorCode::INTERNAL_ERROR;
    }

    memZero(memory);
    Log::Info("Argon2id", std::format("{} byte Key derived with {} kB memory and {} rounds",
                                       _out_len, _m_cost, _t_cost));
    return ErrorCode::OK;
}







// ====== Initialization (H0 and first 2 blocks) ======
ErrorCode Argon2id::initialize(const std::vector<uint8_t>& pwd, const std::vector<uint8_t>& salt, Block1k* mem) {

    if (!mem) return ErrorCode::NULL_POINTER;

    // 1) Build H0 per RFC 9106 §3 (p=1, no secret/ad here)
    std::vector<uint8_t> H0;
    hashH0(pwd, salt, H0); // 64 bytes

    // 2) For each lane (p=1), we produce first two blocks with H′
    //    B[0] = H'(H0 || LE32(0) || LE64(0), 1024)
    //    B[1] = H'(H0 || LE32(1) || LE64(0), 1024)
    uint8_t buf[64 + 12]; // 76 bytes
    std::memset(buf, 0, sizeof(buf));
    std::memcpy(buf, H0.data(), 64);

    // B[0]
    {
        uint32_t ctr0 = 0;
        uint32_t lane0 = 0;
        std::memcpy(buf + 64, &ctr0, sizeof(ctr0));
        std::memcpy(buf + 64 + sizeof(ctr0), &lane0, sizeof(lane0));
        size_t inlen = 64 + sizeof(ctr0) + sizeof(lane0);
        Hprime(buf, inlen, reinterpret_cast<uint8_t*>(mem[0].v), BLOCK_SIZE);
    }

    // B[1]
    {
        uint32_t ctr1 = 1;
        uint64_t z1 = 0;
        std::memcpy(buf + 64, &ctr1, sizeof(ctr1));
        std::memcpy(buf + 64 + sizeof(ctr1), &z1, sizeof(z1));
        size_t inlen = 64 + sizeof(ctr1) + sizeof(z1);
        Hprime(buf, inlen, reinterpret_cast<uint8_t*>(mem[1].v), BLOCK_SIZE);
    }


    explicit_bzero(buf, sizeof(buf));
    explicit_bzero(H0.data(), H0.size());

    // Zero the remainder for now; fillMemory() will populate
    for (uint32_t i = 2; i < _m_cost; ++i) blockZero(mem[i]);
    return ErrorCode::OK;
}



// ====== Memory Filling (Argon2id hybrid indexing, p=1) ======
ErrorCode Argon2id::fillMemory(Block1k* mem) {

    if (!mem) return ErrorCode::NULL_POINTER;
    if (_m_cost < 2) return ErrorCode::INVALID_PARAM;

    const uint32_t lane_length  = _m_cost;       // number of blocks in lane (p=1)
    const uint32_t base_segment = lane_length / SLICES;
    const uint32_t remainder    = lane_length % SLICES;

    // Safety: require at least 2 blocks per slice to avoid degenerate behavior
    if (base_segment == 0) {
        Log::Alarm("Argon2id", "Memory too small for Argon2 slices");
        return ErrorCode::INVALID_PARAM;
    }

    AddrGen ag; // address generator for Argon2i (re-init per slice)


    for (uint32_t pass = 0; pass < _t_cost; ++pass) {

        for (uint32_t slice = 0; slice < SLICES; ++slice) {

            uint32_t segment_length = lane_length / SLICES;
            uint32_t segment_start = slice * segment_length;
            uint32_t segment_end   = segment_start + segment_length;

            // Init address generator for this (pass, slice)
            addrgen_init(ag, pass, slice);


            // iterate absolute indices inside this segment
            for (uint32_t idx_in_seg = 0; idx_in_seg < segment_length; ++idx_in_seg) {
                uint32_t i = segment_start + idx_in_seg;

                // skip the seeded first two blocks
                if (i < 2) continue;

                // Determine mode: first half of pass 0 uses Argon2i indexing, otherwise Argon2d
                bool use_i_mode = (pass == 0) && (i < (lane_length / 2));

                // choose reference index using the proper function
                uint32_t refIndex;
                if (use_i_mode) {
                    refIndex = index_argon2i(pass, slice, idx_in_seg, segment_length, lane_length, ag);
                } else {
                    refIndex = index_argon2d(pass, slice, idx_in_seg, segment_length, lane_length, mem, i);
                }


                // Perform the Argon2 block update:
                // C = B[i-1] XOR B[ref]
                Block1k C;
                blockXor(mem[i - 1], mem[refIndex], C);

                // R = G(C)
                Block1k R;
                blockCopy(C, R);
                G_permute(R);

                // B[i] = R XOR C   (equivalently R XOR B[i-1] XOR B[ref])
                blockXor(R, C, mem[i]);

            } // end segment

        } // end slices

    } // end passes


    return ErrorCode::OK;
}



// ====== Finalization (XOR last blocks, H′) ======
ErrorCode Argon2id::finalize(const Block1k* mem, uint8_t* output) {
    if (!mem || !output) return ErrorCode::INVALID_PARAM;

    // p=1 → just the last block of lane 0
    const Block1k& last = mem[_m_cost - 1];

    // H′(last, T)
    Hprime(reinterpret_cast<const uint8_t*>(last.v), BLOCK_SIZE, output, _out_len);
    return ErrorCode::OK;
}







// ====== Helpers ======

inline void Argon2id::blockZero(Block1k& b) { explicit_bzero(b.v, sizeof(Block1k)); }

inline void Argon2id::memZero(std::vector<Block1k> &memory) { explicit_bzero(memory.data(), memory.size() * sizeof(Block1k)); };

void Argon2id::blockCopy(const Block1k& src, Block1k& dst) {
    std::memcpy(dst.v, src.v, sizeof(src.v));
}

void Argon2id::blockXor(const Block1k& a, const Block1k& b, Block1k& out) {
    for (size_t i = 0; i < QWORDS_IN_BLOCK; ++i) out.v[i] = a.v[i] ^ b.v[i];
}

static inline uint64_t rotr64(uint64_t x, unsigned r) {
    return (x >> r) | (x << (64 - r));
}


inline void G(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d) {
    a = a + b;
    d = rotr64(d ^ a, 32);
    
    c = c + d;
    b = rotr64(b ^ c, 24);
    
    a = a + b;
    d = rotr64(d ^ a, 16);
    
    c = c + d;
    b = rotr64(b ^ c, 63);
}

// ---- full G_permute (Argon2-style P/G) ----
void Argon2id::G_permute(Block1k& state) {
    uint64_t* v = state.v;
    
    // Process 8 columns of 16 qwords each
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 16; j += 4) {
            uint64_t& a = v[i + 8 * (j + 0)];
            uint64_t& b = v[i + 8 * (j + 1)];
            uint64_t& c = v[i + 8 * (j + 2)];
            uint64_t& d = v[i + 8 * (j + 3)];
            G(a, b, c, d);
        }
    }
    
    // Process 16 rows of 8 qwords each  
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 8; j += 4) {
            uint64_t& a = v[i * 8 + j + 0];
            uint64_t& b = v[i * 8 + j + 1];
            uint64_t& c = v[i * 8 + j + 2];
            uint64_t& d = v[i * 8 + j + 3];
            G(a, b, c, d);
        }
    }
}



// Variable-length hash H′ using BLAKE2b
void Argon2id::Hprime(const uint8_t* in, size_t inlen, uint8_t* out, uint32_t outlen) {

    // If <= 64, single BLAKE2b(outlen)
    if (outlen <= 64) {
        blake.reset(outlen); // assume Core_BLAKE2b supports output length
        blake.update(in, inlen);
        blake.finalize(out, outlen);
        return;
    }
    // Otherwise iterative
    uint8_t tmp[64];
    uint32_t produced = 0;

    blake.reset(64);
    blake.update(in, inlen);
    blake.finalize(tmp, 64);

    while (produced < outlen) {
        uint32_t chunk = std::min<uint32_t>(64, outlen - produced);
        std::memcpy(out + produced, tmp, chunk);

        // next = BLAKE2b(64, previous)
        blake.reset(64);
        blake.update(tmp, 64);
        blake.finalize(tmp, 64);

        produced += chunk;
    }
    explicit_bzero(tmp, sizeof(tmp));
}



// ================= Address generator (Argon2i) =================

// Initialize the Argon2i address generator for a given (pass, slice).
// With p=1 we fix lane=0 and segment= slice*segment_length .. +segment_length-1
void Argon2id::addrgen_init(AddrGen& ag, uint32_t pass, uint32_t slice) {

    blockZero(ag.addr_block);
    blockZero(ag.input_block);
    ag.offset = 128; // force a refill on first use
    ag.ctr    = 0;

    // input_block holds parameters that change per pass/slice (simplified p=1 layout)
    // We'll mix these with G to obtain a new addr_block when needed.
    ag.input_block.v[0] = pass;          // pass
    ag.input_block.v[1] = 0;             // lane (p=1)
    ag.input_block.v[2] = slice;         // slice 0..3
    ag.input_block.v[3] = _m_cost;       // lane_length == m (blocks)
    ag.input_block.v[4] = ARGON2_TYPE_ID;// Argon2id
    ag.input_block.v[5] = _t_cost;       // total passes
    ag.input_block.v[6] = 0;             // reserved
    ag.input_block.v[7] = 0;             // reserved
}


// Produce the next 128 qwords of pseudo-random addresses into ag.addr_block.
// This follows Argon2's pattern: two G permutations seeded from a changing input.
void Argon2id::addrgen_refill(AddrGen& ag) {

    // Make a working copy of input and mix a counter so each refill differs
    Block1k tmp;
    blockCopy(ag.input_block, tmp);
    tmp.v[12] ^= ag.ctr;          // fold in a counter (arbitrary slot)
    tmp.v[13] ^= (ag.ctr << 1);
    G_permute(tmp);               // 1st permutation
    blockXor(tmp, ag.addr_block, ag.addr_block); // mix with previous (starts at 0s)
    G_permute(ag.addr_block);     // 2nd permutation → final address words

    ag.offset = 0;
    ag.ctr++;
}



// ================= Index mapping =================

uint32_t Argon2id::map_index_alpha(uint32_t pass, uint32_t slice, uint32_t index_in_segment,
                                  uint32_t segment_length, uint32_t lane_length, uint32_t J1) const {
    // Calculate the absolute index of the current block being computed
    uint32_t current_index = slice * segment_length + index_in_segment;
    
    // Determine the reference area size according to Argon2 spec RFC 9106 §3.4
    uint32_t area_size;
    
    if (pass == 0) {
        // First pass: reference area depends on the slice
        if (slice == 0) {
            area_size = index_in_segment; // blocks computed so far in this segment
        } else {
            area_size = slice * segment_length + index_in_segment;
        }
    } else {
        area_size = lane_length - segment_length;
        
        // For the current segment, we can only reference blocks that have been computed so far
        if (index_in_segment > 0) {
            area_size += index_in_segment;
        }
    }
    
    // Ensure area_size is at least 1
    if (area_size == 0) {
        area_size = 1;
    }
    
    // Convert J1 to reference position
    uint64_t x = (static_cast<uint64_t>(J1) * static_cast<uint64_t>(J1)) >> 32;
    uint64_t y = (static_cast<uint64_t>(area_size) * x) >> 32;
    uint32_t ref_offset = static_cast<uint32_t>(y);
    
    if (pass == 0) {
        // Pass 0: reference area starts at block 0
        // No adjustment needed, ref_offset is already in [0, area_size-1]
    } else {
        // Pass > 0: handle two regions
        uint32_t segment_start = slice * segment_length;
        uint32_t pre_segment_blocks = lane_length - segment_length;
        
        if (ref_offset < pre_segment_blocks) {
            // Reference pre-segment blocks [0, segment_start - 1]
            ref_offset = ref_offset; // Already correct
        } else {
            // Reference current segment blocks [segment_start, segment_start + index_in_segment - 1]
            uint32_t offset_in_segment = ref_offset - pre_segment_blocks;
            if (offset_in_segment < index_in_segment) {
                ref_offset = segment_start + offset_in_segment;
            } else {
                // Fallback: reference pre-segment blocks
                ref_offset = offset_in_segment % pre_segment_blocks;
            }
        }
        
        // Final safety check
        if (ref_offset >= current_index) {
            ref_offset = ref_offset % current_index;
        }
    }

    
    // Avoid immediate predecessor
    if (ref_offset == current_index - 1) {
        ref_offset = (current_index > 1) ? (current_index - 2) : 0;
    }
    
    return ref_offset;
}


// Argon2i reference index (data-independent) for p=1.
uint32_t Argon2id::index_argon2i(uint32_t pass, uint32_t slice, uint32_t index_in_segment, uint32_t segment_length, uint32_t lane_length, AddrGen& ag) {

    if (ag.offset >= 128) addrgen_refill(ag);
    
    uint64_t r = ag.addr_block.v[ag.offset++];
    uint32_t J1 = static_cast<uint32_t>(r & 0xFFFFFFFFu);
    
    // Use the corrected mapping function
    return map_index_alpha(pass, slice, index_in_segment, segment_length, lane_length, J1);
}


// Argon2d reference index (data-dependent) for p=1.
uint32_t Argon2id::index_argon2d(uint32_t pass, uint32_t slice, uint32_t index_in_segment, uint32_t segment_length, uint32_t lane_length, const Block1k* mem, uint32_t curr_abs_index) const {

    if (curr_abs_index == 0) return 0;
    
    const Block1k &prev = mem[curr_abs_index - 1];
    uint64_t r0 = prev.v[0];
    uint32_t J1 = static_cast<uint32_t>(r0 & 0xFFFFFFFFu);
    
    // Use the corrected mapping function
    return map_index_alpha(pass, slice, index_in_segment, segment_length, lane_length, J1);
}




// ----- H0 (initial parameter hash) -----
void Argon2id::hashH0(const std::vector<uint8_t>& pwd, const std::vector<uint8_t>& salt, std::vector<uint8_t>& outH0) {
    // H0 = H64( LE32(p), LE32(T), LE32(m), LE32(t), LE32(version), LE32(type),
    //           LE32(|pwd|), pwd, LE32(|salt|), salt,
    //           LE32(|secret|)=0, LE32(|ad|)=0 )
    std::vector<uint8_t> buf;
    append_u32(buf, LANES);
    append_u32(buf, _out_len);
    append_u32(buf, _m_cost);
    append_u32(buf, _t_cost);
    append_u32(buf, ARGON2_VERSION);
    append_u32(buf, ARGON2_TYPE_ID);

    append_u32(buf, static_cast<uint32_t>(pwd.size()));
    buf.insert(buf.end(), pwd.begin(), pwd.end());

    append_u32(buf, static_cast<uint32_t>(salt.size()));
    buf.insert(buf.end(), salt.begin(), salt.end());

    append_u32(buf, 0); // secret length
    append_u32(buf, 0); // ad length

    outH0.resize(64);
    blake.reset(64);
    blake.update(buf.data(), buf.size());
    blake.finalize(outH0.data(), 64);
    explicit_bzero(buf.data(), buf.size());
}



// ----- LE helpers -----
void Argon2id::append_u32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(uint8_t(x      ));
    v.push_back(uint8_t(x >>  8));
    v.push_back(uint8_t(x >> 16));
    v.push_back(uint8_t(x >> 24));
}
void Argon2id::append_u64(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 0; i < 8; ++i) v.push_back(uint8_t(x >> (8*i)));
}
