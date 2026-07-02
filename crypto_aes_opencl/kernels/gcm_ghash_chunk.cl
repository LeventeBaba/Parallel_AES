#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable

static inline ulong be64_load_g(const __global uchar* p)
{
    return ((ulong)p[0] << 56) |
           ((ulong)p[1] << 48) |
           ((ulong)p[2] << 40) |
           ((ulong)p[3] << 32) |
           ((ulong)p[4] << 24) |
           ((ulong)p[5] << 16) |
           ((ulong)p[6] << 8) |
           ((ulong)p[7]);
}

static inline void gf128_shift_right(ulong* hi, ulong* lo)
{
    ulong l = *lo;
    ulong h = *hi;
    *lo = (l >> 1) | (h << 63);
    *hi = (h >> 1);
}

static inline void gf128_mul(ulong x_hi, ulong x_lo, ulong y_hi, ulong y_lo, ulong* out_hi, ulong* out_lo)
{
    ulong z_hi = 0;
    ulong z_lo = 0;

    ulong v_hi = y_hi;
    ulong v_lo = y_lo;

    for (int i = 0; i < 128; i++) {
        uint bit;
        if (i < 64) {
            bit = (uint)((x_hi >> (63 - i)) & 1ul);
        } else {
            bit = (uint)((x_lo >> (127 - i)) & 1ul);
        }

        ulong lsb = v_lo & 1ul;
        ulong mask = (ulong)0 - (ulong)bit;

        z_hi ^= v_hi & mask;
        z_lo ^= v_lo & mask;

        gf128_shift_right(&v_hi, &v_lo);
        if (lsb) {
            v_hi ^= 0xe100000000000000ul;
        }
    }

    *out_hi = z_hi;
    *out_lo = z_lo;
}

__kernel void gcm_ghash_chunk(__global const uchar* blocks,
                             __global ulong* chunk_hashes,
                             ulong num_blocks,
                             uint chunk_blocks,
                             ulong h_hi,
                             ulong h_lo)
{
    ulong gid = (ulong)get_global_id(0);
    ulong start = gid * (ulong)chunk_blocks;

    if (start >= num_blocks) {
        return;
    }

    ulong y_hi = 0;
    ulong y_lo = 0;

    for (uint i = 0; i < chunk_blocks; i++) {
        ulong idx = start + (ulong)i;
        if (idx >= num_blocks) {
            break;
        }

        const __global uchar* p = blocks + idx * 16;
        ulong x_hi = be64_load_g(p);
        ulong x_lo = be64_load_g(p + 8);

        y_hi ^= x_hi;
        y_lo ^= x_lo;

        ulong t_hi;
        ulong t_lo;
        gf128_mul(y_hi, y_lo, h_hi, h_lo, &t_hi, &t_lo);
        y_hi = t_hi;
        y_lo = t_lo;
    }

    ulong out_idx = gid * 2ul;
    chunk_hashes[out_idx + 0] = y_hi;
    chunk_hashes[out_idx + 1] = y_lo;
}

__kernel void gcm_ghash_reduce(__global const ulong* chunk_hashes,
                               __global ulong* final_hash,
                               ulong chunk_count,
                               ulong pow_full_hi,
                               ulong pow_full_lo,
                               ulong pow_last_hi,
                               ulong pow_last_lo)
{
    if (get_global_id(0) != 0) {
        return;
    }

    ulong y_hi = 0;
    ulong y_lo = 0;

    for (ulong i = 0; i < chunk_count; i++) {
        ulong chunk_hi = chunk_hashes[i * 2ul + 0ul];
        ulong chunk_lo = chunk_hashes[i * 2ul + 1ul];
        ulong mul_hi;
        ulong mul_lo;

        if (i + 1ul == chunk_count) {
            gf128_mul(y_hi, y_lo, pow_last_hi, pow_last_lo, &mul_hi, &mul_lo);
        } else {
            gf128_mul(y_hi, y_lo, pow_full_hi, pow_full_lo, &mul_hi, &mul_lo);
        }

        y_hi = mul_hi ^ chunk_hi;
        y_lo = mul_lo ^ chunk_lo;
    }

    final_hash[0] = y_hi;
    final_hash[1] = y_lo;
}
