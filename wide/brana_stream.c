/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */

#include "brana_stream.h"
#include <string.h>


static void derive_subkey(brana_uint *out, unsigned rail_bits,
                          const uint8_t *seed, size_t seed_len,
                          const uint8_t *nonce, size_t nonce_len,
                          uint64_t counter, uint8_t label)
{
    uint8_t tmp[64];
    size_t i, need;
    uint64_t s = 0x9E3779B97F4A7C15ULL ^ counter ^ ((uint64_t)label << 24);

    memset(tmp, 0, sizeof(tmp));
    need = (size_t)rail_bits / 8u;
    if (need > sizeof(tmp)) need = sizeof(tmp);

    for (i = 0; i < seed_len && i < sizeof(tmp); i++)
        tmp[i] ^= seed[i];
    for (i = 0; i < nonce_len && i < sizeof(tmp); i++)
        tmp[i] ^= nonce[i];


    for (i = 0; i < need; i++) {
        s = s * 0xBF58476D1CE4E5B9ULL + (uint64_t)tmp[i] + label;
        s ^= (s >> 17);
        tmp[i] = (uint8_t)(s & 0xFFu);
    }

    brana_uint_zero(out);
    brana_uint_set_bits(out, rail_bits);
    brana_uint_from_bytes(out, tmp, need);
}

static void block_keystream(uint8_t *block_out, size_t block_bytes,
                            const uint8_t *seed, size_t seed_len,
                            const uint8_t *nonce, size_t nonce_len,
                            uint64_t block_index,
                            unsigned rail_bits, unsigned rounds)
{
    brana_dual st;
    brana_uint Ka, Kb;
    unsigned r;
    size_t half = (size_t)rail_bits / 8u;

    brana_dual_init(&st, rail_bits);


    {
        uint8_t iv[64];
        size_t i;
        memset(iv, 0, sizeof(iv));
        for (i = 0; i < 8 && i < half; i++)
            iv[i] = (uint8_t)((block_index >> (8 * i)) & 0xFFu);
        if (nonce && nonce_len) {
            for (i = 0; i < nonce_len && (8 + i) < half; i++)
                iv[8 + i] ^= nonce[i];
        }
        brana_uint_from_bytes(&st.A, iv, half);

        derive_subkey(&st.B, rail_bits, seed, seed_len, nonce, nonce_len,
                      block_index, 0x5A);
        brana_uint_xor(&st.B, &st.B, &st.A);
    }

    for (r = 0; r < rounds; r++) {
        derive_subkey(&Ka, rail_bits, seed, seed_len, nonce, nonce_len,
                      block_index, (uint8_t)(0xA0 + r));
        derive_subkey(&Kb, rail_bits, seed, seed_len, nonce, nonce_len,
                      block_index, (uint8_t)(0xB0 + r));
        brana_dual_round_fwd(&st, 7 + (r % 5), 11 + (r % 7), &Ka, &Kb);
    }

    brana_dual_to_bytes(&st, block_out, block_bytes);
}

int brana_stream_xor_ex(uint8_t *out, const uint8_t *in, size_t len,
                        const uint8_t *seed, size_t seed_len,
                        const uint8_t *nonce, size_t nonce_len,
                        unsigned rail_bits, unsigned rounds,
                        uint64_t start_block)
{
    size_t block_bytes, off = 0;
    uint64_t blk = start_block;
    uint8_t ks[512];

    if (!out || !seed || seed_len == 0 || rail_bits < 64 || rounds < 1)
        return -1;
    if ((rail_bits % 64u) != 0)
        return -1;

    block_bytes = (size_t)(rail_bits / 8u) * 2u;
    if (block_bytes > sizeof(ks))
        return -1;

    while (off < len) {
        size_t chunk = len - off;
        size_t i;
        if (chunk > block_bytes) chunk = block_bytes;

        block_keystream(ks, block_bytes, seed, seed_len,
                        nonce, nonce_len, blk, rail_bits, rounds);

        for (i = 0; i < chunk; i++) {
            uint8_t p = in ? in[off + i] : 0;
            out[off + i] = p ^ ks[i];
        }
        off += chunk;
        blk++;
    }
    return 0;
}

int brana_stream_xor(uint8_t *out, const uint8_t *in, size_t len,
                     const uint8_t *seed, size_t seed_len,
                     const uint8_t *nonce, size_t nonce_len,
                     unsigned rail_bits, unsigned rounds)
{
    return brana_stream_xor_ex(out, in, len, seed, seed_len,
                               nonce, nonce_len, rail_bits, rounds, 0);
}
