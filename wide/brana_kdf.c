/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */


#include "brana_kdf.h"
#include "brana_dual.h"
#include <stdlib.h>
#include <string.h>

void brana_kdf_get_params(int profile, brana_kdf_params *p)
{
    if (!p) return;
    switch (profile) {
    case BRANA_KDF_PROFILE_FAST:
        p->buf_mb = 1;
        p->rounds = 2;
        p->dual_r = 4;
        break;
    case BRANA_KDF_PROFILE_HIGH:
        p->buf_mb = 32;
        p->rounds = 6;
        p->dual_r = 12;
        break;
    case BRANA_KDF_PROFILE_NORMAL:
    default:
        p->buf_mb = 8;
        p->rounds = 4;
        p->dual_r = 8;
        break;
    }
}


static void mix_password_material(uint8_t out[32],
                                  const char *usuario, const char *clave,
                                  const uint8_t salt[16])
{
    uint64_t s0 = 0x243F6A8885A308D3ULL;
    uint64_t s1 = 0x13198A2E03707344ULL;
    size_t i;
    const char *u = usuario ? usuario : "";
    const char *c = clave ? clave : "";

    for (i = 0; u[i]; i++) {
        s0 ^= ((uint64_t)(uint8_t)u[i]) << ((i % 8) * 8);
        s0 = s0 * 0xBF58476D1CE4E5B9ULL + 0x9E3779B97F4A7C15ULL;
        s0 ^= (s0 >> 29);
    }
    for (i = 0; c[i]; i++) {
        s1 ^= ((uint64_t)(uint8_t)c[i]) << ((i % 8) * 8);
        s1 = s1 * 0x94D049BB133111EBULL + 0xBF58476D1CE4E5B9ULL;
        s1 ^= (s1 >> 27);
    }
    for (i = 0; i < 16; i++) {
        s0 ^= ((uint64_t)salt[i]) << ((i % 8) * 8);
        s1 ^= ((uint64_t)salt[15 - i]) << ((i % 8) * 8);
        s0 = s0 * 0xD6E8FEB86659FD93ULL + s1;
        s1 = s1 * 0xA5A79147E6DD9C5FULL + s0;
    }
    for (i = 0; i < 4; i++) {
        s0 ^= s1;
        s1 += s0;
        s0 = (s0 << 17) | (s0 >> 47);
        s1 = (s1 << 29) | (s1 >> 35);
    }
    for (i = 0; i < 8; i++) {
        out[i]      = (uint8_t)((s0 >> (i * 8)) & 0xFF);
        out[8 + i]  = (uint8_t)((s1 >> (i * 8)) & 0xFF);
    }

    s0 ^= 0xA0761D6478BD642FULL;
    s1 ^= 0xE7037ED1A0B428DBULL;
    for (i = 0; i < 8; i++) {
        out[16 + i] = (uint8_t)((s0 >> (i * 8)) & 0xFF);
        out[24 + i] = (uint8_t)((s1 >> (i * 8)) & 0xFF);
    }
}

int brana_kdf(const char *usuario, const char *clave,
              const uint8_t salt[BRANA_KDF_SALT_LEN],
              int profile,
              uint8_t out32[BRANA_KDF_CORE_LEN])
{
    brana_kdf_params par;
    uint8_t seed[32];
    uint8_t *buf = NULL;
    size_t buf_len, i, r;
    brana_dual st;
    brana_uint Ka, Kb;
    unsigned rail = 128;
    uint64_t acc0, acc1;

    if (!salt || !out32) return -1;

    brana_kdf_get_params(profile, &par);
    mix_password_material(seed, usuario, clave, salt);

    buf_len = (size_t)par.buf_mb * 1024u * 1024u;
    buf = (uint8_t *)malloc(buf_len);
    if (!buf) return -1;


    {
        uint64_t s = 0;
        memcpy(&s, seed, 8);
        for (i = 0; i < buf_len; i++) {
            s = s * 0xBF58476D1CE4E5B9ULL + 0x9E3779B97F4A7C15ULL;
            s ^= (s >> 17);
            buf[i] = (uint8_t)(s & 0xFF) ^ seed[i % 32];
        }
    }

    brana_dual_init(&st, rail);
    brana_uint_from_bytes(&st.A, seed, 16);
    brana_uint_from_bytes(&st.B, seed + 16, 16);

    brana_uint_zero(&Ka);
    brana_uint_zero(&Kb);
    brana_uint_set_bits(&Ka, rail);
    brana_uint_set_bits(&Kb, rail);


    for (r = 0; r < par.rounds; r++) {
        for (i = 0; i + 32 <= buf_len; i += 32) {
            unsigned dr;
            brana_uint_from_bytes(&Ka, buf + i, 16);
            brana_uint_from_bytes(&Kb, buf + i + 16, 16);
            for (dr = 0; dr < par.dual_r; dr++) {
                brana_dual_round_fwd(&st, 7 + (dr % 5), 11 + (dr % 7), &Ka, &Kb);
            }

            brana_dual_to_bytes(&st, buf + i, 32);
        }

        {
            uint8_t tmp[32];
            brana_dual_to_bytes(&st, tmp, 32);
            for (i = 0; i < 32; i++)
                buf[i] ^= tmp[i];
        }
    }


    brana_dual_to_bytes(&st, out32, 32);
    acc0 = 0;
    acc1 = 0;
    for (i = 0; i < buf_len; i += 16) {
        uint64_t piece = 0;
        size_t j;
        for (j = 0; j < 8 && i + j < buf_len; j++)
            piece |= ((uint64_t)buf[i + j]) << (8 * j);
        acc0 ^= piece;
        if (i + 8 < buf_len) {
            piece = 0;
            for (j = 0; j < 8 && i + 8 + j < buf_len; j++)
                piece |= ((uint64_t)buf[i + 8 + j]) << (8 * j);
            acc1 ^= piece;
        }
    }
    for (i = 0; i < 8; i++) {
        out32[i]      ^= (uint8_t)((acc0 >> (8 * i)) & 0xFF);
        out32[8 + i]  ^= (uint8_t)((acc1 >> (8 * i)) & 0xFF);
        out32[16 + i] ^= (uint8_t)((acc0 >> (8 * i)) & 0xFF) ^ seed[i];
        out32[24 + i] ^= (uint8_t)((acc1 >> (8 * i)) & 0xFF) ^ seed[16 + i];
    }


    memset(buf, 0, buf_len);
    free(buf);
    memset(seed, 0, sizeof(seed));
    return 0;
}


#include <string.h>


int brana_kdf_ex(const char *usuario, const char *clave,
                 const uint8_t salt[BRANA_KDF_SALT_LEN],
                 int profile,
                 uint8_t *out, size_t out_len)
{
    uint8_t core[BRANA_KDF_CORE_LEN];
    size_t off;
    uint64_t s0, s1;
    int i;

    if (!out || out_len < 32 || (out_len % 32) != 0)
        return -1;


    if (out_len > (size_t)(BRANA_BITS_SOFT_MAX / 8))
        return -1;

    if (brana_kdf(usuario, clave, salt, profile, core) != 0)
        return -1;


    for (i = 0; i < 32; i++)
        out[i] = core[i];
    if (out_len == 32)
        return 0;


    s0 = 0x9E3779B97F4A7C15ULL;
    s1 = 0xBF58476D1CE4E5B9ULL;
    for (i = 0; i < 32; i++) {
        s0 ^= (uint64_t)core[i] << ((i % 8) * 8);
        s1 ^= (uint64_t)core[31 - i] << ((i % 8) * 8);
    }
    for (off = 32; off < out_len; off++) {
        s0 = s0 * 0xBF58476D1CE4E5B9ULL + s1 + (uint64_t)off;
        s0 ^= (s0 >> 17);

        s1 = s1 * 0x94D049BB133111EBULL + s0 + (uint64_t)out_len * 8ULL;
        s1 ^= (s1 >> 13);
        out[off] = (uint8_t)((s0 ^ s1) & 0xFFu);
        if ((off & 31) == 31) {
            s0 ^= (uint64_t)out[off - 31] * 0x9E3779B97F4A7C15ULL;
        }
    }
    return 0;
}

