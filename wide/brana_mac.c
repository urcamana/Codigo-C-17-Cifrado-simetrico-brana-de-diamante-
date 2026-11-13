/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */

#include "brana_mac.h"
#include "brana_dual.h"
#include "brana_wide.h"
#include <string.h>

static void put_u64_le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)((v >> (8 * i)) & 0xFF);
}

void brana_mac_build_msg(uint8_t out[BRANA_MAC_MSG_LEN],
                         const uint8_t salt[16], int profile,
                         uint64_t CRC_Control, uint64_t Control_Semilla,
                         uint64_t Faro, uint64_t Fatiga,
                         uint64_t N_defensa, uint64_t size_data,
                         uint64_t body_fp)
{
    memset(out, 0, BRANA_MAC_MSG_LEN);
    memcpy(out, salt, 16);
    out[16] = (uint8_t)(profile & 0xFF);
    put_u64_le(out + 24, CRC_Control);
    put_u64_le(out + 32, Control_Semilla);
    put_u64_le(out + 40, Faro);
    put_u64_le(out + 48, Fatiga);
    put_u64_le(out + 56, N_defensa);
    put_u64_le(out + 64, size_data);
    put_u64_le(out + 72, body_fp);
}


uint64_t brana_mac_update_fp(uint64_t fp, const uint8_t *p, size_t n)
{
    if (fp == 0)
        fp = 14695981039346656037ULL;
    for (size_t i = 0; i < n; i++) {
        fp ^= (uint64_t)p[i];
        fp *= 1099511628211ULL;
    }
    return fp;
}

int brana_mac(const uint8_t K[32],
              const uint8_t *msg, size_t msg_len,
              uint8_t out32[BRANA_MAC_LEN])
{
    if (!K || !out32)
        return -1;
    if (msg_len > 0 && !msg)
        return -1;

    const unsigned rail = 128;
    const unsigned rounds = 12;
    brana_dual st;
    brana_uint Ka, Kb, T, tmp;

    brana_dual_init(&st, rail);
    brana_uint_set_bits(&Ka, rail);
    brana_uint_set_bits(&Kb, rail);
    brana_uint_set_bits(&T, rail);
    brana_uint_set_bits(&tmp, rail);

    brana_uint_from_bytes(&Ka, K, 16);
    brana_uint_from_bytes(&Kb, K + 16, 16);

    for (unsigned r = 0; r < rounds; r++)
        brana_dual_round_fwd(&st, 7 + 3 * r, 11 + 5 * r, &Ka, &Kb);

    size_t off = 0;
    while (off < msg_len) {
        uint8_t blk[32];
        memset(blk, 0, 32);
        size_t n = msg_len - off;
        if (n > 32) n = 32;
        memcpy(blk, msg + off, n);
        if (n < 32)
            blk[n] ^= (uint8_t)(n & 0xFF);

        brana_uint_from_bytes(&T, blk, 16);
        brana_uint_xor(&tmp, &st.A, &T);
        st.A = tmp;
        brana_uint_from_bytes(&T, blk + 16, 16);
        brana_uint_xor(&tmp, &st.B, &T);
        st.B = tmp;

        for (unsigned r = 0; r < rounds; r++) {
            brana_uint_rotl(&tmp, &Ka, 1);
            Ka = tmp;
            brana_uint_rotl(&tmp, &Kb, 3);
            Kb = tmp;
            brana_dual_round_fwd(&st, 13 + 2 * r, 17 + 3 * r, &Ka, &Kb);
        }
        off += n;
    }

    {
        static const uint8_t fin[16] = {
            'B','R','A','N','A','_','M','A','C','_','v','1',0,0,0,1
        };
        brana_uint_from_bytes(&T, fin, 16);
        brana_uint_xor(&tmp, &st.A, &T);
        st.A = tmp;
    }
    for (unsigned r = 0; r < rounds + 4; r++)
        brana_dual_round_fwd(&st, 19 + r, 23 + r, &Ka, &Kb);

    brana_dual_to_bytes(&st, out32, BRANA_MAC_LEN);
    return 0;
}

int brana_mac_verify(const uint8_t a[BRANA_MAC_LEN],
                     const uint8_t b[BRANA_MAC_LEN])
{
    unsigned diff = 0;
    for (int i = 0; i < BRANA_MAC_LEN; i++)
        diff |= (unsigned)(a[i] ^ b[i]);
    return diff == 0 ? 1 : 0;
}
