/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */


#include "brana_v5_flow.h"
#include <stdlib.h>
#include <string.h>


static const uint64_t LAMBDA = 577215664ULL;
static const uint64_t REFERENCIA = 528000000ULL;
static const uint64_t ANCLAJE_SIGMA = 4040509648ULL;


static const uint64_t C_SIGMA = 0xBF58476D1CE4E5B9ULL;
static const uint64_t C_MU    = 0x94D049BB133111EBULL;
static const uint64_t C_GOLD  = 0x9E3779B97F4A7C15ULL;

static uint64_t rotl64(uint64_t x, unsigned n)
{
    n &= 63u;
    return n ? ((x << n) | (x >> (64u - n))) : x;
}

static uint8_t rotl8(uint8_t x, unsigned n)
{
    n &= 7u;
    return (uint8_t)((x << n) | (x >> (8u - n)));
}

static void torsionar_base_8(uint64_t e[8], uint64_t k)
{

    uint64_t rot = k;
    unsigned i;
    for (i = 0; i < 8; i++) {
        uint64_t x = e[i] ^ e[(i + 1) & 7] ^ rot;
        x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
        x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
        e[i] = x ^ (x >> 31);
        rot = ((rot << 13) | (rot >> 51)) ^ k;
        rot ^= e[i];
    }
}

static void array_torsion_8(uint64_t e[8])
{
    unsigned i;
    torsionar_base_8(e, LAMBDA);
    torsionar_base_8(e, REFERENCIA ^ LAMBDA);
    for (i = 0; i < 4; i++)
        e[i] ^= e[7 - i];
}

static void v5_torsion_round(uint64_t *s, size_t nlimbs)
{
    size_t i;
    if (nlimbs < 2)
        return;
    for (i = 0; i < nlimbs; i++) {
        uint64_t a = s[i];
        uint64_t b = s[(i + 1) % nlimbs];
        uint64_t c = s[(i + 3) % nlimbs];
        a = rotl64(a + b + C_GOLD, (unsigned)(b & 63ull));
        a ^= c * C_SIGMA;
        a = rotl64(a, 17) + b;
        a ^= (a >> 27);
        s[i] = a;
    }
    if (nlimbs >= 4) {
        size_t half = nlimbs / 2;
        for (i = 0; i < half; i++) {
            uint64_t f = s[i];
            uint64_t e = s[i + half];
            s[i] = f + rotl64(e, 9);
            s[i + half] = e ^ rotl64(f, 13) ^ C_MU;
        }
    }
    if (nlimbs >= 8) {
        for (i = 0; i + 8 <= nlimbs; i += 8)
            array_torsion_8(&s[i]);
        if ((nlimbs % 8) != 0)
            array_torsion_8(&s[nlimbs - 8]);
    }
}

static void v5_init_viscosa(uint8_t tab[256], const uint8_t *key, size_t key_len)
{
    size_t i, j = 0;
    uint64_t s = C_GOLD;
    for (i = 0; i < key_len; i++)
        s = s * C_SIGMA + key[i] + (uint64_t)i;
    for (i = 0; i < 256; i++)
        tab[i] = (uint8_t)i;
    for (i = 0; i < 256; i++) {
        s = s * C_MU + tab[i] + LAMBDA;
        s ^= (s >> 17);
        j = (j + tab[i] + (size_t)(s & 0xFFu)) & 255u;
        {
            uint8_t t = tab[i];
            tab[i] = tab[j];
            tab[j] = t;
        }
    }
}

static uint64_t load_u64_le(const uint8_t *p, size_t avail, size_t off)
{
    uint64_t v = 0;
    size_t i;
    for (i = 0; i < 8; i++) {
        size_t idx = off + i;
        if (idx < avail)
            v |= (uint64_t)p[idx] << (8 * i);
    }
    return v;
}

static uint8_t secundaria_individual_ks(uint64_t freq, uint64_t i, uint64_t clave, uint8_t VEV)
{
    uint64_t desp = (i * ((LAMBDA >> 22) + 3ull)) & 63ull;
    uint64_t salto = rotl64((uint64_t)VEV, (unsigned)desp);
    uint64_t fase = (freq ^ (i * 0x94D049BBull)) ^ (salto ^ (clave << 5));
    uint8_t comp = (uint8_t)(((fase >> ((i * 19ull) & 63ull)) ^ clave) & 0xFFull);
    return (uint8_t)((comp ^ (uint8_t)(clave >> 12) ^ (uint8_t)(freq >> 20)) & 0xFFu);
}

static uint8_t dual_esclavo1_ks(uint64_t freq, uint64_t i, uint64_t clave, uint8_t VEV)
{
    uint64_t desp = (i * (LAMBDA >> 20)) & 63ull;
    uint64_t salto = rotl64((uint64_t)VEV, (unsigned)desp);
    uint64_t fase = (freq ^ (i * 0x9E3779B9ull)) ^ (salto ^ (clave << 1));
    return (uint8_t)((((fase ^ LAMBDA) >> ((i * 13ull) & 63ull))
                      ^ (clave >> 32) ^ (freq >> 8)) & 0xFFu);
}

static uint8_t dual_esclavo2_ks(uint64_t freq, uint64_t i, uint64_t clave, uint8_t VEV)
{
    uint64_t desp = (i * ((LAMBDA >> 20) + 1ull)) & 63ull;
    uint64_t salto = rotl64((uint64_t)VEV, (unsigned)desp);
    uint64_t fase = (freq ^ (i * 0xBF58476Dull)) ^ (salto ^ (clave << 3));
    return (uint8_t)((((fase ^ (LAMBDA + 1ull)) >> ((i * 17ull) & 63ull))
                      ^ (clave >> 24) ^ (freq >> 16)) & 0xFFu);
}

static uint8_t secundaria_dual_ks(uint64_t freq, uint64_t i, uint64_t clave, uint8_t VEV)
{
    return (VEV & 1u) ? dual_esclavo2_ks(freq, i, clave, VEV)
                      : dual_esclavo1_ks(freq, i, clave, VEV);
}

static uint64_t aplicar_salto_masa(uint64_t dato, uint64_t semilla_dual,
                                   uint64_t offset_byte, uint64_t semilla_mutante)
{
    uint64_t sem_local = (semilla_dual ^ LAMBDA) ^ (offset_byte ^ semilla_mutante);
    uint64_t tension = (sem_local ^ ANCLAJE_SIGMA) * 0xBF58476D1CE4E5B9ULL;
    uint64_t resto = sem_local % 7ull;
    return dato ^ tension ^ resto;
}

static void inject_estado8(uint64_t e[8], uint64_t i, uint8_t byte_ks)
{
    uint64_t inj = (uint64_t)byte_ks;
    uint64_t desp = i & 31ull;
    uint64_t idx = i & 7ull;
    uint64_t lambda_local = LAMBDA + (e[idx] & (LAMBDA >> 6));
    e[idx] ^= (inj << desp) | (inj >> (64ull - desp));
    e[idx] ^= (inj >> 5);
    e[idx] += lambda_local;
}


static void derivar_params_principal(const uint8_t *key, size_t key_len,
                                     const uint8_t *nonce, size_t nonce_len,
                                     uint64_t counter, unsigned bits,
                                     uint64_t *Clave_CRC, uint64_t *Clave_Temp,
                                     uint64_t *Frecuencia_Final,
                                     uint64_t *Frecuencia_Dispersion,
                                     uint64_t *Semilla)
{
    *Clave_CRC = load_u64_le(key, key_len, 0);
    *Clave_Temp = load_u64_le(key, key_len, 8);
    *Frecuencia_Final = load_u64_le(key, key_len, 16);
    *Frecuencia_Dispersion = load_u64_le(key, key_len, 24);
    *Semilla = load_u64_le(key, key_len, 32);
    if (key_len < 40)
        *Semilla ^= *Clave_CRC * C_MU + (uint64_t)bits;
    if (nonce && nonce_len >= 8) {
        uint64_t n0 = load_u64_le(nonce, nonce_len, 0);
        *Frecuencia_Dispersion ^= n0;
        *Semilla ^= n0 << 1;
    }
    if (nonce && nonce_len >= 16) {
        uint64_t n1 = load_u64_le(nonce, nonce_len, 8);
        *Frecuencia_Final ^= n1;
    }
    *Frecuencia_Final ^= counter * C_GOLD;
    *Semilla ^= counter;
}

static void seed_estado8_principal(uint64_t e[8],
                                   uint64_t Clave_CRC, uint64_t Clave_Temp,
                                   uint64_t Frecuencia_Final,
                                   uint64_t Frecuencia_Dispersion,
                                   uint64_t inicio_global)
{
    uint64_t saltos, s;
    e[0] = Frecuencia_Dispersion ^ (Clave_CRC + LAMBDA);
    e[1] = Clave_CRC ^ Clave_Temp;
    e[2] = Frecuencia_Final ^ LAMBDA;
    e[3] = LAMBDA;
    e[4] = Clave_CRC;
    e[5] = (LAMBDA ^ Frecuencia_Final);
    e[6] = Frecuencia_Dispersion ^ 0x5555555555555555ULL;
    e[7] = REFERENCIA ^ Clave_Temp;

    saltos = (inicio_global / 1024ull) & 63ull;
    for (s = 0; s < saltos; s++)
        array_torsion_8(e);
}

static unsigned v5_rounds_wide(unsigned bits)
{
    return 12u + (bits / 256u) * 2u;
}

static void v5_block_keystream(uint8_t *block, size_t block_bytes,
                               uint64_t *s, size_t nlimbs,
                               const uint8_t *key, size_t key_len,
                               const uint8_t *nonce, size_t nonce_len,
                               uint64_t counter, unsigned bits,
                               const uint8_t viscosa[256])
{
    uint64_t e[8];
    uint64_t Clave_CRC, Clave_Temp, Frecuencia_Final, Frecuencia_Dispersion, Semilla;
    uint64_t inicio_global = counter * (uint64_t)block_bytes;
    uint8_t VEV;
    size_t off;
    unsigned r, rounds = v5_rounds_wide(bits);

    derivar_params_principal(key, key_len, nonce, nonce_len, counter, bits,
                             &Clave_CRC, &Clave_Temp, &Frecuencia_Final,
                             &Frecuencia_Dispersion, &Semilla);

    seed_estado8_principal(e, Clave_CRC, Clave_Temp, Frecuencia_Final,
                           Frecuencia_Dispersion, inicio_global);


    if (s && nlimbs) {
        size_t i;
        for (i = 0; i < nlimbs; i++)
            s[i] = e[i & 7] ^ ((uint64_t)i * C_MU) ^ counter ^ (uint64_t)bits;
        for (i = 0; i < key_len; i++)
            s[(i / 8) % nlimbs] ^= (uint64_t)key[i] << ((i % 8) * 8);
        for (r = 0; r < rounds; r++)
            v5_torsion_round(s, nlimbs);
        for (i = 0; i < 8 && i < nlimbs; i++)
            e[i] ^= s[i];
    }

    VEV = (uint8_t)(Frecuencia_Final & 0xFFu);

    for (off = 0; off < block_bytes; off++) {
        uint64_t i = inicio_global + (uint64_t)off;
        uint64_t torsor = e[i & 7ull];
        uint64_t freq;
        uint8_t aleat, idx, mask, ks;

        if (i < 64ull) {
            freq = Frecuencia_Final ^ Semilla;
            aleat = secundaria_individual_ks(freq, i, Clave_CRC, VEV);
        } else if (i < 2048ull) {
            freq = Frecuencia_Final ^ torsor;
            aleat = secundaria_individual_ks(freq, i, Clave_CRC, VEV);
        } else {
            freq = Frecuencia_Final ^ torsor;
            aleat = secundaria_dual_ks(freq, i, Clave_CRC, VEV);
        }

        idx = (uint8_t)(((torsor >> 32) ^ VEV ^ (uint8_t)(i & 0xFF)) & 0xFF);
        mask = viscosa[idx];
        ks = (uint8_t)(aleat ^ mask ^ rotl8(VEV, (unsigned)(i & 7ull)));
        block[off] = ks;

        inject_estado8(e, i, ks);
        VEV = ks;

        if (i > 0 && ((i + 1) & 1023ull) == 0)
            array_torsion_8(e);
    }


    {
        size_t nwords = block_bytes / 8;
        size_t k;
        for (k = 0; k < nwords; k++) {
            uint64_t w = 0;
            size_t b;
            uint64_t offset_elem = inicio_global + (uint64_t)(k * 8);
            uint64_t sem_mut = Semilla ^ (uint64_t)k;
            for (b = 0; b < 8; b++)
                w |= (uint64_t)block[k * 8 + b] << (8 * b);
            w = aplicar_salto_masa(w, Frecuencia_Final, offset_elem, sem_mut);
            for (b = 0; b < 8; b++)
                block[k * 8 + b] = (uint8_t)((w >> (8 * b)) & 0xFFu);
        }
    }

    if (s && nlimbs) {
        size_t i;
        for (i = 0; i < nlimbs; i++)
            s[i] ^= e[i & 7];
    }
}

int brana_v5_flow_xor_rt(uint8_t *out, const uint8_t *in, size_t len,
                         const uint8_t *key, size_t key_len,
                         const uint8_t *nonce, size_t nonce_len,
                         uint64_t start_block,
                         unsigned bits)
{
    size_t block_bytes, nlimbs;
    size_t off = 0;
    uint64_t blk = start_block;
    uint8_t *ks = NULL;
    uint64_t *state = NULL;
    uint8_t viscosa[256];
    int rc = -1;

    if (!out || !key || key_len == 0)
        return -1;
    if (bits < 256u || (bits % 32u) != 0)
        return -1;

    block_bytes = (size_t)(bits / 8u);
    nlimbs = (size_t)((bits + 63u) / 64u);
    if (block_bytes == 0 || nlimbs == 0)
        return -1;

    v5_init_viscosa(viscosa, key, key_len);
    ks = (uint8_t *)malloc(block_bytes);
    state = (uint64_t *)calloc(nlimbs, sizeof(uint64_t));
    if (!ks || !state)
        goto done;

    while (off < len) {
        size_t chunk = len - off;
        size_t i;
        if (chunk > block_bytes)
            chunk = block_bytes;

        v5_block_keystream(ks, block_bytes, state, nlimbs,
                           key, key_len, nonce, nonce_len, blk, bits, viscosa);

        for (i = 0; i < chunk; i++) {
            uint8_t p = in ? in[off + i] : 0;
            out[off + i] = (uint8_t)(p ^ ks[i]);
        }
        off += chunk;
        blk++;
    }
    rc = 0;
done:
    free(ks);
    free(state);
    return rc;
}

int brana_v5_flow_xor(uint8_t *out, const uint8_t *in, size_t len,
                      const uint8_t *key, size_t key_len,
                      const uint8_t *nonce, size_t nonce_len,
                      uint64_t start_block)
{
    return brana_v5_flow_xor_rt(out, in, len, key, key_len,
                                nonce, nonce_len, start_block,
                                (unsigned)BRANA_BITS);
}
