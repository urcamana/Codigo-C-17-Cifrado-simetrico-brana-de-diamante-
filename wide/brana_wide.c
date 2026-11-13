/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */


#include "brana_wide.h"
#include <string.h>

void brana_uint_zero(brana_uint *x)
{
    if (!x) return;
    memset(x->limb, 0, sizeof(x->limb));
    x->nlimbs = 1;
}

void brana_uint_set_nlimbs(brana_uint *x, unsigned n)
{
    unsigned i;
    if (!x) return;
    if (n < 1u) n = 1u;
    if (n > (unsigned)BRANA_WIDE_MAX_LIMBS) n = (unsigned)BRANA_WIDE_MAX_LIMBS;
    if (n > x->nlimbs) {
        for (i = x->nlimbs; i < n; i++)
            x->limb[i] = 0;
    }
    x->nlimbs = n;
}

void brana_uint_set_bits(brana_uint *x, unsigned W)
{
    unsigned n;
    if (!x) return;
    if (W < 1u) W = 64u;
    if (W > (unsigned)BRANA_WIDE_MAX_BITS) W = (unsigned)BRANA_WIDE_MAX_BITS;
    n = (W + 63u) / 64u;
    if (n < 1u) n = 1u;
    brana_uint_set_nlimbs(x, n);
}

unsigned brana_uint_nlimbs(const brana_uint *x)
{
    return x ? x->nlimbs : 0;
}

unsigned brana_uint_bits(const brana_uint *x)
{
    return x ? (x->nlimbs * 64u) : 0;
}

void brana_uint_from_bytes(brana_uint *x, const uint8_t *b, size_t len)
{
    size_t need, i, ncopy;
    if (!x) return;
    memset(x->limb, 0, sizeof(uint64_t) * x->nlimbs);
    if (!b || len == 0) return;
    need = (size_t)x->nlimbs * 8u;
    ncopy = (len < need) ? len : need;

    for (i = 0; i < ncopy; i++) {
        unsigned li = (unsigned)(i / 8u);
        unsigned sh = (unsigned)((i % 8u) * 8u);
        x->limb[li] |= ((uint64_t)b[i]) << sh;
    }
}

void brana_uint_to_bytes(const brana_uint *x, uint8_t *b, size_t len)
{
    size_t i, need, ncopy;
    if (!b || len == 0) return;
    memset(b, 0, len);
    if (!x) return;
    need = (size_t)x->nlimbs * 8u;
    ncopy = (len < need) ? len : need;
    for (i = 0; i < ncopy; i++) {
        unsigned li = (unsigned)(i / 8u);
        unsigned sh = (unsigned)((i % 8u) * 8u);
        b[i] = (uint8_t)((x->limb[li] >> sh) & 0xFFu);
    }
}

void brana_uint_xor(brana_uint *r, const brana_uint *a, const brana_uint *b)
{
    unsigned n, i;
    if (!r || !a || !b) return;
    n = a->nlimbs;
    if (b->nlimbs > n) n = b->nlimbs;
    if (n > (unsigned)BRANA_WIDE_MAX_LIMBS) n = (unsigned)BRANA_WIDE_MAX_LIMBS;
    brana_uint_set_nlimbs(r, n);
    for (i = 0; i < n; i++) {
        uint64_t av = (i < a->nlimbs) ? a->limb[i] : 0;
        uint64_t bv = (i < b->nlimbs) ? b->limb[i] : 0;
        r->limb[i] = av ^ bv;
    }
}

void brana_uint_add(brana_uint *r, const brana_uint *a, const brana_uint *b)
{
    unsigned n, i;
    uint64_t carry = 0;
    if (!r || !a || !b) return;
    n = a->nlimbs;
    if (b->nlimbs > n) n = b->nlimbs;
    if (n > (unsigned)BRANA_WIDE_MAX_LIMBS) n = (unsigned)BRANA_WIDE_MAX_LIMBS;
    brana_uint_set_nlimbs(r, n);
    for (i = 0; i < n; i++) {
        uint64_t av = (i < a->nlimbs) ? a->limb[i] : 0;
        uint64_t bv = (i < b->nlimbs) ? b->limb[i] : 0;
        uint64_t s = av + carry;
        uint64_t c1 = (s < av) ? 1u : 0u;
        uint64_t s2 = s + bv;
        uint64_t c2 = (s2 < s) ? 1u : 0u;
        r->limb[i] = s2;
        carry = c1 + c2;
    }

}

void brana_uint_rotl(brana_uint *r, const brana_uint *a, unsigned bits)
{
    unsigned n, total_bits, i;
    unsigned limb_rot, bit_rot;
    brana_uint tmp;
    if (!r || !a) return;
    n = a->nlimbs;
    if (n < 1u) return;
    total_bits = n * 64u;
    bits %= total_bits;
    if (bits == 0u) {
        if (r != a) {
            brana_uint_set_nlimbs(r, n);
            memcpy(r->limb, a->limb, sizeof(uint64_t) * n);
        }
        return;
    }
    limb_rot = bits / 64u;
    bit_rot = bits % 64u;
    brana_uint_zero(&tmp);
    brana_uint_set_nlimbs(&tmp, n);
    for (i = 0; i < n; i++) {
        unsigned src = (i + n - limb_rot) % n;
        uint64_t v = a->limb[src];
        uint64_t v_lo, v_hi, prev;
        if (bit_rot == 0u) {
            tmp.limb[i] = v;
        } else {
            prev = a->limb[(src + n - 1u) % n];
            v_lo = v << bit_rot;
            v_hi = prev >> (64u - bit_rot);
            tmp.limb[i] = v_lo | v_hi;
        }
    }
    brana_uint_set_nlimbs(r, n);
    memcpy(r->limb, tmp.limb, sizeof(uint64_t) * n);
}

int brana_uint_ct_eq(const brana_uint *a, const brana_uint *b)
{
    unsigned n, i;
    uint64_t d = 0;
    if (!a || !b) return 0;
    if (a->nlimbs != b->nlimbs) {

        return 0;
    }
    n = a->nlimbs;
    for (i = 0; i < n; i++)
        d |= (a->limb[i] ^ b->limb[i]);

    return (d == 0) ? 1 : 0;
}
