/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */

#include "brana_dual.h"
#include <string.h>

void brana_dual_init(brana_dual *d, unsigned rail_bits)
{
    if (!d) return;
    if (rail_bits < 64u) rail_bits = 64u;
    brana_uint_zero(&d->A);
    brana_uint_zero(&d->B);
    brana_uint_set_bits(&d->A, rail_bits);
    brana_uint_set_bits(&d->B, rail_bits);
}

void brana_dual_round_fwd(brana_dual *d,
                          unsigned rot_a, unsigned rot_b,
                          const brana_uint *Ka, const brana_uint *Kb)
{
    brana_uint t;
    if (!d || !Ka || !Kb) return;


    brana_uint_rotl(&t, &d->A, rot_b);
    brana_uint_xor(&t, &t, Kb);
    brana_uint_xor(&d->B, &d->B, &t);


    brana_uint_rotl(&t, &d->B, rot_a);
    brana_uint_xor(&t, &t, Ka);
    brana_uint_xor(&d->A, &d->A, &t);
}

void brana_dual_round_inv(brana_dual *d,
                          unsigned rot_a, unsigned rot_b,
                          const brana_uint *Ka, const brana_uint *Kb)
{
    brana_uint t;
    if (!d || !Ka || !Kb) return;


    brana_uint_rotl(&t, &d->B, rot_a);
    brana_uint_xor(&t, &t, Ka);
    brana_uint_xor(&d->A, &d->A, &t);


    brana_uint_rotl(&t, &d->A, rot_b);
    brana_uint_xor(&t, &t, Kb);
    brana_uint_xor(&d->B, &d->B, &t);
}

void brana_dual_to_bytes(const brana_dual *d, uint8_t *out, size_t out_len)
{
    size_t half;
    if (!d || !out || out_len == 0) return;
    half = (size_t)brana_uint_bits(&d->A) / 8u;
    if (out_len < half * 2u) return;
    brana_uint_to_bytes(&d->A, out, half);
    brana_uint_to_bytes(&d->B, out + half, half);
}

void brana_dual_from_bytes(brana_dual *d, const uint8_t *in, size_t in_len)
{
    size_t half;
    if (!d || !in) return;
    half = (size_t)brana_uint_bits(&d->A) / 8u;
    if (in_len < half * 2u) return;
    brana_uint_from_bytes(&d->A, in, half);
    brana_uint_from_bytes(&d->B, in + half, half);
}
