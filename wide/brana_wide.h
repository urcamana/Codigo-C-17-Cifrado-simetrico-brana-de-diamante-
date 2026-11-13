/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */


#ifndef BRANA_WIDE_H
#define BRANA_WIDE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


#define BRANA_WIDE_LIMB_BITS 64


#ifndef BRANA_WIDE_MAX_LIMBS
#define BRANA_WIDE_MAX_LIMBS 32
#endif


#define BRANA_WIDE_MAX_BITS (BRANA_WIDE_MAX_LIMBS * BRANA_WIDE_LIMB_BITS)


typedef struct brana_uint_s {
    uint64_t limb[BRANA_WIDE_MAX_LIMBS];
    unsigned nlimbs;
} brana_uint;


void brana_uint_zero(brana_uint *x);


void brana_uint_set_nlimbs(brana_uint *x, unsigned n);


void brana_uint_set_bits(brana_uint *x, unsigned W);


unsigned brana_uint_nlimbs(const brana_uint *x);


unsigned brana_uint_bits(const brana_uint *x);


void brana_uint_from_bytes(brana_uint *x, const uint8_t *b, size_t len);


void brana_uint_to_bytes(const brana_uint *x, uint8_t *b, size_t len);


void brana_uint_xor(brana_uint *r, const brana_uint *a, const brana_uint *b);


void brana_uint_add(brana_uint *r, const brana_uint *a, const brana_uint *b);


void brana_uint_rotl(brana_uint *r, const brana_uint *a, unsigned bits);


int brana_uint_ct_eq(const brana_uint *a, const brana_uint *b);

#ifdef __cplusplus
}
#endif

#endif
