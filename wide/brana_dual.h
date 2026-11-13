/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */


#ifndef BRANA_DUAL_H
#define BRANA_DUAL_H

#include "brana_wide.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct brana_dual_s {
    brana_uint A;
    brana_uint B;
} brana_dual;


void brana_dual_init(brana_dual *d, unsigned rail_bits);


void brana_dual_round_fwd(brana_dual *d,
                          unsigned rot_a, unsigned rot_b,
                          const brana_uint *Ka, const brana_uint *Kb);


void brana_dual_round_inv(brana_dual *d,
                          unsigned rot_a, unsigned rot_b,
                          const brana_uint *Ka, const brana_uint *Kb);


void brana_dual_to_bytes(const brana_dual *d, uint8_t *out, size_t out_len);


void brana_dual_from_bytes(brana_dual *d, const uint8_t *in, size_t in_len);

#ifdef __cplusplus
}
#endif

#endif
