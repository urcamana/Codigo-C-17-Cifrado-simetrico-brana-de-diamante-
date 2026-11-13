/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */


#ifndef BRANA_STREAM_H
#define BRANA_STREAM_H

#include "brana_dual.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


int brana_stream_xor_ex(uint8_t *out, const uint8_t *in, size_t len,
                        const uint8_t *seed, size_t seed_len,
                        const uint8_t *nonce, size_t nonce_len,
                        unsigned rail_bits, unsigned rounds,
                        uint64_t start_block);


int brana_stream_xor(uint8_t *out, const uint8_t *in, size_t len,
                     const uint8_t *seed, size_t seed_len,
                     const uint8_t *nonce, size_t nonce_len,
                     unsigned rail_bits, unsigned rounds);

#ifdef __cplusplus
}
#endif

#endif
