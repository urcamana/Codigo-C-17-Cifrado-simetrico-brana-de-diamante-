/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */


#ifndef BRANA_KDF_H
#define BRANA_KDF_H

#include <stddef.h>
#include <stdint.h>
#include "brana_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BRANA_KDF_SALT_LEN   16

#define BRANA_KDF_CORE_LEN   32

#define BRANA_KDF_OUT_LEN    BRANA_KEY_BYTES
#define BRANA_KDF_OUT_FULL   BRANA_KEY_BYTES

#define BRANA_KDF_PROFILE_FAST   0
#define BRANA_KDF_PROFILE_NORMAL 1
#define BRANA_KDF_PROFILE_HIGH   2

int brana_kdf(const char *usuario, const char *clave,
              const uint8_t salt[BRANA_KDF_SALT_LEN],
              int profile,
              uint8_t out_core[BRANA_KDF_CORE_LEN]);

typedef struct brana_kdf_params_s {
    unsigned buf_mb;
    unsigned rounds;
    unsigned dual_r;
} brana_kdf_params;

void brana_kdf_get_params(int profile, brana_kdf_params *p);


int brana_kdf_ex(const char *usuario, const char *clave,
                 const uint8_t salt[BRANA_KDF_SALT_LEN],
                 int profile,
                 uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif
