/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */


#ifndef BRANA_MAC_H
#define BRANA_MAC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BRANA_MAC_LEN 32
#define BRANA_MAC_ZONE (BRANA_MAC_LEN * 2)
#define BRANA_MAC_MSG_LEN 80
#define BRANA_MAC_DOM_PLAIN 0ULL
#define BRANA_MAC_DOM_CT    1ULL

int brana_mac(const uint8_t K[32],
              const uint8_t *msg, size_t msg_len,
              uint8_t out32[BRANA_MAC_LEN]);

int brana_mac_verify(const uint8_t a[BRANA_MAC_LEN],
                     const uint8_t b[BRANA_MAC_LEN]);

void brana_mac_build_msg(uint8_t out[BRANA_MAC_MSG_LEN],
                         const uint8_t salt[16], int profile,
                         uint64_t CRC_Control, uint64_t Control_Semilla,
                         uint64_t Faro, uint64_t Fatiga,
                         uint64_t N_defensa, uint64_t size_data,
                         uint64_t body_fp);

uint64_t brana_mac_update_fp(uint64_t fp, const uint8_t *p, size_t n);

#ifdef __cplusplus
}
#endif

#endif
