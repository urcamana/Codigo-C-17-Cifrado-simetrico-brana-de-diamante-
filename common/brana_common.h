/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */

#ifndef BRANA_COMMON_H
#define BRANA_COMMON_H
#include <cstdint>
#include <cstddef>

#define METRICA_L 64
#define VUELTAS_OVILLO 1000001ULL

const uint64_t REFERENCIA = 528ULL;
const uint64_t ZONA_header = 44ULL;
const uint64_t ZONA_faro = 64ULL;
const uint64_t ZONA_REGISTRO = 1024ULL;
const uint64_t Bloque_MAX = 1024ULL * 1024ULL * 16ULL;

#ifdef __cplusplus
struct alignas(METRICA_L) BranaDatos {
    float Fase_Vorticidad[VUELTAS_OVILLO];
    float Espejo_Adelico[VUELTAS_OVILLO];
};
#endif
#endif
