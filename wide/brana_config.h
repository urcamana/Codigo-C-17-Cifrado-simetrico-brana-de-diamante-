/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */


#ifndef BRANA_CONFIG_H
#define BRANA_CONFIG_H

// --- Ancho institucional (editar al compilar el ENCRIPTADOR) ---
// Ejemplo: -DBRANA_BITS=256  o  512, 1024, 2048, 65536, ...
// Reglas: >= 256, multiplo de 32. El desencriptador es universal (lee el archivo).
#ifndef BRANA_BITS
#define BRANA_BITS 256
#endif


// Tope blando de bits (subir solo si hace falta)
#ifndef BRANA_BITS_SOFT_MAX
#define BRANA_BITS_SOFT_MAX 1048576
#endif

#if (BRANA_BITS < 256)
#error "BRANA_BITS minimo = 256"
#endif
#if (BRANA_BITS % 32) != 0
#error "BRANA_BITS debe ser multiplo de 32"
#endif
#if (BRANA_BITS > BRANA_BITS_SOFT_MAX)
#error "BRANA_BITS > BRANA_BITS_SOFT_MAX (sube SOFT_MAX en brana_config.h si hace falta)"
#endif

#define BRANA_KEY_BYTES    (BRANA_BITS / 8)
#define BRANA_KEY_LIMBS    ((BRANA_BITS + 63) / 64)
#define BRANA_STATE_BITS   (BRANA_BITS)
#define BRANA_BLOCK_BYTES  (BRANA_BITS / 8)

#define BRANA_KDF_MIN_OUT  32
#if BRANA_KEY_BYTES < 32
#error "BRANA_KEY_BYTES < 32"
#endif


#define BRANA_V5_FLOW_ROUNDS  (12u + (unsigned)(BRANA_BITS / 256u) * 2u)


#define BRANA_BASURA_OFF_SALT     0
#define BRANA_BASURA_OFF_PROFILE  16
#define BRANA_BASURA_OFF_SENUELO  17
#define BRANA_BASURA_OFF_NONCE    25
#define BRANA_BASURA_OFF_BITS     41
#define BRANA_BASURA_BITS_LEN     4
#define BRANA_BASURA_OFF_BITS_MAGIC 45
#define BRANA_BASURA_MAGIC_0       0xB1u
#define BRANA_BASURA_MAGIC_1       0x54u


#endif
