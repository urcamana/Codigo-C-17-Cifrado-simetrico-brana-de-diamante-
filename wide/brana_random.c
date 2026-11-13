/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */

#include "brana_random.h"
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

int brana_random_bytes(uint8_t *out, size_t len)
{
    NTSTATUS st;
    if (!out || len == 0) return -1;
    st = BCryptGenRandom(NULL, out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (st == 0) ? 0 : -1;
}

#else

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#if defined(__linux__)
#include <sys/random.h>
#endif

int brana_random_bytes(uint8_t *out, size_t len)
{
    size_t off = 0;
    if (!out || len == 0) return -1;

#if defined(__linux__)

    while (off < len) {
        ssize_t n = getrandom(out + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        off += (size_t)n;
    }
    if (off == len) return 0;
    off = 0;
#endif

    {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) return -1;
        while (off < len) {
            ssize_t n = read(fd, out + off, len - off);
            if (n < 0) {
                if (errno == EINTR) continue;
                close(fd);
                return -1;
            }
            if (n == 0) {
                close(fd);
                return -1;
            }
            off += (size_t)n;
        }
        close(fd);
    }
    return 0;
}
#endif

int brana_random_salt16(uint8_t salt16[16])
{
    if (!salt16) return -1;
    return brana_random_bytes(salt16, 16);
}
