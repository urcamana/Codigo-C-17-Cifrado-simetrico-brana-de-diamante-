/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */



#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <cstdint>
#include <cmath>
#include <iomanip>
#include <thread>
#include <chrono>
#include <algorithm>
#include <vector>
#include <immintrin.h>
#include <cstdio>
#include <sys/stat.h>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#ifndef MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#endif
#include "miniz.h"
#include "crypto/brana_crypto.h"
#include "wide/brana_mac.h"


#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#include <io.h>
#include <fcntl.h>
#include <tchar.h>
#else
#include <unistd.h>
#include <sys/file.h>
#include <sys/sysinfo.h>
#include <x86intrin.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <time.h>
#endif

using namespace std;


#ifdef __linux__
#define _read(fd, buf, count) read(fd, buf, count)
#define _write(fd, buf, count) write(fd, buf, count)
#define _close(fd) close(fd)
#define _lseeki64(fd, offset, origin) lseek(fd, offset, origin)
#define _rotl8(val, shift) static_cast<uint8_t>((val << (shift % 8)) | (val >> (8 - (shift % 8))))
#define _rotl64(val, shift) static_cast<uint64_t>((val << (shift % 64)) | (val >> (64 - (shift % 64))))
#define _rotr8(val, shift) static_cast<uint8_t>((val >> (shift % 8)) | (val << (8 - (shift % 8))))
#define _rotr64(val, shift) static_cast<uint64_t>((val >> (shift % 64)) | (val << (64 - (shift % 64))))
#define _commit(fd) fsync(fd)
#define _telli64(fd) lseek(fd, 0, SEEK_CUR)
#endif
#ifdef _WIN32
    HANDLE hFileIn = INVALID_HANDLE_VALUE;
    HANDLE hFileOut = INVALID_HANDLE_VALUE;
    OVERLAPPED ovIn = {0};
    OVERLAPPED ovOut = {0};
#endif


#pragma pack(push, 1)
struct RegistroFaroFinal {
    uint64_t Faro_Esperado;
    uint64_t Valor_Defensa;
    uint64_t Fatiga_Final;
};
#pragma pack(pop)


// --- Valores editables (personalizacion / hardware) ---
// 1MB - Compatibilidad universal
const size_t Tam_bloque_Hilo = 1 * 1024 * 1024;
// 2MB - Arquitecturas con buena cache L2
// const size_t Tam_bloque_Hilo = 2 * 1024 * 1024;
// 4MB - Estaciones de trabajo / servidores
// const size_t Tam_bloque_Hilo = 4 * 1024 * 1024;


const double ALPHA_S = 0.1181;
const uint64_t ZONA_header = 44ULL;
const uint64_t ZONA_faro = 64ULL;
const uint64_t UMBRAL_CUANTICO = 256ULL * 1024ULL;
const uint64_t ZONA_media = 8ULL * 1024ULL;
const uint64_t ZONA_REGISTRO = 1024ULL;
const uint64_t Bloque_MAX = 1024ULL * 1024ULL * 16ULL;
const int64_t VALORES_DENSIDAD[2LL] = {625LL, -625LL};
const uint64_t UMBRAL_EVOLUCION_32GB = 34359738368ULL;
static const char OV_MAGIC[8]   = { 'O','V','I','L','L','O','0','1' };
static const char BULK_MAGIC[8] = { 'B','U','L','K','0','0','0','1' };
const size_t BULK_IO_BUF = 4ULL * 1024ULL * 1024ULL;
const size_t OV_IO_BUF = 4ULL * 1024ULL * 1024ULL;
const uint64_t BLOQUE = 1024ULL * 1024ULL;
const uint64_t V_MIN = 2ULL;
const uint64_t V_MAX = 500ULL;
const uint64_t V_SPAN = V_MAX - V_MIN + 1ULL;
const uint64_t VUELTA_MAX_L = 758ULL;
const uint64_t VUELTA_MAX_R = 763ULL;


int64_t Acumulador_Espectral = 0LL;
string Usuario, Clave, Nombre_Salida, Texto_Campo;
bool flag_db = false;
bool flag_stream = false;
int fdIn = -1;
int fdOut = -1;
bool Bloqueo_Entrada = false;
bool Bloqueo_Salida = false;
uint64_t Factor_Frecuencia_CPU;
int64_t hSize = 0LL;
uint64_t Control_Semilla_Leida = 0ULL;
uint64_t CRC_Control = 0ULL;
bool ana = false;
uint64_t PosicionFaroGlobal = 0ULL;
uint64_t Constante_Dispersion = 115456244545773ULL;
bool Sincronizado = true;
uint64_t faroLeido;
uint64_t Fatiga_Leida;
uint64_t Valor_Recuperado_Defensa;
bool final = false;
uint64_t Vuelta_R = 1ULL;
uint64_t Vuelta_L = 1ULL;
uint64_t Zona_Defensa_Activa = 4096ULL;
uint64_t BytesProcesadosTotales = 0ULL;
float Torsor_Global = 0.0f;
    bool es_senuelo = false;


bool Verificar_Integridad_Brana(int64_t fd)
{
    if (fd == -1)
        return false;
    if (_telli64(fd) == -1)
    {
        return false;
    }

    if (errno == EBADF || errno == EIO)
    {
        return false;
    }

    return true;
}

bool Verificar_Inercia_Brana(int64_t fdIn, uint64_t Fatiga_Final, uint64_t Semilla_Ofuscacion, int64_t Basura_Relleno_Final, uint64_t Header_y_Masa, uint64_t ZONA_REGISTRO, uint64_t Clave_ENC, uint64_t Usuario_Semilla_Principal, uint64_t Clave_Semilla_Principal)
{

    std::vector<uint8_t> registroLeido(ZONA_REGISTRO);
    _lseeki64(fdIn, -(static_cast<int64_t>(Basura_Relleno_Final) + static_cast<int64_t>(BRANA_MAC_ZONE) + static_cast<int64_t>(ZONA_REGISTRO)), SEEK_END);
    _read(fdIn, registroLeido.data(), static_cast<unsigned int>(ZONA_REGISTRO));

    uint64_t NudoCalculado = (Usuario_Semilla_Principal ^ Clave_ENC) * LAMBDA;
    uint64_t FirmaCalculada = (Fatiga_Final ^ NudoCalculado) ^ ((Header_y_Masa * Clave_Semilla_Principal) + Semilla_Ofuscacion);

    for (uint64_t j = 0ULL; j < ZONA_REGISTRO; j++)
    {
        uint64_t v = (j + FirmaCalculada) * (Clave_ENC | 1ULL);
        uint8_t ByteEsperado = static_cast<uint8_t>((v >> 16ULL) ^ (v >> 8ULL));

        if (registroLeido[j] != ByteEsperado)
        {
            return false;
        }
    }

    return true;
}


void Actualizar_Registro_Final(int64_t fdIn, uint64_t Faro_Esperado, uint64_t Valor_Defensa, uint64_t Fatiga_Final, uint64_t PosicionFaro)
{
    if (fdIn == -1)
        return;

    uint64_t posPreEscrituraRegistro = _lseeki64(fdIn, PosicionFaro, SEEK_SET);
    if (!Verificar_Integridad_Brana(fdIn))
        exit(1);
    _lseeki64(fdIn, PosicionFaro, SEEK_SET);
    RegistroFaroFinal registro = { Faro_Esperado, Valor_Defensa, Fatiga_Final };
    _write(fdIn, &registro, sizeof(RegistroFaroFinal));

#ifdef _WIN32
    _commit(fdIn);
#else
    fsync(fdIn);
#endif
    uint64_t offsetFinalRegistro = _lseeki64(fdIn, 0, SEEK_CUR);
}


#include "pool/brana_pool.hpp"
#include "util/brana_util.h"
#include "container/brana_container.h"
#include "wide/brana_kdf.h"
#include "wide/brana_random.h"
#include "wide/brana_stream.h"
#include "wide/brana_v5_flow.h"
#include "wide/brana_config.h"


static ThreadPool g_Pool;


void Protocolo_Panico_Minimo(int fdIn, uint64_t Total_Bytes_Brana)
{
    if (fdIn < 0 || Total_Bytes_Brana == 0ULL)
        return;


    std::vector<uint8_t> buf(static_cast<size_t>(BLOQUE));

    uint64_t estado = Generador_String(Valor_Header) ^ LAMBDA
                    ^ static_cast<uint64_t>(
                        std::chrono::high_resolution_clock::now()
                            .time_since_epoch().count());

    _lseeki64(fdIn, 0, SEEK_SET);
    uint64_t escritos = 0ULL;

    while (escritos < Total_Bytes_Brana)
    {
        uint64_t quedan = Total_Bytes_Brana - escritos;
        uint64_t n = (quedan > BLOQUE) ? BLOQUE : quedan;

        for (uint64_t i = 0ULL; i < n; ++i)
        {
            estado = Actualizar_Siguiente_Estado(estado);
            buf[static_cast<size_t>(i)] = static_cast<uint8_t>(estado & 0xFFULL);
        }

        _write(fdIn, buf.data(), static_cast<unsigned int>(n));
        escritos += n;
    }

    #ifdef _WIN32
        _commit(fdIn);
    #else
        fsync(fdIn);
    #endif
}

int Verificar_Superficial(const string &path)
{
    int fd = -1;
#ifdef _WIN32
    fd = _open(path.c_str(), _O_RDONLY | _O_BINARY);
#else
    fd = open(path.c_str(), O_RDONLY);
#endif
    if (fd < 0)
    {
        cerr << "[!] No se puede abrir: " << path << "\n";
        return 1;
    }

    int64_t total64 = _lseeki64(fd, 0, SEEK_END);
    if (total64 < 0)
    {
        cerr << "[!] No se puede leer el archivo.\n";
        _close(fd);
        return 1;
    }
    uint64_t Total_Bytes_Brana = static_cast<uint64_t>(total64);

    const uint64_t minimo = ZONA_header + ZONA_faro + ZONA_REGISTRO + BRANA_MAC_ZONE + 56ULL;
    if (Total_Bytes_Brana < minimo)
    {
        cerr << "[!] Archivo no valido o incompleto.\n";
        _close(fd);
        return 1;
    }

    uint64_t Bytes_Header = ZONA_header;
    if (Bytes_Header > Total_Bytes_Brana)
        Bytes_Header = Total_Bytes_Brana;

    std::vector<uint8_t> bufferMaestro(static_cast<size_t>(Bytes_Header));
    _lseeki64(fd, 0, SEEK_SET);
    if (_read(fd, bufferMaestro.data(), static_cast<unsigned int>(Bytes_Header)) !=
        static_cast<int>(Bytes_Header))
    {
        cerr << "[!] Error de lectura.\n";
        _close(fd);
        return 1;
    }

    Restaurar_Torsion_Principal(bufferMaestro, Total_Bytes_Brana);


    if (Bytes_Header < sizeof(int) + sizeof(uint64_t) * 2)
    {
        cerr << "[!] Archivo no valido o incompleto.\n";
        _close(fd);
        return 1;
    }

    int hSize = 0;
    memcpy(&hSize, bufferMaestro.data(), sizeof(int));

    if (hSize < 16 || hSize > 512)
    {
        cerr << "[!] No es un contenedor valido.\n";
        _close(fd);
        return 1;
    }

    const uint64_t off_control = static_cast<uint64_t>(sizeof(int)) + static_cast<uint64_t>(hSize);
    const uint64_t off_crc     = off_control + sizeof(uint64_t);
    const uint64_t fin_logico  = off_crc + sizeof(uint64_t);

    if (fin_logico > Bytes_Header)
    {
        cerr << "[!] No es un contenedor valido.\n";
        _close(fd);
        return 1;
    }

    uint64_t Control_Semilla = 0ULL;
    uint64_t CRC_Control = 0ULL;
    memcpy(&Control_Semilla, &bufferMaestro[static_cast<size_t>(off_control)], sizeof(uint64_t));
    memcpy(&CRC_Control,     &bufferMaestro[static_cast<size_t>(off_crc)],     sizeof(uint64_t));

    if (Control_Semilla == 0ULL || CRC_Control == 0ULL)
    {
        cerr << "[!] No es un contenedor valido.\n";
        _close(fd);
        return 1;
    }

    uint64_t Fatiga_Esperada =
        (Generador_String(Valor_Header) ^ CRC_Control) + (Control_Semilla ^ LAMBDA);

    uint64_t len_basura = Calcular_Longitud_Relleno(Control_Semilla, CRC_Control);
    uint64_t OffsetControl = len_basura + 24ULL + ZONA_REGISTRO + BRANA_MAC_ZONE;

    if (Total_Bytes_Brana <= OffsetControl)
    {
        cerr << "[!] No es un contenedor valido.\n";
        _close(fd);
        return 1;
    }

    uint64_t PosicionFaro = Total_Bytes_Brana - OffsetControl;

    uint64_t faroLeido = 0ULL;
    uint64_t Valor_Defensa = 0ULL;
    uint64_t Fatiga_Leida = 0ULL;

    _lseeki64(fd, static_cast<int64_t>(PosicionFaro), SEEK_SET);
    if (_read(fd, &faroLeido, sizeof(uint64_t)) != (int)sizeof(uint64_t) ||
        _read(fd, &Valor_Defensa, sizeof(uint64_t)) != (int)sizeof(uint64_t) ||
        _read(fd, &Fatiga_Leida, sizeof(uint64_t)) != (int)sizeof(uint64_t))
    {
        cerr << "[!] Error de lectura.\n";
        _close(fd);
        return 1;
    }

    if (Fatiga_Leida != Fatiga_Esperada)
    {
        cerr << "[!] No es un contenedor valido.\n";
        _close(fd);
        return 1;
    }

    if (Valor_Defensa < 1ULL || Valor_Defensa > 100000ULL)
    {
        cerr << "[!] No es un contenedor valido.\n";
        _close(fd);
        return 1;
    }

    if (faroLeido == 0ULL || faroLeido == ~0ULL)
    {
        cerr << "[!] No es un contenedor valido.\n";
        _close(fd);
        return 1;
    }

    _close(fd);
    cout << "[*] OK: archivo .Brana legible (verificacion superficial completa).\n";
    return 0;
}
int main(int argc, char* argv[])
{
    BranaDatos *Brana_OK = (BranaDatos *)_mm_malloc(sizeof(BranaDatos), 64);
    if (Brana_OK == NULL)
        return -1;

    Inicializar_TABLA_VISCOSA();

    Nombre_Salida.clear();
    Usuario.clear();
    Clave.clear();

    bool modo_cli = (argc > 1);
    bool modo_verify = false;
    char respuesta = 'S';

    if (modo_cli)
    {
        for (int i = 1; i < argc; ++i)
        {
            string a = argv[i];

            auto need = [&](const char *flag) -> string {
                if (i + 1 >= argc)
                {
                    cerr << "Falta valor para " << flag << "\n";
                    Mostrar_Ayuda_Desencriptador();
                    exit(1);
                }
                return string(argv[++i]);
            };

            if (a == "-h" || a == "--help" || a == "-ayuda" || a == "--ayuda")
            {
                Mostrar_Ayuda_Desencriptador();
                return 0;
            }
            else if (a == "-S" || a == "--stream") { flag_stream = true; }
            else if (a == "-DB" || a == "--field" || a == "--db")
            {
                flag_db = true;
            }
            else if (a == "-t")
            {
                Texto_Campo = need("-t");
            }
            else if (a == "-v")
            {
                modo_verify = true;
            }
            else if (a == "-i") Nombre_Salida = need("-i");
            else if (a == "-u") Usuario = need("-u");
            else if (a == "-p") Clave = need("-p");
            else
            {
                cerr << "Argumento desconocido: " << a << "\n";
                Mostrar_Ayuda_Desencriptador();
                exit(1);
            }
        }


        if (modo_verify)
        {
            if (Nombre_Salida.empty())
            {
                cerr << "[!] Indique el archivo con -i.\n";
                Mostrar_Ayuda_Desencriptador();
                _mm_free(Brana_OK);
                return 1;
            }
            int rc = Verificar_Superficial(Nombre_Salida);
            _mm_free(Brana_OK);
            return rc;
        }


        if (flag_db)
        {
            if (Usuario.empty() || Clave.empty() || Texto_Campo.empty())
            {
                cerr << "[!] Modo -DB requiere -u, -p y -t (hex del campo).\n";
                Mostrar_Ayuda_Desencriptador();
                return 1;
            }
            auto hexval = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            string hex = Texto_Campo;

            string hex2;
            for (char c : hex)
                if (c != ' ' && c != '\n' && c != '\r') hex2.push_back(c);
            if (hex2.size() % 2)
            {
                cerr << "[!] Hex invalido.\n";
                return 1;
            }
            std::vector<uint8_t> env(hex2.size() / 2);
            for (size_t i = 0; i < env.size(); i++)
            {
                int a = hexval(hex2[i * 2]), b = hexval(hex2[i * 2 + 1]);
                if (a < 0 || b < 0)
                {
                    cerr << "[!] Hex invalido.\n";
                    return 1;
                }
                env[i] = (uint8_t)((a << 4) | b);
            }
            if (env.size() < 7 + 16 + 1 + 16 + 4 + 2 + 4 ||
                memcmp(env.data(), "BRANAF1", 7) != 0)
            {
                cerr << "[!] Sobre de campo invalido.\n";
                return 1;
            }
            size_t o = 7;
            uint8_t salt[16], nonce[16];
            for (int i = 0; i < 16; i++) salt[i] = env[o++];
            int profile_kdf = env[o++];
            if (profile_kdf < 0 || profile_kdf > 2) profile_kdf = 1;
            for (int i = 0; i < 16; i++) nonce[i] = env[o++];
            uint32_t bits = (uint32_t)env[o] | ((uint32_t)env[o+1] << 8) |
                            ((uint32_t)env[o+2] << 16) | ((uint32_t)env[o+3] << 24);
            o += 4;
            if (env[o] != 0xB1 || env[o+1] != 0x54)
            {
                cerr << "[!] Sobre de campo invalido.\n";
                return 1;
            }
            o += 2;
            if (bits < 256u || (bits % 32u) != 0 || bits > (uint32_t)BRANA_BITS_SOFT_MAX)
                bits = 256;
            uint32_t L = (uint32_t)env[o] | ((uint32_t)env[o+1] << 8) |
                         ((uint32_t)env[o+2] << 16) | ((uint32_t)env[o+3] << 24);
            o += 4;
            if (o + L > env.size())
            {
                cerr << "[!] Sobre truncado.\n";
                return 1;
            }
            size_t kb = (size_t)(bits / 8);
            if (kb < 32) kb = 32;
            if (kb % 32) kb += 32 - (kb % 32);
            std::vector<uint8_t> K(kb, 0);
            if (brana_kdf_ex(Usuario.c_str(), Clave.c_str(), salt, profile_kdf, K.data(), K.size()) != 0)
            {
                cerr << "[ERROR] KDF fallo.\n";
                return 1;
            }
            std::vector<uint8_t> plain(L);
            if (brana_v5_flow_xor_rt(plain.data(), env.data() + o, L,
                                     K.data(), K.size(), nonce, 16, 0, bits) != 0)
            {
                cerr << "[ERROR] Descifrado de campo fallo.\n";
                return 1;
            }
            cout.write(reinterpret_cast<const char*>(plain.data()), (std::streamsize)plain.size());
            cout << "\n";
            _mm_free(Brana_OK);
            return 0;
        }

        if (flag_stream)
        {
            if (Nombre_Salida.empty() || Usuario.empty() || Clave.empty())
            {
                cerr << "[!] -S requiere -i, -u y -p.\n";
                return 1;
            }
            string path_in = Nombre_Salida;
            string path_out;
            {
                string base = path_in;
                size_t slash = base.find_last_of("/\\");
                string leaf = (slash == string::npos) ? base : base.substr(slash + 1);
                if (leaf.size() >= 7 && leaf.substr(leaf.size() - 7) == ".branas")
                    leaf = leaf.substr(0, leaf.size() - 7);
                path_out = "rec_" + leaf;
            }

            int fdIn = -1;
#ifdef _WIN32
            fdIn = _open(path_in.c_str(), _O_RDONLY | _O_BINARY);
#else
            fdIn = open(path_in.c_str(), O_RDONLY);
#endif
            if (fdIn < 0)
            {
                cerr << "[ERROR] No se puede abrir: " << path_in << "\n";
                return 1;
            }
            uint8_t hdr[7 + 16 + 1 + 16 + 4 + 2 + 8];
            if (_read(fdIn, hdr, sizeof(hdr)) != (int)sizeof(hdr) ||
                memcmp(hdr, "BRANAS1", 7) != 0)
            {
                cerr << "[!] No es contenedor stream (-S / BRANAS1).\n";
                _close(fdIn);
                return 1;
            }
            size_t o = 7;
            uint8_t salt[16], nonce[16];
            for (int i = 0; i < 16; i++) salt[i] = hdr[o++];
            int profile_kdf = (int)hdr[o++];
            if (profile_kdf < 0 || profile_kdf > 2) profile_kdf = 1;
            for (int i = 0; i < 16; i++) nonce[i] = hdr[o++];
            uint32_t bits = (uint32_t)hdr[o] | ((uint32_t)hdr[o+1] << 8) |
                            ((uint32_t)hdr[o+2] << 16) | ((uint32_t)hdr[o+3] << 24);
            o += 4;
            if (hdr[o] != 0xB1 || hdr[o + 1] != 0x54)
            {
                cerr << "[!] Contenedor stream invalido.\n";
                _close(fdIn);
                return 1;
            }
            o += 2;
            uint64_t sz = 0;
            for (int i = 0; i < 8; i++)
                sz |= (uint64_t)hdr[o + i] << (8 * i);
            if (bits < 256u || (bits % 32u) != 0 || bits > (uint32_t)BRANA_BITS_SOFT_MAX)
                bits = 256;

            size_t kb = (size_t)(bits / 8);
            if (kb < 32) kb = 32;
            if (kb % 32) kb += 32 - (kb % 32);
            std::vector<uint8_t> K(kb, 0);
            if (brana_kdf_ex(Usuario.c_str(), Clave.c_str(), salt, profile_kdf, K.data(), K.size()) != 0)
            {
                _close(fdIn);
                cerr << "[ERROR] KDF fallo.\n";
                return 1;
            }

            int fdOut = -1;
#ifdef _WIN32
            fdOut = _open(path_out.c_str(), _O_RDWR | _O_CREAT | _O_TRUNC | _O_BINARY, _S_IREAD | _S_IWRITE);
#else
            fdOut = open(path_out.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
#endif
            if (fdOut < 0)
            {
                _close(fdIn);
                cerr << "[ERROR] No se puede crear: " << path_out << "\n";
                return 1;
            }

            const size_t CHUNK = 1024 * 1024;
            std::vector<uint8_t> buf(CHUNK), outb(CHUNK);
            uint64_t done = 0;
            uint64_t blk_bytes = (uint64_t)(bits / 8);
            if (blk_bytes == 0) blk_bytes = 32;
            cout << "[*] Stream puro (-S) descifrando...\n";
            while (done < sz)
            {
                size_t n = (size_t)((sz - done) > CHUNK ? CHUNK : (sz - done));
                int64_t nr = _read(fdIn, buf.data(), (unsigned)n);
                if (nr <= 0) break;
                n = (size_t)nr;
                uint64_t start_blk = done / blk_bytes;
                if (brana_v5_flow_xor_rt(outb.data(), buf.data(), n,
                                         K.data(), K.size(), nonce, 16, start_blk, bits) != 0)
                {
                    cerr << "[ERROR] Stream fallo.\n";
                    _close(fdIn); _close(fdOut);
                    return 1;
                }
                _write(fdOut, outb.data(), (unsigned)n);
                done += n;
                if (sz > 8ULL * 1024 * 1024)
                {
                    double pct = 100.0 * (double)done / (double)sz;
                    cout << "\r[*] Progreso: [" << fixed << setprecision(1) << pct << "%]" << flush;
                }
            }
            if (sz > 8ULL * 1024 * 1024) cout << "\n";
#ifdef _WIN32
            _commit(fdOut);
#else
            fsync(fdOut);
#endif
            _close(fdIn);
            _close(fdOut);
            cout << "[*] Listo. Salida: " << path_out << "\n";
            _mm_free(Brana_OK);
            return 0;
        }


        if (Nombre_Salida.empty() || Usuario.empty() || Clave.empty())
        {
            cerr << "[!] Faltan datos. Use -i, -u y -p (o -h para ayuda).\n";
            Mostrar_Ayuda_Desencriptador();
            exit(1);
        }

    }
    else
    {
        std::cout << "Brana de Diamante  -  Desencriptador\n"
                  << "----------------------------------\n"
                  << "Aviso: se modificara el archivo .brana durante el proceso.\n"
                  << "Conviene tener una copia de respaldo.\n"
                  << "----------------------------------\n"
                  << "Continuar? (S/N): ";

        std::cin >> respuesta;
        std::cin.ignore();
    }

    if (toupper(respuesta) == 'S') {

        if (!modo_cli) {
            cout << "Archivo a desencriptar: ";
            getline(cin, Nombre_Salida);
            cout << "Usuario: ";
            getline(cin, Usuario);
            cout << "Clave: ";
            getline(cin, Clave);
        }

        string Nombre_Archivo = Nombre_Salida;
        uint64_t posBrana = Nombre_Archivo.find(".brana");
        if (posBrana != string::npos)
        {
            Nombre_Archivo = "rec_" + Nombre_Archivo.substr(0, posBrana);
        }
        else
        {
            Nombre_Archivo = "rec_" + Nombre_Archivo;
        }
#ifdef _WIN32
fdIn = _open(Nombre_Salida.c_str(), _O_RDWR | _O_BINARY);
if (fdIn != -1)
    {
    hFileIn = (HANDLE)_get_osfhandle(fdIn);
    Bloqueo_Entrada = LockFileEx(hFileIn, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 0xFFFFFFFF, 0xFFFFFFFF, &ovIn);
    }
#else
fdIn = open(Nombre_Salida.c_str(), O_RDWR);
if (fdIn != -1)
    {
    Bloqueo_Entrada = (flock(fdIn, LOCK_EX | LOCK_NB) == 0);
    }
#endif

if (!Bloqueo_Entrada)
    {
    cout << "[!] El archivo esta en uso. Cierre otros programas e intente de nuevo." << endl;
    if (fdIn != -1)
        _close(fdIn);
    return 1;
    }

#ifdef _WIN32
fdOut = _open(Nombre_Archivo.c_str(), _O_RDWR | _O_CREAT | _O_TRUNC | _O_BINARY, _S_IREAD | _S_IWRITE);
if (fdOut != -1)
    {
    hFileOut = (HANDLE)_get_osfhandle(fdOut);
    Bloqueo_Salida = LockFileEx(hFileOut, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 0xFFFFFFFF, 0xFFFFFFFF, &ovOut);
    }
#else
fdOut = open(Nombre_Archivo.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0666);
if (fdOut != -1)
    {
    Bloqueo_Salida = (flock(fdOut, LOCK_EX | LOCK_NB) == 0);
    }
#endif
if (fdOut == -1)
    {
    cout << "[!] No se pudo crear el archivo de salida." << endl;
    _close(fdIn);
    return 1;

#ifdef _WIN32
        UnlockFileEx(hFileIn, 0, 0xFFFFFFFF, 0xFFFFFFFF, &ovIn);
#else
        flock(fdIn, LOCK_UN);
#endif
    _close(fdIn);
    return 1;
    }
if (Bloqueo_Salida)
    {
    cout << "\n[*] Preparando..." << endl;
    }
else
    {
    cout << "[!] No se puede escribir la salida (archivo en uso)." << endl;
    _close(fdOut);
    return 1;
    }
#ifdef _WIN32
    uint64_t Total_Bytes_Brana = _filelengthi64(fdIn);
#else
    struct stat st;
    fstat(fdIn, &st);
    uint64_t Total_Bytes_Brana = st.st_size;
#endif

uint64_t Clave_ENC = 0, Usuario_ENC = 0, Semilla_Dual_ENC = 0;
uint64_t Clave_Semilla_Principal = 0, Usuario_Semilla_Principal = 0;
std::vector<uint8_t> K_master(32, 0);
uint8_t mac_guardado_ct[BRANA_MAC_LEN] = {0};
uint8_t mac_guardado_plain[BRANA_MAC_LEN] = {0};
bool mac_tag_ok = false;
bool ct_mac_ok = false;
uint8_t stream_nonce[16] = {0};
bool stream_nonce_ok = false;
unsigned file_brana_bits = 256;
uint8_t salt_kdf[BRANA_KDF_SALT_LEN] = {0};
int profile_kdf = BRANA_KDF_PROFILE_NORMAL;
float Frecuencia_Maxima_CPU = Obtener_Frecuencia_Cpu();

if (Frecuencia_Maxima_CPU > 0.0f) {
    Factor_Frecuencia_CPU = static_cast<uint64_t>(Frecuencia_Maxima_CPU * 1000);
} else {
    Factor_Frecuencia_CPU = 1000ULL + (Semilla_Dual_ENC % 2001ULL);
}
Optimizar_Sistema();
uint64_t Bytes_Header = (Total_Bytes_Brana < (ZONA_header * 2ULL)) ? ZONA_header : ZONA_header;

    if (Bytes_Header > Total_Bytes_Brana)
        Bytes_Header = Total_Bytes_Brana;

    std::vector<uint8_t> bufferMaestro(Bytes_Header);

    uint64_t Puntero_Inicio = _lseeki64(fdIn, 0, SEEK_SET);
    int64_t BytesLeidosHeader = _read(fdIn, bufferMaestro.data(), static_cast<unsigned int>(Bytes_Header));
    uint64_t InicioData = _lseeki64(fdIn, 0, SEEK_CUR);
    Restaurar_Torsion_Principal(bufferMaestro, Total_Bytes_Brana);
    _lseeki64(fdIn, 0, SEEK_SET);
    _write(fdIn, bufferMaestro.data(), static_cast<unsigned int>(Bytes_Header));
    _commit(fdIn);


    if (Total_Bytes_Brana > (Bytes_Header + 128ULL))
    {
        uint64_t Espacio_Restante = Total_Bytes_Brana - Bytes_Header;
        uint64_t BytesALeerFaro = (Espacio_Restante < ZONA_faro) ? ZONA_header : ZONA_faro;

        if (BytesALeerFaro > Espacio_Restante)
            BytesALeerFaro = Espacio_Restante;

        _lseeki64(fdIn, -static_cast<int64_t>(BytesALeerFaro), SEEK_END);
        std::vector<uint8_t> bufferFaro(BytesALeerFaro);
        _read(fdIn, bufferFaro.data(), static_cast<unsigned int>(BytesALeerFaro));
        Restaurar_Torsion_Principal(bufferFaro, Total_Bytes_Brana);
        _lseeki64(fdIn, -static_cast<int64_t>(BytesALeerFaro), SEEK_END);
        _write(fdIn, bufferFaro.data(), static_cast<unsigned int>(BytesALeerFaro));
        _commit(fdIn);


        if (Total_Bytes_Brana > UMBRAL_CUANTICO)
        {
            uint64_t EspacioLibreCentro = Total_Bytes_Brana - Bytes_Header - BytesALeerFaro;
            if (EspacioLibreCentro > ZONA_media)
            {
                uint64_t SemillaPos = (Total_Bytes_Brana ^ LAMBDA);
                uint64_t Porcentaje = 15ULL + (SemillaPos % 60ULL);
                uint64_t Ubicacion_Cuantica_Real = (Total_Bytes_Brana * Porcentaje) / 100ULL;
                if (Ubicacion_Cuantica_Real < Bytes_Header)
                    Ubicacion_Cuantica_Real = Bytes_Header + 1024ULL;
                if (Ubicacion_Cuantica_Real + ZONA_media > (Total_Bytes_Brana - BytesALeerFaro))
                    Ubicacion_Cuantica_Real = (Total_Bytes_Brana - BytesALeerFaro) - ZONA_media - 1024ULL;
                _lseeki64(fdIn, Ubicacion_Cuantica_Real, SEEK_SET);
                std::vector<uint8_t> bufferMedia(ZONA_media);
                _read(fdIn, bufferMedia.data(), static_cast<unsigned int>(ZONA_media));
                Restaurar_Torsion_Principal(bufferMedia, Total_Bytes_Brana);
                _lseeki64(fdIn, Ubicacion_Cuantica_Real, SEEK_SET);
                _write(fdIn, bufferMedia.data(), static_cast<unsigned int>(ZONA_media));
                _commit(fdIn);
            }
        }

    }
    _lseeki64(fdIn, Puntero_Inicio, SEEK_SET);
    if (fdIn == -1)
    {
        std::cerr << "[!] Se necesita permiso de escritura sobre el archivo .brana." << std::endl;
        return 1;
    }

    if (!Verificar_Integridad_Brana(fdIn))
        exit(1);


    int64_t BytesLeidosSize = _read(fdIn, &hSize, sizeof(int));
    std::vector<uint8_t> hBuf(hSize);
    int64_t BytesLeidosHBuf = _read(fdIn, hBuf.data(), static_cast<unsigned int>(hSize));
    int64_t BytesLeidosControl_Semilla_Leida = _read(fdIn, &Control_Semilla_Leida, sizeof(uint64_t));
    int64_t BytesLeidosCRC_Control = _read(fdIn, &CRC_Control, sizeof(uint64_t));


    InicioData = static_cast<uint64_t>(sizeof(int)) + static_cast<uint64_t>(hSize)
               + sizeof(uint64_t) + sizeof(uint64_t);

    uint64_t offsetTrasMetadatos = _lseeki64(fdIn, 0, SEEK_CUR);
    string CRC_ENC = to_string(CRC_Control);
    string CRC_INV_ENC = CRC_ENC;
    reverse(CRC_INV_ENC.begin(), CRC_INV_ENC.end());

    {
        uint64_t len_b = Calcular_Longitud_Relleno(Control_Semilla_Leida, CRC_Control);
        if (len_b >= 17ULL)
        {
            int64_t posb = _lseeki64(fdIn, -static_cast<int64_t>(len_b), SEEK_END);
            if (posb >= 0)
            {
                uint8_t cabeza[47] = {0};
                int nr_cab = _read(fdIn, cabeza, 47);
                if (nr_cab >= 17)
                {
                    for (int si = 0; si < 16; ++si)
                        salt_kdf[si] = cabeza[si];
                    profile_kdf = static_cast<int>(cabeza[16]);
                    if (profile_kdf < 0 || profile_kdf > 2)
                        profile_kdf = BRANA_KDF_PROFILE_NORMAL;
                    if (nr_cab >= 41)
                    {
                        for (int ni = 0; ni < 16; ++ni)
                            stream_nonce[ni] = cabeza[25 + ni];
                        stream_nonce_ok = true;
                        if (nr_cab >= 47
                            && cabeza[45] == (uint8_t)BRANA_BASURA_MAGIC_0
                            && cabeza[46] == (uint8_t)BRANA_BASURA_MAGIC_1)
                        {
                            uint32_t bits_file =
                                (uint32_t)cabeza[41]
                                | ((uint32_t)cabeza[42] << 8)
                                | ((uint32_t)cabeza[43] << 16)
                                | ((uint32_t)cabeza[44] << 24);
                            if (bits_file >= 256u && (bits_file % 32u) == 0u
                                && bits_file <= (uint32_t)BRANA_BITS_SOFT_MAX)
                                file_brana_bits = bits_file;
                        }

                    }
                }
            }
        }
        cout << "[*] Derivando clave...\n";
        {
            size_t kb = (size_t)(file_brana_bits / 8u);
            if (kb < 32) kb = 32;
            if (kb % 32u) kb += 32u - (kb % 32u);
            K_master.assign(kb, 0);
        }
        if (brana_kdf_ex(Usuario.c_str(), Clave.c_str(), salt_kdf, profile_kdf, K_master.data(), K_master.size()) != 0)
        {
            cerr << "[ERROR] KDF fallo.\n";
            return 1;
        }
        Brana_Expandir_Desde_KMaster(K_master.data(), CRC_Control, Clave_ENC, Usuario_ENC,
            Clave_Semilla_Principal, Usuario_Semilla_Principal);
        Semilla_Dual_ENC = Clave_ENC ^ Usuario_ENC;
    }
    uint64_t Semilla = Generador_String(Valor_Header) ^ Clave_Semilla_Principal;
    uint64_t Faro_Esperado = Generador_String(to_string(Semilla_Dual_ENC ^ Clave_Semilla_Principal));
    uint64_t Basura_Relleno_Final = Calcular_Longitud_Relleno(Control_Semilla_Leida, CRC_Control);
    _lseeki64(fdIn, 0, SEEK_END);

    for (uint64_t i = 0ULL; i < Valor_Header.length() && i < 8ULL; i++)
        Constante_Dispersion |= (static_cast<uint64_t>(static_cast<uint8_t>(Valor_Header[i])) << (i * 8ULL));

        const uint64_t Semilla_Dispersion = ((Constante_Dispersion + REFERENCIA) ^ (CRC_Control * LAMBDA + 1ULL)) * (LAMBDA % 10007ULL) + 1ULL;
        uint64_t Control_Semilla = Semilla_Dispersion ^ (static_cast<uint64_t>(CRC_Control) << 32ULL | CRC_Control);
        bool Semilla_Control_OK = (Control_Semilla == Control_Semilla_Leida);

    string Firma_Control = "";
    for (int64_t i = 0LL; i < 8LL; i++)
    {
        uint8_t Control = static_cast<uint8_t>((Semilla_Dispersion >> (i * 8LL)) & 0xFFLL);
        if (Control == 0)
            Control = (uint8_t)(i + 1);
        Firma_Control += Control;
    }
    uint64_t Semilla_HBuf = LAMBDA ^ Clave_Semilla_Principal;
    for (uint64_t i = 0ULL; i < hBuf.size(); i++)
    {
        hBuf[i] = Desencriptacion_Secundaria_Individual(hBuf[i], REFERENCIA, i, false, Clave_Semilla_Principal, 0);
        hBuf[i] ^= static_cast<uint8_t>((Semilla_HBuf >> (i % 8ULL)) % 256ULL);
    }

    for (int64_t i = 0LL; i < 8LL; i++)
    {
        if (hBuf[i] != (uint8_t)Firma_Control[i])
        {
            Sincronizado = false;
            break;
        }
    }

    uint64_t TamTotal = _lseeki64(fdIn, 0, SEEK_END);
    uint64_t OffsetControl = static_cast<uint64_t>(Basura_Relleno_Final) + 24ULL + ZONA_REGISTRO + BRANA_MAC_ZONE;
    const uint64_t PosicionFaro = TamTotal - OffsetControl;

    if (TamTotal > OffsetControl)
    {
     _lseeki64(fdIn, PosicionFaro, SEEK_SET);
    if (!Verificar_Integridad_Brana(fdIn))
        exit(1);
        _read(fdIn, &faroLeido, sizeof(uint64_t));
        _read(fdIn, &Valor_Recuperado_Defensa, sizeof(uint64_t));
        _read(fdIn, &Fatiga_Leida, sizeof(uint64_t));

        if (faroLeido == Faro_Esperado)
        {
            ana = true;
        }


        {
            int64_t pos_mac_ct = static_cast<int64_t>(TamTotal)
                - static_cast<int64_t>(Basura_Relleno_Final)
                - static_cast<int64_t>(BRANA_MAC_ZONE);
            if (pos_mac_ct >= 0
                && _lseeki64(fdIn, pos_mac_ct, SEEK_SET) >= 0
                && _read(fdIn, mac_guardado_ct, BRANA_MAC_LEN) == (int)BRANA_MAC_LEN
                && _read(fdIn, mac_guardado_plain, BRANA_MAC_LEN) == (int)BRANA_MAC_LEN)
                mac_tag_ok = true;
            else
                mac_tag_ok = false;
        }
    }
    uint64_t Longitud_Brana_Orig = PosicionFaro - InicioData;


    const bool Auth_OK = (Sincronizado && Semilla_Control_OK && ana);


    if (Auth_OK && hBuf.size() >= 24)
    {

        memcpy(&Vuelta_R, &hBuf[8], sizeof(uint64_t));
        memcpy(&Vuelta_L, &hBuf[16], sizeof(uint64_t));
    }
    else
    {

        uint64_t mezclado = Clave_Semilla_Principal ^ Control_Semilla_Leida ^ CRC_Control ^ LAMBDA;
        mezclado ^= mezclado >> 30;
        mezclado *= 0xBF58476D1CE4E5B9ULL;
        mezclado ^= mezclado >> 27;

        Vuelta_L = 4ULL + (mezclado % 16ULL);
        mezclado ^= 0x9E3779B97F4A7C15ULL;
        mezclado ^= mezclado >> 33;
        Vuelta_R = 4ULL + (mezclado % 16ULL);
        if (Vuelta_L < 1ULL) Vuelta_L = 1ULL;
        if (Vuelta_R < 1ULL) Vuelta_R = 1ULL;
    }


    if (Vuelta_L > VUELTA_MAX_L) Vuelta_L = VUELTA_MAX_L;
    if (Vuelta_R > VUELTA_MAX_R) Vuelta_R = VUELTA_MAX_R;


    {
        uint64_t len_basura = Calcular_Longitud_Relleno(Control_Semilla_Leida, CRC_Control);

        uint8_t salt_kdf[BRANA_KDF_SALT_LEN] = {0};
        int profile_kdf = BRANA_KDF_PROFILE_NORMAL;


        uint64_t mask_senuelo =
            Generador_String(Valor_Header) ^ CRC_Control ^ Control_Semilla_Leida ^ LAMBDA;

        uint64_t token_leido = 0ULL;
        if (len_basura >= 25ULL)
        {
            int64_t pos = _lseeki64(fdIn, -static_cast<int64_t>(len_basura), SEEK_END);
            if (pos >= 0)
            {
                uint8_t cabeza[25] = {0};
                if (_read(fdIn, cabeza, 25) == 25)
                {
                    for (int si = 0; si < 16; ++si)
                        salt_kdf[si] = cabeza[si];
                    profile_kdf = static_cast<int>(cabeza[16]);
                    if (profile_kdf < 0 || profile_kdf > 2)
                        profile_kdf = BRANA_KDF_PROFILE_NORMAL;
                    for (int b = 0; b < 8; ++b)
                        token_leido |= (static_cast<uint64_t>(cabeza[17 + b]) << (8 * b));
                }
            }

        }
        else if (len_basura >= 8ULL)
        {

            int64_t pos = _lseeki64(fdIn, -static_cast<int64_t>(len_basura), SEEK_END);
            if (pos >= 0)
            {
                uint8_t ocho[8] = {0};
                if (_read(fdIn, ocho, 8) == 8)
                {
                    for (int b = 0; b < 8; ++b)
                        token_leido |= (static_cast<uint64_t>(ocho[b]) << (8 * b));
                }
            }
        }

        if (Clave.size() == 8)
        {
            uint64_t token_tipeado = Generador_String(Clave) ^ mask_senuelo;
            es_senuelo = (token_tipeado == token_leido);
        }

        if (es_senuelo)
        {

        }
    }


    _lseeki64(fdIn, 0, SEEK_END);
    uint64_t Fatiga_Final = (Generador_String(Valor_Header) ^ CRC_Control) + (Control_Semilla_Leida ^ LAMBDA);
    uint64_t Clave_Semilla_Alterna = _rotr64(Clave_Semilla_Principal ^ LAMBDA, Semilla % 32ULL);
    uint64_t Control_Semilla_Alterno = _rotr64(Control_Semilla ^ Vuelta_R, Semilla % 13ULL);
    uint64_t Clave_ENC2 = _rotl64(Clave_ENC ^ Clave_Semilla_Principal, Semilla % 64ULL);
    uint64_t Semilla_Ofuscacion = Generador_String(Valor_Header) ^ ((Control_Semilla_Leida ^ CRC_Control) ^ LAMBDA);
    uint64_t Fin_Data_Util = (Total_Bytes_Brana > OffsetControl) ? (Total_Bytes_Brana - OffsetControl) : InicioData;
    uint64_t espacioDataPura = (Fin_Data_Util > InicioData) ? (Fin_Data_Util - InicioData) : 0ULL;
    uint64_t BytesARestaurar = (espacioDataPura < Zona_Defensa_Activa) ? espacioDataPura : Zona_Defensa_Activa;

    if (BytesARestaurar > 0ULL)
    {
        Restaurar_Defensa_Activa(fdIn, InicioData, Fatiga_Final, Valor_Recuperado_Defensa, Semilla_Ofuscacion, BytesARestaurar);
    }


    if (mac_tag_ok && Auth_OK)
    {
        uint64_t ct_size = (PosicionFaro > InicioData) ? (PosicionFaro - InicioData) : 0ULL;
        uint64_t ct_fp = 0ULL;
        if (ct_size > 0ULL)
        {
            const size_t CH = 1024ULL * 1024ULL;
            std::vector<uint8_t> chunk(CH);
            uint64_t left = ct_size;
            _lseeki64(fdIn, static_cast<int64_t>(InicioData), SEEK_SET);
            while (left > 0ULL)
            {
                size_t n = static_cast<size_t>(left > CH ? CH : left);
                int64_t nr = _read(fdIn, chunk.data(), static_cast<unsigned int>(n));
                if (nr <= 0)
                    break;
                ct_fp = brana_mac_update_fp(ct_fp, chunk.data(), static_cast<size_t>(nr));
                left -= static_cast<uint64_t>(nr);
            }
        }
        uint64_t Fatiga_Para_Mac =
            (Generador_String(Valor_Header) ^ CRC_Control)
            + (Control_Semilla_Leida ^ LAMBDA);
        uint8_t mac_msg[BRANA_MAC_MSG_LEN];
        uint8_t mac_calc[BRANA_MAC_LEN];
        brana_mac_build_msg(mac_msg, salt_kdf, profile_kdf,
            CRC_Control, Control_Semilla_Leida, Faro_Esperado,
            Fatiga_Para_Mac, BRANA_MAC_DOM_CT, ct_size, ct_fp);
        brana_mac(K_master.data(), mac_msg, BRANA_MAC_MSG_LEN, mac_calc);
        ct_mac_ok = brana_mac_verify(mac_guardado_ct, mac_calc);
        if (!ct_mac_ok)
        {

            Sincronizado = false;
        }
    }

    uint64_t Header_y_Masa = Longitud_Brana_Orig + InicioData;
    bool BranaEstable = Verificar_Inercia_Brana(fdIn, Fatiga_Final, Semilla_Ofuscacion, Basura_Relleno_Final, Header_y_Masa, ZONA_REGISTRO, Clave_ENC, Usuario_Semilla_Principal, Clave_Semilla_Principal);
    if (es_senuelo || !Auth_OK || !ct_mac_ok)
    {

        BranaEstable = false;
    }
    uint64_t Frecuencia_Orig = Clave_Semilla_Principal % REFERENCIA;
    _lseeki64(fdIn, InicioData, SEEK_SET);
    _lseeki64(fdOut, 0, SEEK_SET);
    int64_t NumHilos = Optimizar_Hilos_CPU(Tam_bloque_Hilo);
    size_t BytesALeer = Tam_bloque_Hilo * NumHilos;
        g_Pool.inicializar(static_cast<size_t>(NumHilos));
vector<uint8_t> buffer(BytesALeer);
    std::fill(buffer.begin(), buffer.end(), 0);
    const uint8_t Salto_Cuantico = static_cast<uint8_t>(Semilla % 256ULL);
    auto Tiempo_Inicio = std::chrono::high_resolution_clock::now();
 uint64_t UMBRAL_EVOLUCION = UMBRAL_EVOLUCION_32GB;
    while (BytesProcesadosTotales < Longitud_Brana_Orig)
    {
        buffer.assign(BytesALeer, 0);
        if (!Verificar_Integridad_Brana(fdIn))
            exit(1);

        int64_t LecturaDirecta = _read(fdIn, buffer.data(), static_cast<unsigned int>(BytesALeer));
        if (LecturaDirecta <= 0)
            break;

        size_t BytesLeidos = 0;
        const int64_t TAMANO_BASURA_TOTAL = static_cast<int64_t>(Basura_Relleno_Final + 24ULL + ZONA_REGISTRO + BRANA_MAC_ZONE);
        if (LecturaDirecta >= static_cast<int64_t>(BytesALeer)) {
            BytesLeidos = static_cast<size_t>(LecturaDirecta);
        }
        else {
            int64_t DatosReales = LecturaDirecta - TAMANO_BASURA_TOTAL;

            if (DatosReales > 0) {
                BytesLeidos = static_cast<size_t>(DatosReales);
            } else {
                BytesLeidos = 0;
            }
        }
        if (BytesLeidos == 0)
            break;


        if (BranaEstable)
        {
            Inicializar_Rigidez_Adelica(Brana_OK, buffer.data(), Longitud_Brana_Orig);
            for (int64_t i = static_cast<int64_t>(BytesLeidos) - 1; i > 0; i--)
            {
                buffer[i] ^= (buffer[i - 1LL] >> 4LL);
            }

            for (size_t i = 0; i < BytesLeidos; i++)
            {
                buffer[i] = Desencriptacion_Secundaria_Individual(buffer[i], REFERENCIA, i, false, Clave_Semilla_Alterna, Salto_Cuantico);
            }

            for (int64_t i = static_cast<int64_t>(BytesLeidos) - 1; i > 0; i--)
            {
                buffer[i] ^= (buffer[i - 1LL] >> 4LL);
            }

            for (uint64_t i = 0ULL; i < BytesLeidos; i++)
            {
                uint64_t Posicion = Semilla ^ i;

                buffer[i] ^= 0x13ULL;

                uint8_t Desplazamiento = static_cast<uint8_t>(Posicion % 5ULL + 1ULL);
                buffer[i] = (buffer[i] >> Desplazamiento) | (buffer[i] << (8 - Desplazamiento));
            }

            if (BytesLeidos > 0)
            {
                uint64_t Salto = (Semilla % 7ULL) + 1ULL;

                for (int64_t i = static_cast<int64_t>(BytesLeidos) - 1; i >= 0; i--)
                {
                    uint64_t Posicion = (static_cast<uint64_t>(i) * Salto) % BytesLeidos;
                    if (static_cast<uint64_t>(i) != Posicion)
                    {
                        std::swap(buffer[i], buffer[Posicion]);
                    }
                }
            }

            if (BytesLeidos > 0)
            {
                vector<uint64_t> Vector_Frecuencia;
                Vector_Frecuencia.reserve(Vuelta_L);
                uint64_t Frecuencia_Temporal = Frecuencia_Orig;

                for (uint64_t v = 0ULL; v < Vuelta_L; v++)
                {
                    Vector_Frecuencia.push_back(Frecuencia_Temporal);
                    if (Frecuencia_Temporal % 2ULL == 0ULL)
                    {
                        Frecuencia_Temporal = (Frecuencia_Temporal / 2ULL) ^ (Frecuencia_Temporal + LAMBDA);
                    }
                    else
                    {
                        Frecuencia_Temporal = (Frecuencia_Temporal * 3ULL + LAMBDA) ^ (Frecuencia_Temporal >> 1ULL);
                    }
                    Frecuencia_Temporal %= REFERENCIA;
                }

                for (int64_t v = Vuelta_L - 1LL; v >= 0LL; v--)
                {
                    if (v % 20LL == 0LL)
                    {
                        if (fdIn == -1)
                        {
                            std::cerr << "\n[!] Error de lectura del archivo." << std::endl;
                            exit(1);
                        }
                    }
                    uint64_t Frecuencia_Final = Vector_Frecuencia[v];
                    for (int64_t i = 0LL; i < NumHilos; i++)
                    {
                        size_t Inicio = static_cast<size_t>(i) * Tam_bloque_Hilo;
                        if (Inicio >= BytesLeidos)
                            break;
                        size_t Final = (std::min)(Inicio + Tam_bloque_Hilo, BytesLeidos);

                        g_Pool.encolar([&, Inicio, Final, Frecuencia_Final]() {
                            Desencriptacion_Principal(
                                buffer, Inicio, Final, Frecuencia_Final,
                                Clave_Semilla_Alterna, false, Control_Semilla_Alterno,
                                Clave_ENC2, REFERENCIA, Semilla, true);
                        });
                    }
                    g_Pool.esperar_tareas();

                    double Avance_Vuelta = ((double)(Vuelta_R + v) / (Vuelta_R + Vuelta_L)) * (double)BytesLeidos;
                    double Progreso_Real = ((double)BytesProcesadosTotales + Avance_Vuelta) / (double)Longitud_Brana_Orig * 100.0;
                    cout << "\r[*] Progreso: [" << fixed << setprecision(1)
                         << (Progreso_Real > 99.9 ? 99.9 : Progreso_Real) << "%]" << flush;
                }
            }

            for (int64_t i = static_cast<int64_t>(BytesLeidos) - 1; i > 0; i--)
            {
                buffer[i] ^= (buffer[i - 1LL] >> 4LL);
            }

            for (size_t i = 0; i < BytesLeidos; i++)
            {
                buffer[i] = Desencriptacion_Secundaria_Individual(buffer[i], REFERENCIA, i, false, Clave_Semilla_Principal, Salto_Cuantico);
            }

            for (int64_t i = static_cast<int64_t>(BytesLeidos) - 1; i > 0; i--)
            {
                buffer[i] ^= (buffer[i - 1LL] >> 4LL);
            }

            for (uint64_t i = 0ULL; i < BytesLeidos; i++)
            {
                uint64_t Posicion_Global = BytesProcesadosTotales + i;
                uint64_t Posicion = Semilla ^ i;
                buffer[i] ^= 0x62ULL;
                buffer[i] = _rotr8(buffer[i], (Posicion % 7ULL) + 1ULL);
                buffer[i] ^= static_cast<uint8_t>((Posicion ^ (Posicion >> 8ULL)) & 0xFFULL);
                buffer[i] ^= static_cast<uint8_t>((Posicion_Global ^ (Posicion_Global >> 8ULL)) & 0xFFULL);
            }

            if (BytesLeidos > 0)
            {
                uint64_t Salto = (Semilla % 7ULL) + 1ULL;
                for (int64_t i = static_cast<int64_t>(BytesLeidos) - 1; i >= 0; i--)
                {
                    uint64_t Posicion = (static_cast<uint64_t>(i) * Salto) % BytesLeidos;
                    if (static_cast<uint64_t>(i) != Posicion)
                    {
                        std::swap(buffer[i], buffer[Posicion]);
                    }
                }
            }

            if (BytesLeidos > 0)
            {
                vector<uint64_t> Vector_Frecuencia;
                Vector_Frecuencia.reserve(Vuelta_R);
                uint64_t Frecuencia_Temporal = Frecuencia_Orig;
                for (uint64_t v = 0ULL; v < Vuelta_R; v++)
                {
                    Vector_Frecuencia.push_back(Frecuencia_Temporal);
                    if (Frecuencia_Temporal % 2ULL == 0ULL)
                    {
                        Frecuencia_Temporal = (Frecuencia_Temporal / 2ULL) ^ (Frecuencia_Temporal + LAMBDA);
                    }
                    else
                    {
                        Frecuencia_Temporal = (Frecuencia_Temporal * 3ULL + LAMBDA) ^ (Frecuencia_Temporal >> 1ULL);
                    }
                    Frecuencia_Temporal %= REFERENCIA;
                }

                for (int64_t v = Vuelta_R - 1LL; v >= 0LL; v--)
                {
                    if (v % 20LL == 0LL && fdIn == -1)
                    {
                        std::cerr << "\n[!] Error de lectura del archivo." << std::endl;
                        exit(1);
                    }
                    uint64_t Frecuencia_Final = Vector_Frecuencia[v];
                    for (int64_t i = 0LL; i < NumHilos; i++)
                    {
                        size_t Inicio = static_cast<size_t>(i) * Tam_bloque_Hilo;
                        if (Inicio >= BytesLeidos)
                            break;
                        size_t Final = (std::min)(Inicio + Tam_bloque_Hilo, BytesLeidos);

                        g_Pool.encolar([&, Inicio, Final, Frecuencia_Final]() {
                            Desencriptacion_Principal(
                                buffer, Inicio, Final, Frecuencia_Final,
                                Clave_Semilla_Principal, false, Control_Semilla,
                                Clave_ENC, REFERENCIA, Semilla, true);
                        });
                    }
                    g_Pool.esperar_tareas();

                    double Avance_Vuelta = ((double)v / (double)(Vuelta_R + Vuelta_L)) * (double)BytesLeidos;
                    double Progreso_Real = ((double)BytesProcesadosTotales + Avance_Vuelta) / (double)Longitud_Brana_Orig * 100.0;
                    cout << "\r[*] Progreso: [" << fixed << setprecision(1)
                         << (Progreso_Real > 99.9 ? 99.9 : Progreso_Real) << "%]" << flush;
                }
            }
            Procesar_Ovillo(Brana_OK, Semilla_Dual_ENC);
            Estabilizar_Brana(Brana_OK, buffer.data(), BytesLeidos, &Torsor_Global);
            memcpy(Brana_OK->Espejo_Adelico, Brana_OK->Fase_Vorticidad, sizeof(Brana_OK->Fase_Vorticidad));
        }
        else
        {
            Inicializar_Rigidez_Adelica(Brana_OK, buffer.data(), Longitud_Brana_Orig);
            for (int64_t i = BytesLeidos - 1; i > 0; i--)
            {
                buffer[i] ^= (buffer[i - 1] >> 4);
            }
            for (size_t i = 0; i < BytesLeidos; i++)
            {
                uint8_t sal = static_cast<uint8_t>(Semilla_Dispersion % 256);
                buffer[i] = Desencriptacion_Secundaria_Individual(buffer[i], REFERENCIA * 2, i, false, Frecuencia_Orig, sal);
            }

            for (int64_t i = (int64_t)BytesLeidos - 1; i > 0; i--)
            {
                buffer[i] ^= (buffer[i - 1] << 4);
            }

            for (uint64_t i = 0; i < BytesLeidos; i++)
            {
                uint64_t Posicion_Global = BytesProcesadosTotales + i;

                uint64_t p = Semilla ^ Semilla_Dual_ENC ^ i;
                buffer[i] ^= 0x32;
                buffer[i] ^= 0x17;
                buffer[i] = (buffer[i] >> (p % 3 + 1)) | (buffer[i] << (6 - (p % 5 + 1)));
            }

            if (BytesLeidos > 0)
            {
                uint64_t Salto = (Semilla_Ofuscacion % 7) + 3;
                for (int64_t i = (static_cast<int64_t>(BytesLeidos)) - 1; i >= 0; i--)
                {
                    uint64_t pos2 = (i * Salto) % BytesLeidos;

                    std::swap(buffer[i], buffer[pos2]);
                }
            }

            if (BytesLeidos > 0)
            {
                vector<uint64_t> Vector_Frecuencia;
                uint64_t Frecuencia_Temporal = (Frecuencia_Orig * LAMBDA) / 2;
                for (uint64_t v = 0; v < Vuelta_L; v++)
                {
                    Vector_Frecuencia.push_back(Frecuencia_Temporal);
                    if (Frecuencia_Temporal % 2 == 0)
                        Frecuencia_Temporal = (Frecuencia_Temporal * 2) ^ (Frecuencia_Temporal + LAMBDA);
                    else
                        Frecuencia_Temporal = (Frecuencia_Temporal * 6 + REFERENCIA) ^ (Frecuencia_Temporal >> 3);
                    Frecuencia_Temporal %= Valor_Header.length() * 256;
                }

                for (int64_t v = (int)Vuelta_L - 1; v >= 0; v--)
                {
                    if (v % 20 == 0)
                    {
                        if (fdIn == -1)
                        {
                            std::cerr << "\n[!] Error de lectura del archivo." << std::endl;
                            exit(1);
                        }
                    }
                                        uint64_t Frecuencia_Final = Vector_Frecuencia[v];

                    for (int64_t t = 0; t < NumHilos; t++)
                    {
                        size_t Inicio = static_cast<size_t>(t) * Tam_bloque_Hilo;
                        size_t Final = (std::min)(Inicio + Tam_bloque_Hilo, BytesLeidos);
                        if (Inicio >= BytesLeidos)
                            break;

                        g_Pool.encolar([&, Inicio, Final, Frecuencia_Final]() {
                            Desencriptacion_Principal(
                                buffer, Inicio, Final, Frecuencia_Final,
                                Control_Semilla_Leida, false,
                                Clave_Semilla_Alterna * 2, Usuario_ENC,
                                REFERENCIA / 2,
                                Semilla ^ static_cast<uint64_t>(3.14159),
                                false);
                        });
                    }
                    g_Pool.esperar_tareas();

                    double Avance_Vuelta = ((double)(Vuelta_R + v) / (Vuelta_R + Vuelta_L)) * (double)BytesLeidos;
                    double Progreso_Real = ((double)BytesProcesadosTotales + Avance_Vuelta) / (double)Longitud_Brana_Orig * 100.0;
                    cout << "\r[*] Progreso: [" << fixed << setprecision(1)
                         << (Progreso_Real > 99.9 ? 99.9 : Progreso_Real) << "%] | Activo    " << flush;
                }
            }

            for (int64_t i = BytesLeidos - 1; i > 0; i--)
            {
                buffer[i] ^= (buffer[i - 1] >> 3);
            }
            for (size_t i = 0; i < BytesLeidos; i++)
            {
                uint8_t sal = static_cast<uint8_t>(Clave_Semilla_Principal % 256);
                buffer[i] = Desencriptacion_Secundaria_Individual(buffer[i], REFERENCIA / 4, i, false, Semilla / LAMBDA, sal);
            }

            for (int64_t i = (int64_t)BytesLeidos - 1; i > 0; i--)
            {
                buffer[i] ^= (buffer[i - 1] >> 4);
            }

            for (uint64_t i = 0; i < BytesLeidos; i++)
            {
                uint64_t Posicion_Global = BytesProcesadosTotales + i;

                uint64_t p = Clave_Semilla_Alterna ^ i;
                buffer[i] ^= 0x16;
                buffer[i] = _rotr8(buffer[i], (p % 11) + 3);
                buffer[i] ^= static_cast<uint8_t>((p ^ (p >> 3)) & 0xFF);
                buffer[i] ^= static_cast<uint8_t>((Posicion_Global ^ (Posicion_Global >> 6)) & 0xFF);
            }

            if (BytesLeidos > 0)
            {
                uint64_t Salto = ((Semilla ^ Semilla_Dispersion) % 3) + 1;
                for (int64_t i = (static_cast<int64_t>(BytesLeidos)) - 1; i >= 0; i--)
                {
                    uint64_t pos2 = (i * Salto) % BytesLeidos;
                    std::swap(buffer[i], buffer[pos2]);
                }
            }

            if (BytesLeidos > 0)
            {
                vector<uint64_t> Vector_Frecuencia;
                uint64_t Frecuencia_Temporal = Frecuencia_Orig / 2;
                for (uint64_t v = 0; v < Vuelta_R; v++)
                {
                    Vector_Frecuencia.push_back(Frecuencia_Temporal);
                    if (Frecuencia_Temporal % 2 == 0)
                        Frecuencia_Temporal = (Frecuencia_Temporal / 4) ^ (Frecuencia_Temporal + (LAMBDA ^ REFERENCIA));
                    else
                        Frecuencia_Temporal = (Frecuencia_Temporal * 6 + LAMBDA) ^ (Frecuencia_Temporal << 1);
                    Frecuencia_Temporal %= (REFERENCIA +1);
                }

                for (int64_t v = (int)Vuelta_R - 1; v >= 0; v--)
                {
                    if (v % 20 == 0)
                    {
                        if (fdIn == -1)
                        {
                            std::cerr << "\n[!] Error de lectura del archivo." << std::endl;
                            exit(1);
                        }
                    }
                                       uint64_t Frecuencia_Final = Vector_Frecuencia[v];

                    for (int64_t t = 0; t < NumHilos; t++)
                    {
                        size_t Inicio = static_cast<size_t>(t) * Tam_bloque_Hilo;
                        size_t Final = (std::min)(Inicio + Tam_bloque_Hilo, BytesLeidos);
                        if (Inicio >= BytesLeidos)
                            break;


                        g_Pool.encolar([&, Inicio, Final, Frecuencia_Temporal]() {
                            Desencriptacion_Principal(
                                buffer, Inicio, Final, Frecuencia_Temporal,
                                Clave_ENC ^ Usuario_ENC, true,
                                Control_Semilla + LAMBDA, Semilla_Dispersion,
                                REFERENCIA ^ Usuario_Semilla_Principal,
                                Semilla / 2, false);
                        });
                    }
                    g_Pool.esperar_tareas();

                    double Avance_Vuelta = ((double)v / (Vuelta_R + Vuelta_L)) * (double)BytesLeidos;
                    double Progreso_Real = ((double)BytesProcesadosTotales + Avance_Vuelta) / (double)Longitud_Brana_Orig * 100.0;
                    cout << "\r[*] Progreso: [" << fixed << setprecision(1)
                         << (Progreso_Real > 99.9 ? 99.9 : Progreso_Real) << "%] | Activo    " << flush;
                }
            }
            Procesar_Ovillo(Brana_OK, Semilla_Dual_ENC);
            Estabilizar_Brana(Brana_OK, buffer.data(), BytesLeidos, &Torsor_Global);
            memcpy(Brana_OK->Espejo_Adelico, Brana_OK->Fase_Vorticidad, sizeof(Brana_OK->Fase_Vorticidad));
        }

        if (Auth_OK && stream_nonce_ok && ct_mac_ok && BytesLeidos > 0)
        {
            uint64_t start_blk = BytesProcesadosTotales / (uint64_t)(file_brana_bits / 8u);
            brana_v5_flow_xor_rt(buffer.data(), buffer.data(), BytesLeidos,
                K_master.data(), K_master.size(),
                stream_nonce, 16, start_blk, file_brana_bits);
        }
        int64_t BytesEscritos = _write(fdOut, buffer.data(), static_cast<unsigned int>(BytesLeidos));
        if (BytesEscritos == -1)
        {
            cout << "\n[!] Error crítico: disco lleno o pérdida de conexión con el medio" << endl;
            exit(1);
        }
        BytesProcesadosTotales += BytesLeidos;

        if (BytesProcesadosTotales >= UMBRAL_EVOLUCION) {
             Evolucionar_Ecosistema_Semillas(
                Clave_Semilla_Principal, Clave_Semilla_Alterna, Clave_ENC,
                Control_Semilla, Control_Semilla_Alterno, Clave_ENC2
            );

             UMBRAL_EVOLUCION += 34359738368ULL;
             std::memset(Brana_OK->Fase_Vorticidad, 0, sizeof(Brana_OK->Fase_Vorticidad));
             std::memset(Brana_OK->Espejo_Adelico, 0, sizeof(Brana_OK->Espejo_Adelico));
             Torsor_Global = 0.0f;

        }

        double ProgresoFinalBloque = ((double)BytesProcesadosTotales / Longitud_Brana_Orig) * 100.0;
        cout << "\r[*] Progreso: [" << fixed << setprecision(1) << (ProgresoFinalBloque > 100.00 ? 100.00 : ProgresoFinalBloque) << "%] | Activo    " << flush;

        if (Frecuencia_Orig % 2 == 0)
            Frecuencia_Orig = (Frecuencia_Orig / 2) ^ (Frecuencia_Orig + LAMBDA);
        else
            Frecuencia_Orig = (Frecuencia_Orig * 3 + LAMBDA) ^ (Frecuencia_Orig >> 1);
        Frecuencia_Orig %= REFERENCIA;
    }


    uint64_t Valor_Defensa = Valor_Recuperado_Defensa + 1ULL;

    if (BytesARestaurar > 0ULL)
    {
        if (BranaEstable)
        {
            Aplicar_Defensa_Activa(fdIn, InicioData, Fatiga_Final, Valor_Recuperado_Defensa, Semilla_Ofuscacion, BytesARestaurar);
            uint64_t punteroactual = _lseeki64(fdIn, 0, SEEK_END);
            {
                uint64_t intentos_prev = (Valor_Recuperado_Defensa > 1ULL) ? (Valor_Recuperado_Defensa - 1ULL) : 0ULL;
                cout << "\n[*] Se intento acceder " << intentos_prev << " veces.\n";
            }
            Actualizar_Registro_Final(fdIn, faroLeido, Valor_Recuperado_Defensa, Fatiga_Final, PosicionFaro);
        }
        else
        {
            Aplicar_Defensa_Activa(fdIn, InicioData, Fatiga_Final, Valor_Defensa, Semilla_Ofuscacion, BytesARestaurar);
            _lseeki64(fdIn, 0, SEEK_END);
            {
                uint64_t intentos_prev = (Valor_Recuperado_Defensa > 1ULL) ? (Valor_Recuperado_Defensa - 1ULL) : 0ULL;
                cout << "\n[*] Se intento acceder " << intentos_prev << " veces.\n";
            }
            Actualizar_Registro_Final(fdIn, faroLeido, Valor_Defensa, Fatiga_Final, PosicionFaro);
        }
    }

    _commit(fdIn);

    uint64_t Bytes_HeaderCierre = (Total_Bytes_Brana < (ZONA_header * 2ULL)) ? ZONA_faro : ZONA_header;
    if (Bytes_HeaderCierre > Total_Bytes_Brana)
        Bytes_HeaderCierre = Total_Bytes_Brana;

    std::vector<uint8_t> bufferCierre(Bytes_HeaderCierre);
    _lseeki64(fdIn, 0, SEEK_SET);
    _read(fdIn, bufferCierre.data(), static_cast<unsigned int>(Bytes_HeaderCierre));
    Aplicar_Torsion_Principal(bufferCierre, Total_Bytes_Brana);
    _lseeki64(fdIn, 0, SEEK_SET);
    _write(fdIn, bufferCierre.data(), static_cast<unsigned int>(Bytes_HeaderCierre));
    _commit(fdIn);

    if (Total_Bytes_Brana > (Bytes_HeaderCierre + 64))
    {
        uint64_t espacioDispFaro = Total_Bytes_Brana - Bytes_HeaderCierre;

        uint64_t BytesALeerFaroCierre = (espacioDispFaro < ZONA_faro) ? ZONA_header : ZONA_faro;

        if (BytesALeerFaroCierre > espacioDispFaro)
            BytesALeerFaroCierre = espacioDispFaro;

        _lseeki64(fdIn, -static_cast<int64_t>(BytesALeerFaroCierre), SEEK_END);
        std::vector<uint8_t> bufferSelloFinal(BytesALeerFaroCierre);
        _read(fdIn, bufferSelloFinal.data(), static_cast<unsigned int>(BytesALeerFaroCierre));
        Aplicar_Torsion_Principal(bufferSelloFinal, Total_Bytes_Brana);
        _lseeki64(fdIn, -static_cast<int64_t>(BytesALeerFaroCierre), SEEK_END);
        _write(fdIn, bufferSelloFinal.data(), static_cast<unsigned int>(BytesALeerFaroCierre));
        _commit(fdIn);

        if (Total_Bytes_Brana > UMBRAL_CUANTICO)
        {
            uint64_t EspacioLibreCentro = Total_Bytes_Brana - Bytes_HeaderCierre - BytesALeerFaroCierre;
            if (EspacioLibreCentro > ZONA_media)
            {
                uint64_t SemillaPos = (Total_Bytes_Brana ^ LAMBDA);
                uint64_t Porcentaje = 15ULL + (SemillaPos % 60ULL);
                uint64_t Ubicacion_Cuantica_Real = (Total_Bytes_Brana * Porcentaje) / 100ULL;

                if (Ubicacion_Cuantica_Real < Bytes_HeaderCierre)
                {
                    Ubicacion_Cuantica_Real = Bytes_HeaderCierre + ZONA_REGISTRO;
                }
                if (Ubicacion_Cuantica_Real + ZONA_media > (Total_Bytes_Brana - BytesALeerFaroCierre))
                {
                    Ubicacion_Cuantica_Real = (Total_Bytes_Brana - BytesALeerFaroCierre) - ZONA_media - ZONA_REGISTRO;
                }

                _lseeki64(fdIn, Ubicacion_Cuantica_Real, SEEK_SET);
                std::vector<uint8_t> bufferSelloMedio(ZONA_media);
                _read(fdIn, bufferSelloMedio.data(), static_cast<unsigned int>(ZONA_media));
                Aplicar_Torsion_Principal(bufferSelloMedio, Total_Bytes_Brana);
                _lseeki64(fdIn, Ubicacion_Cuantica_Real, SEEK_SET);
                _write(fdIn, bufferSelloMedio.data(), static_cast<unsigned int>(ZONA_media));
                _commit(fdIn);
            }
        }
    }

if (es_senuelo)
    {
        Protocolo_Panico_Minimo(fdIn, Total_Bytes_Brana);
    }
    auto Tiempo_Final = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> Duracion_Total = Tiempo_Final - Tiempo_Inicio;

    cout << "\n\n[*] Listo (" << fixed << setprecision(1) << Duracion_Total.count() << " s)." << endl;
    _mm_free(Brana_OK);
    g_Pool.cerrar();
#ifdef _WIN32
    _commit(fdOut);
    _commit(fdIn);
#else
    fsync(fdOut);
    fsync(fdIn);
#endif

#ifdef _WIN32
    if (Bloqueo_Salida)
    {
        UnlockFileEx(hFileOut, 0, 0xFFFFFFFF, 0xFFFFFFFF, &ovOut);
    }
    if (Bloqueo_Entrada)
    {
        UnlockFileEx(hFileIn, 0, 0xFFFFFFFF, 0xFFFFFFFF, &ovIn);
    }
#else
    flock(fdOut, LOCK_UN);
    flock(fdIn, LOCK_UN);
#endif

if (fdOut != -1)
        _close(fdOut);
if (fdIn != -1)
        _close(fdIn);


    bool plain_mac_ok = false;
    if (mac_tag_ok && Auth_OK)
    {
        uint64_t plain_fp = 0ULL;
        uint64_t plain_size = 0ULL;
        int fdCheck = -1;
#ifdef _WIN32
        fdCheck = _open(Nombre_Archivo.c_str(), _O_RDONLY | _O_BINARY);
#else
        fdCheck = open(Nombre_Archivo.c_str(), O_RDONLY);
#endif
        if (fdCheck >= 0)
        {
            int64_t tsz = _lseeki64(fdCheck, 0, SEEK_END);
            if (tsz > 0)
                plain_size = static_cast<uint64_t>(tsz);
            _lseeki64(fdCheck, 0, SEEK_SET);
            const size_t CH = 1024ULL * 1024ULL;
            std::vector<uint8_t> chunk(CH);
            uint64_t left = plain_size;
            while (left > 0ULL)
            {
                size_t n = static_cast<size_t>(left > CH ? CH : left);
                int64_t nr = _read(fdCheck, chunk.data(), static_cast<unsigned int>(n));
                if (nr <= 0)
                    break;
                plain_fp = brana_mac_update_fp(plain_fp, chunk.data(), static_cast<size_t>(nr));
                left -= static_cast<uint64_t>(nr);
            }
            _close(fdCheck);
        }
        uint64_t Fatiga_Para_Mac =
            (Generador_String(Valor_Header) ^ CRC_Control)
            + (Control_Semilla_Leida ^ LAMBDA);
        uint8_t mac_msg[BRANA_MAC_MSG_LEN];
        uint8_t mac_calc[BRANA_MAC_LEN];
        brana_mac_build_msg(mac_msg, salt_kdf, profile_kdf,
            CRC_Control, Control_Semilla_Leida, Faro_Esperado,
            Fatiga_Para_Mac, BRANA_MAC_DOM_PLAIN, plain_size, plain_fp);
        brana_mac(K_master.data(), mac_msg, BRANA_MAC_MSG_LEN, mac_calc);
        plain_mac_ok = brana_mac_verify(mac_guardado_plain, mac_calc);
    }

    if (Auth_OK && plain_mac_ok && ct_mac_ok)
    {
        Postproceso_Capas(Nombre_Archivo);
    }
    else if (Auth_OK && (!plain_mac_ok || !ct_mac_ok))
    {

        int fdW = -1;
#ifdef _WIN32
        fdW = _open(Nombre_Archivo.c_str(), _O_RDWR | _O_BINARY);
#else
        fdW = open(Nombre_Archivo.c_str(), O_RDWR);
#endif
        if (fdW >= 0)
        {
            int64_t tsz = _lseeki64(fdW, 0, SEEK_END);
            if (tsz > 0)
            {
                uint64_t sz = static_cast<uint64_t>(tsz);
                uint64_t est2 = 0ULL;
                for (int i = 0; i < 8; i++)
                    est2 ^= (static_cast<uint64_t>(K_master[i]) << (8 * (i % 8)));
                est2 ^= (sz * 0x9E3779B97F4A7C15ULL);
                const int n_hits = 16;
                for (int h = 0; h < n_hits; h++)
                {
                    est2 = brana_mac_update_fp(est2, (const uint8_t *)&est2, 8);
                    uint64_t off = (sz > 1ULL) ? (est2 % sz) : 0ULL;
                    unsigned char b = static_cast<unsigned char>(est2 & 0xFF);
                    b ^= static_cast<unsigned char>((est2 >> 17) & 0xFF);
                    _lseeki64(fdW, static_cast<int64_t>(off), SEEK_SET);
                    _write(fdW, &b, 1);
                }
#ifdef _WIN32
                _commit(fdW);
#else
                fsync(fdW);
#endif
            }
            _close(fdW);
        }
    }

cout << "\n[*] Salida: " << Nombre_Archivo << endl;

return 0;
} else {
    std::cout << "Proceso abortado por el usuario." << std::endl;
    return 0;
}
}
