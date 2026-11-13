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
#include <mutex>
#include <algorithm>
#include <ctime>
#include <chrono>
#include <immintrin.h>
#include <fcntl.h>
#include <cstdio>
#include <sys/stat.h>
#include <condition_variable>
#include <queue>
#include <functional>
#include <atomic>
#include <sstream>

#ifndef MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#endif
#include "miniz.h"
#include "pool/brana_pool.hpp"
#include "util/brana_util.h"
#include "container/brana_container.h"
#include "wide/brana_kdf.h"
#include "wide/brana_mac.h"
#include "wide/brana_random.h"
#include "wide/brana_stream.h"
#include "wide/brana_v5_flow.h"
#include "wide/brana_config.h"
#include "crypto/brana_crypto.h"


static ThreadPool g_Pool;


#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#include <io.h>
#include <tchar.h>
#include <direct.h>
#define Brana_Mkdir(path) _mkdir(path)
#else
#include <dirent.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <x86intrin.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <time.h>
#define Brana_Mkdir(path) mkdir(path, 0700)
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
#endif
#ifdef _WIN32
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hOut = INVALID_HANDLE_VALUE;
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

struct BulkEntry {
    string name;
    uint64_t size;
    uint32_t crc32;
    std::vector<uint8_t> data;
};


// --- Valores editables (personalizacion / hardware) ---
// 1MB - Compatibilidad universal
const size_t Tam_Bloque_Hilo = 1 * 1024 * 1024;
// 2MB - Arquitecturas con buena cache L2
// const size_t Tam_Bloque_Hilo = 2 * 1024 * 1024;
// 4MB - Estaciones de trabajo / servidores
// const size_t Tam_Bloque_Hilo = 4 * 1024 * 1024;


const double ALPHA_S = 0.1181;
const uint64_t ZONA_header = 44ULL;
const uint64_t ZONA_faro = 64ULL;
const uint64_t UMBRAL_CUANTICO = 256ULL * 1024ULL;
const uint64_t ZONA_media = 8ULL * 1024ULL;
const uint64_t ZONA_REGISTRO = 1024ULL;
const uint64_t Bloque_MAX = 1024ULL * 1024ULL * 16ULL;
const int64_t VALORES_DENSIDAD[2LL] = {625LL, -625LL};
const uint64_t UMBRAL_EVOLUCION_32GB = 34359738368ULL;
const double UMBRAL_ENTROPIA_OV = 7.5;
const size_t MUESTRA_ENTROPIA_MAX = 256 * 1024;
static const char OV_MAGIC[8] = { 'O','V','I','L','L','O','0','1' };
static const char BULK_MAGIC[8] = { 'B','U','L','K','0','0','0','1' };
const size_t BULK_IO_BUF = 4ULL * 1024ULL * 1024ULL;
const size_t OV_IO_BUF = 4ULL * 1024ULL * 1024ULL;


uint64_t Zona_Defensa_Activa = 4096ULL;
int64_t Acumulador_Espectral = 0LL;
int fdIn = -1;
int fdOut = -1;
bool Bloqueo_Entrada = false;
bool Bloqueo_Salida = false;
uint64_t Factor_Frecuencia_CPU;
uint64_t Constante_Dispersion = 115456244545773ULL;
int64_t Modo_Uso;
uint64_t Seleccion_Vueltas = 1ULL;
uint64_t Seleccion_Capas = 1ULL;
uint64_t Variabilidad = 2ULL;
float Torsor_Global = 0.0f;
uint64_t BytesProcesadosTotales = 0ULL;
bool hodge_critico = false;
int64_t Sector_Principal;
uint64_t N_inicial = 1ULL;
bool credenciales_validas = false;
bool tiene_senuelo = false;
string Usuario, Clave, Nombre_Archivo, Nombre_Salida, Clave_Senuelo, motivo_clave;
int perfil = 3;
int profile_kdf_cli = 1;
std::vector<string> lista_entrada;
bool flag_comprimir_cli = false;
bool flag_wipe = false;
bool flag_db = false;
bool flag_stream = false;
string Texto_Campo;


int main(int argc, char* argv[])
{
BranaDatos *Brana_OK = (BranaDatos *)_mm_malloc(sizeof(BranaDatos), 64);
if (Brana_OK == NULL)
return -1;

Inicializar_TABLA_VISCOSA();

    Nombre_Archivo.clear();
    Nombre_Salida.clear();
    Usuario.clear();
    Clave.clear();
    Clave_Senuelo.clear();


    bool modo_cli = (argc > 1);

    if (modo_cli)
    {
        for (int i = 1; i < argc; ++i)
        {
            string a = argv[i];
            auto need = [&](const char *flag) -> string {
                if (i + 1 >= argc)
                {
                    cerr << "Falta valor para " << flag << "\n";
                    Mostrar_Ayuda_Encriptador();
                    exit(1);
                }
                return string(argv[++i]);
            };

            if (a == "-h" || a == "--help")
            {
                Mostrar_Ayuda_Encriptador();
                return 0;
            }
            else if (a == "-i")
{
    lista_entrada.push_back(need("-i"));
}
            else if (a == "-o") Nombre_Salida = need("-o");
            else if (a == "-u") Usuario = need("-u");
            else if (a == "-p") Clave = need("-p");
            else if (a == "-s") Clave_Senuelo = need("-s");
                        else if (a == "-w" || a == "--wipe")
            {
                flag_wipe = true;
            }
            else if (a == "-y" || a == "--yes-compress")
            {
                flag_comprimir_cli = true;
            }
            else if (a == "-m")
            {
                perfil = atoi(need("-m").c_str());
                if (perfil < 1 || perfil > 5) perfil = 3;
            }
            else if (a == "-k")
            {
                profile_kdf_cli = atoi(need("-k").c_str());
                if (profile_kdf_cli < 0 || profile_kdf_cli > 2) profile_kdf_cli = 1;
            }
            else if (a == "-DB" || a == "--field" || a == "--db")
            {
                flag_db = true;
            }
            else if (a == "-t")
            {
                Texto_Campo = need("-t");
            }
            else if (a == "-S" || a == "--stream")
            {
                flag_stream = true;
            }
            else
            {
                cerr << "Argumento desconocido: " << a << "\n";
                Mostrar_Ayuda_Encriptador();
                return 1;
            }
        }

        if (flag_db)
        {
            if (Usuario.empty() || Clave.empty() || Texto_Campo.empty())
            {
                cerr << "Modo -DB requiere -u, -p y -t.\n";
                Mostrar_Ayuda_Encriptador();
                return 1;
            }
        }
        else if (lista_entrada.empty() || Usuario.empty() || Clave.empty())
        {
            cerr << "CLI requiere al menos un -i, mas -u y -p.\n";
            Mostrar_Ayuda_Encriptador();
            return 1;
        }
        if (!lista_entrada.empty())
            Nombre_Archivo = lista_entrada[0];


        if (!Clave_Cumple_Politica(Clave, motivo_clave))
        {
            cerr << "[!] Clave invalida: " << motivo_clave << "\n";
            return 1;
        }


        if (flag_db)
        {
            uint8_t salt[16], nonce[16];
            int profile_kdf = profile_kdf_cli;
            if (brana_random_salt16(salt) != 0)
            {
                for (int i = 0; i < 16; i++)
                    salt[i] = (uint8_t)(i * 31 + Usuario.size());
            }
            if (brana_random_bytes(nonce, 16) != 0)
            {
                for (int i = 0; i < 16; i++)
                    nonce[i] = (uint8_t)(salt[i] ^ (i * 17));
            }
            size_t kb = (size_t)(BRANA_BITS / 8);
            if (kb < 32) kb = 32;
            if (kb % 32) kb += 32 - (kb % 32);
            std::vector<uint8_t> K(kb, 0);
            if (brana_kdf_ex(Usuario.c_str(), Clave.c_str(), salt, profile_kdf, K.data(), K.size()) != 0)
            {
                cerr << "[ERROR] KDF fallo.\n";
                return 1;
            }
            std::vector<uint8_t> plain(Texto_Campo.begin(), Texto_Campo.end());
            std::vector<uint8_t> ct(plain.size());
            if (brana_v5_flow_xor(ct.data(), plain.data(), plain.size(),
                                  K.data(), K.size(), nonce, 16, 0) != 0)
            {
                cerr << "[ERROR] Cifrado de campo fallo.\n";
                return 1;
            }

            std::vector<uint8_t> env;
            const char *mg = "BRANAF1";
            env.insert(env.end(), mg, mg + 7);
            env.insert(env.end(), salt, salt + 16);
            env.push_back((uint8_t)profile_kdf);
            env.insert(env.end(), nonce, nonce + 16);
            {
                uint32_t bits = (uint32_t)BRANA_BITS;
                for (int b = 0; b < 4; b++)
                    env.push_back((uint8_t)((bits >> (8 * b)) & 0xFF));
                env.push_back(0xB1);
                env.push_back(0x54);
            }
            {
                uint32_t L = (uint32_t)ct.size();
                for (int b = 0; b < 4; b++)
                    env.push_back((uint8_t)((L >> (8 * b)) & 0xFF));
            }
            env.insert(env.end(), ct.begin(), ct.end());
            static const char *hx = "0123456789ABCDEF";
            for (size_t i = 0; i < env.size(); i++)
            {
                unsigned char c = env[i];
                cout << hx[(c >> 4) & 0xF] << hx[c & 0xF];
            }
            cout << "\n";
            _mm_free(Brana_OK);
            return 0;
        }


        if (flag_stream)
        {
            if (lista_entrada.empty())
            {
                cerr << "[!] -S requiere -i <archivo>.\n";
                return 1;
            }
            string path_in = lista_entrada[0];
            string path_out = Nombre_Salida.empty() ? (path_in + ".branas") : Nombre_Salida;
            if (path_out.size() < 7 || path_out.substr(path_out.size() - 7) != ".branas")
            {

                if (Nombre_Salida.empty())
                    path_out = path_in + ".branas";
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
            int64_t total = _lseeki64(fdIn, 0, SEEK_END);
            if (total < 0)
            {
                _close(fdIn);
                cerr << "[ERROR] Lectura fallida.\n";
                return 1;
            }
            uint64_t sz = (uint64_t)total;
            _lseeki64(fdIn, 0, SEEK_SET);

            uint8_t salt[16], nonce[16];
            int profile_kdf = profile_kdf_cli;
            if (brana_random_salt16(salt) != 0)
                for (int i = 0; i < 16; i++) salt[i] = (uint8_t)(i * 31 + (int)sz);
            if (brana_random_bytes(nonce, 16) != 0)
                for (int i = 0; i < 16; i++) nonce[i] = (uint8_t)(salt[i] ^ (i * 17));

            size_t kb = (size_t)(BRANA_BITS / 8);
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


            const char *mg = "BRANAS1";
            _write(fdOut, mg, 7);
            _write(fdOut, salt, 16);
            uint8_t prof = (uint8_t)profile_kdf;
            _write(fdOut, &prof, 1);
            _write(fdOut, nonce, 16);
            {
                uint32_t bits = (uint32_t)BRANA_BITS;
                uint8_t b[4];
                for (int i = 0; i < 4; i++) b[i] = (uint8_t)((bits >> (8 * i)) & 0xFF);
                _write(fdOut, b, 4);
                uint8_t magic[2] = {0xB1, 0x54};
                _write(fdOut, magic, 2);
            }
            {
                uint8_t szb[8];
                for (int i = 0; i < 8; i++)
                    szb[i] = (uint8_t)((sz >> (8 * i)) & 0xFF);
                _write(fdOut, szb, 8);
            }

            const size_t CHUNK = 1024 * 1024;
            std::vector<uint8_t> buf(CHUNK), outb(CHUNK);
            uint64_t done = 0;
            uint64_t start_blk = 0;
            cout << "[*] Stream puro (-S)...\n";
            while (done < sz)
            {
                size_t n = (size_t)((sz - done) > CHUNK ? CHUNK : (sz - done));
                int64_t nr = _read(fdIn, buf.data(), (unsigned)n);
                if (nr <= 0) break;
                n = (size_t)nr;
                if (brana_v5_flow_xor(outb.data(), buf.data(), n,
                                      K.data(), K.size(), nonce, 16, start_blk) != 0)
                {
                    cerr << "[ERROR] Stream fallo.\n";
                    _close(fdIn); _close(fdOut);
                    return 1;
                }
                _write(fdOut, outb.data(), (unsigned)n);
                done += n;
                start_blk += (n + (size_t)(BRANA_BITS / 8) - 1) / (size_t)(BRANA_BITS / 8);
                if (sz > 8 * 1024 * 1024)
                {
                    double pct = 100.0 * (double)done / (double)sz;
                    cout << "\r[*] Progreso: [" << fixed << setprecision(1) << pct << "%]" << flush;
                }
            }
            if (sz > 8 * 1024 * 1024) cout << "\n";
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


        credenciales_validas = true;

        if (Clave_Senuelo.size() == 8)
            tiene_senuelo = true;
        else if (!Clave_Senuelo.empty())
        {
            cerr << "[!] Senuelo: 8 caracteres exactos (se ignora).\n";
            Clave_Senuelo.clear();
        }
    }
    else
    {
        cout << "Brana de Diamante  -  Encriptador\n";
        lista_entrada.clear();

        cout << "\nTipo de entrada:\n"
             << "  1) Un archivo\n"
             << "  2) Una carpeta (cofre .bulk)\n"
             << "  3) Varios archivos (lista)\n"
             << "Opcion: ";
        string op;
        getline(cin, op);

        if (op == "2")
        {
            cout << "Ruta de la carpeta: ";
            string carpeta;
            getline(cin, carpeta);
            lista_entrada.push_back(carpeta);
        }
        else if (op == "3")
        {
            cout << "Rutas de archivos (una por linea; linea vacia = fin):\n";
            for (;;)
            {
                string linea;
                cout << "  > ";
                getline(cin, linea);
                if (linea.empty())
                    break;
                lista_entrada.push_back(linea);
            }
            if (lista_entrada.size() < 2)
            {
                cerr << "[ERROR] Hacen falta al menos 2 archivos.\n";
                return 1;
            }
        }
        else
        {
            cout << "Archivo a encriptar: ";
            string un;
            getline(cin, un);
            lista_entrada.push_back(un);
        }

        if (lista_entrada.empty())
        {
            cerr << "[ERROR] Sin archivos de entrada.\n";
            return 1;
        }
        Nombre_Archivo = lista_entrada[0];

        do {
            cout << "Usuario: ";
            getline(cin, Usuario);
            if (Usuario.empty())
            {
                cout << "[!] El usuario no puede estar vacio.\n";
                continue;
            }

            cout << "Clave (Minimo 8. Debe tener mayuscula, minuscula, digito y simbolo): ";
            getline(cin, Clave);

            if (!Clave_Cumple_Politica(Clave, motivo_clave))
            {
                cout << "[!] Clave invalida: " << motivo_clave << ".\n";
                credenciales_validas = false;
            }
            else
            {
                credenciales_validas = true;
            }
        } while (!credenciales_validas);

        cout << "Clave senuelo (8 caracteres, Enter = ninguna): ";
        getline(cin, Clave_Senuelo);
        if (Clave_Senuelo.size() == 8)
            tiene_senuelo = true;
        else if (!Clave_Senuelo.empty())
        {
            cout << "[!] Senuelo: 8 caracteres exactos (se ignora).\n";
            Clave_Senuelo.clear();
        }

            cout << "\nIntensidad (1=mas rapido, 5=mas lento; recomendado 3):\n"
             << "  1  Rapido\n"
             << "  2  Moderado\n"
             << "  3  Equilibrado (recomendado)\n"
             << "  4  Fuerte\n"
             << "  5  Maximo\n"
             << "Opcion: ";
        {
            string sp;
            getline(cin, sp);
            if (!sp.empty())
            {
                perfil = atoi(sp.c_str());
                if (perfil < 1 || perfil > 5) perfil = 3;

            }
            Modo_Uso = perfil;
        }


               Nombre_Salida.clear();
                       cout << "Nombre de salida (Enter = automatico): ";
        {
            string so;
            getline(cin, so);
            if (!so.empty())
                Nombre_Salida = so;
        }
    }

    if (lista_entrada.empty() && !Nombre_Archivo.empty())
        lista_entrada.push_back(Nombre_Archivo);

    if (lista_entrada.empty())
    {
        cerr << "[ERROR] Sin entrada.\n";
        return 1;
    }

    Dir_Temporal.clear();
    path_bulk_intermedio.clear();
    path_ov_intermedio.clear();


    string path_a_cifrar;
    bool uso_bulk = false;
    bool uso_ov = false;

    if (lista_entrada.size() == 1 && Es_Directorio(lista_entrada[0]))
    {
        std::vector<string> lista, nombres_rel;
        Listar_Archivos_Recursivo(lista_entrada[0], "", lista, nombres_rel);
        if (lista.empty())
        {
            cerr << "[ERROR] Carpeta vacia o inaccesible.\n";
            Limpiar_Dir_Temporal();
            return 1;
        }
                if (Dir_Temporal.empty())
        {
            Dir_Temporal = Crear_Dir_Temporal();
            if (Dir_Temporal.empty())
            {
                cerr << "[ERROR] No se pudo crear carpeta temporal.\n";
                Limpiar_Dir_Temporal();
                return 1;
            }
        }
        string path_bulk = Path_En_Temp(
            (lista_entrada.size() == 1 && Es_Directorio(lista_entrada[0]))
                ? (Nombre_Base_Carpeta(lista_entrada[0]) + ".bulk")
                : string("paquete.bulk"));
        cout << "[*] Empaquetando " << lista.size()
             << " archivo(s) en " << path_bulk << " ...\n";
        if (!Crear_Archivo_BULK(lista, nombres_rel, path_bulk))
        {
            cerr << "[ERROR] No se pudo crear .bulk\n";
            Limpiar_Dir_Temporal();
            return 1;
        }
                path_a_cifrar = path_bulk;
        path_bulk_intermedio = path_bulk;
        uso_bulk = true;
        cout << "[*] Empaquetado.\n";
    }
        else if (lista_entrada.size() >= 2)
    {
        for (size_t i = 0; i < lista_entrada.size(); ++i)
        {
            if (Es_Directorio(lista_entrada[i]))
            {
                cerr << "[ERROR] Con varios archivos no se admiten carpetas: "
                     << lista_entrada[i] << "\n";
                     Limpiar_Dir_Temporal();
                return 1;
            }
        }

        if (Dir_Temporal.empty())
        {
            Dir_Temporal = Crear_Dir_Temporal();
            if (Dir_Temporal.empty())
            {
                cerr << "[ERROR] No se pudo crear carpeta temporal.\n";
                Limpiar_Dir_Temporal();
                return 1;
            }
        }

        string nombre_bulk = "paquete.bulk";
        if (!Nombre_Salida.empty())
        {
            string base = Nombre_Salida;
            if (base.size() >= 6 && base.substr(base.size() - 6) == ".brana")
                base = base.substr(0, base.size() - 6);
            if (base.size() >= 3 && base.substr(base.size() - 3) == ".ov")
                base = base.substr(0, base.size() - 3);
            if (base.size() >= 5 && base.substr(base.size() - 5) == ".bulk")
                base = base.substr(0, base.size() - 5);
            if (!base.empty())
                nombre_bulk = Solo_Nombre(base) + ".bulk";
        }

        string path_bulk = Path_En_Temp(nombre_bulk);

        std::vector<string> nombres_rel;
        for (size_t i = 0; i < lista_entrada.size(); ++i)
            nombres_rel.push_back(Solo_Nombre(lista_entrada[i]));

        cout << "[*] Empaquetando " << lista_entrada.size()
             << " archivo(s) en " << path_bulk << " ...\n";
        if (!Crear_Archivo_BULK(lista_entrada, nombres_rel, path_bulk))
        {
            cerr << "[ERROR] No se pudo crear .bulk\n";
            Limpiar_Dir_Temporal();
            return 1;
        }
        path_a_cifrar = path_bulk;
        path_bulk_intermedio = path_bulk;
        uso_bulk = true;
        cout << "[*] Empaquetado.\n";
    }
    else
    {

        path_a_cifrar = lista_entrada[0];
    }


        double h = Entropia_Shannon(path_a_cifrar);
    (void)h;

    bool quiere_ov = false;
    if (!Entropia_Es_Alta(path_a_cifrar))
    {
        if (modo_cli)
        {

            quiere_ov = flag_comprimir_cli;
            if (flag_comprimir_cli)
                cout << "[*] Compresion solicitada\n";
        }
        else
        {
            cout << "\n[?] Comprimir antes de cifrar? (S/N): ";
            char r = 'N';
            cin >> r;
            cin.ignore(1024, '\n');
            quiere_ov = (toupper(static_cast<unsigned char>(r)) == 'S');
        }
    }
    else if (modo_cli && flag_comprimir_cli)
    {
        cout << "[*] Compresion omitida (no aporta en este caso)\n";
    }

    if (quiere_ov)
    {
        if (Dir_Temporal.empty())
        {
            Dir_Temporal = Crear_Dir_Temporal();
            if (Dir_Temporal.empty())
            {
                cerr << "[ERROR] No se pudo crear carpeta temporal.\n";
                cout << "[*] Sin compresion.\n";
            }
        }
        string path_ov = Dir_Temporal.empty()
            ? (path_a_cifrar + ".ov")
            : Path_En_Temp(Solo_Nombre(path_a_cifrar) + ".ov");

        cout << "[*] Comprimiendo...\n";
        if (Crear_Archivo_OV(path_a_cifrar, path_ov))
        {
            path_a_cifrar = path_ov;
            path_ov_intermedio = path_ov;
            uso_ov = true;
            cout << "[*] Comprimido.\n";

                if (!path_bulk_intermedio.empty())
                {
#ifdef _WIN32
                    if (_unlink(path_bulk_intermedio.c_str()) == 0)
                        cout << "[*] Espacio liberado (intermedio)\n";
#else
                    if (unlink(path_bulk_intermedio.c_str()) == 0)
                        cout << "[*] Espacio liberado (intermedio)\n";
#endif
                    path_bulk_intermedio.clear();
                }
        }
        else
            cout << "[*] Sin compresion; se cifra el contenido tal cual.\n";
    }


    string base_usuario;
    if (!Nombre_Salida.empty())
    {
        base_usuario = Nombre_Salida;
        if (base_usuario.size() >= 6 &&
            base_usuario.substr(base_usuario.size() - 6) == ".brana")
            base_usuario = base_usuario.substr(0, base_usuario.size() - 6);
        if (base_usuario.size() >= 3 &&
            base_usuario.substr(base_usuario.size() - 3) == ".ov")
            base_usuario = base_usuario.substr(0, base_usuario.size() - 3);
        if (base_usuario.size() >= 5 &&
            base_usuario.substr(base_usuario.size() - 5) == ".bulk")
            base_usuario = base_usuario.substr(0, base_usuario.size() - 5);
    }

    string nombre_base_archivo;
    string ext_original;

    if (!base_usuario.empty())
    {
        nombre_base_archivo = base_usuario;
        if (!uso_bulk && lista_entrada.size() == 1 &&
            !Es_Directorio(lista_entrada[0]))
        {
            string orig = Solo_Nombre(lista_entrada[0]);
            size_t d = orig.find_last_of('.');
            if (d != string::npos && d > 0 && d + 1 < orig.size())
                ext_original = orig.substr(d);
        }
    }
    else if (lista_entrada.size() >= 2)
    {
        nombre_base_archivo = "paquete";
    }
    else if (Es_Directorio(lista_entrada[0]))
    {
        nombre_base_archivo = Nombre_Base_Carpeta(lista_entrada[0]);
    }
    else
    {

        nombre_base_archivo = Solo_Nombre(lista_entrada[0]);

    }


    if (!ext_original.empty())
        nombre_base_archivo += ext_original;

    if (uso_bulk)
        nombre_base_archivo += ".bulk";
    if (uso_ov)
        nombre_base_archivo += ".ov";

    Nombre_Salida = nombre_base_archivo + ".brana";


#ifdef _WIN32
fdIn = _open(path_a_cifrar.c_str(), _O_RDONLY | _O_BINARY);
if (fdIn != -1)
    {
    hFile = (HANDLE)_get_osfhandle(fdIn);
    Bloqueo_Entrada = LockFileEx(hFile, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 0xFFFFFFFF, 0xFFFFFFFF, &ovIn);
    }
#else
fdIn = open(path_a_cifrar.c_str(), O_RDONLY);
if (fdIn != -1)
    {
    Bloqueo_Entrada = (flock(fdIn, LOCK_EX | LOCK_NB) == 0);
    }
#endif
if (!Bloqueo_Entrada)
    {
    cout << "[!] No se puede abrir la entrada (en uso o inexistente)." << endl;
    if (fdIn != -1)
        _close(fdIn);
        Limpiar_Dir_Temporal();
    return 1;
    }

#ifdef _WIN32
    uint64_t Total_Bytes_Orig = _filelengthi64(fdIn);
#else
    struct stat st;
    fstat(fdIn, &st);
    uint64_t Total_Bytes_Orig = st.st_size;
#endif

#ifdef _WIN32
fdOut = _open(Nombre_Salida.c_str(), _O_RDWR | _O_CREAT | _O_TRUNC | _O_BINARY, _S_IREAD | _S_IWRITE);
if (fdOut != -1)
    {
    hOut = (HANDLE)_get_osfhandle(fdOut);
    Bloqueo_Salida = LockFileEx(hOut, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 0, 0xFFFFFFFF, &ovOut);
    }
#else
fdOut = open(Nombre_Salida.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0666);
if (fdOut != -1)
    {
    Bloqueo_Salida = (flock(fdOut, LOCK_EX | LOCK_NB) == 0);
    }
#endif

if (fdOut == -1)
    {
    cout << "[!] Error fatal: No se pudo crear el archivo de salida." << endl;
    _close(fdIn);
    Limpiar_Dir_Temporal();
    return 1;
    }

if (Bloqueo_Salida)
    {
    cout << "\n[*] Preparando..." << endl;
    }
else
    {
    cout << "[!] No se puede escribir la salida (archivo en uso)." << endl;
    _close(fdIn);
    _close(fdOut);
    Limpiar_Dir_Temporal();
    return 1;
    }


uint64_t plain_fp = 0ULL;
uint64_t plain_size = 0ULL;
{
    _lseeki64(fdIn, 0, SEEK_END);
    int64_t tsz = _lseeki64(fdIn, 0, SEEK_CUR);
    if (tsz > 0)
        plain_size = static_cast<uint64_t>(tsz);
    _lseeki64(fdIn, 0, SEEK_SET);
    const size_t CH = 1024ULL * 1024ULL;
    std::vector<uint8_t> chunk(CH);
    uint64_t left = plain_size;
    while (left > 0ULL)
    {
        size_t n = static_cast<size_t>(left > CH ? CH : left);
        int64_t nr = _read(fdIn, chunk.data(), static_cast<unsigned int>(n));
        if (nr <= 0)
            break;
        plain_fp = brana_mac_update_fp(plain_fp, chunk.data(), static_cast<size_t>(nr));
        left -= static_cast<uint64_t>(nr);
    }
    _lseeki64(fdIn, 0, SEEK_SET);
}


uint8_t salt_kdf[BRANA_KDF_SALT_LEN];
int profile_kdf = profile_kdf_cli;
    cout << "[*] Derivando clave...\n";
uint8_t K_master[BRANA_KEY_BYTES];
if (brana_random_salt16(salt_kdf) != 0)
{
    for (int si = 0; si < 16; ++si)
        salt_kdf[si] = static_cast<uint8_t>((si * 31) ^ (Total_Bytes_Orig & 0xFF));
}
if (brana_kdf_ex(Usuario.c_str(), Clave.c_str(), salt_kdf, profile_kdf, K_master, BRANA_KEY_BYTES) != 0)
{
    cerr << "[ERROR] KDF fallo.\n";
    Limpiar_Dir_Temporal();
    return 1;
}

uint64_t CRC_Control = static_cast<uint64_t>(Total_Bytes_Orig ^ 0xEDB88320);
uint64_t Clave_ENC = 0, Usuario_ENC = 0, Clave_Semilla_Principal = 0, Usuario_Semilla_Principal = 0;
Brana_Expandir_Desde_KMaster(K_master, CRC_Control, Clave_ENC, Usuario_ENC,
    Clave_Semilla_Principal, Usuario_Semilla_Principal);


uint8_t stream_nonce[16];
if (brana_random_bytes(stream_nonce, 16) != 0)
{
    for (int ni = 0; ni < 16; ++ni)
        stream_nonce[ni] = static_cast<uint8_t>((ni * 17) ^ salt_kdf[ni % 16]);
}

uint64_t Semilla_Dual_ENC = Clave_ENC ^ Usuario_ENC;

float Frecuencia_Maxima_CPU = Obtener_Frecuencia_Cpu();
if (Frecuencia_Maxima_CPU > 0.0f)
    {
    Factor_Frecuencia_CPU = static_cast<uint64_t>(Frecuencia_Maxima_CPU * 1000);
    }
else
    {
    Factor_Frecuencia_CPU = 1000ULL + (Semilla_Dual_ENC % 2001ULL);
    }
Optimizar_Sistema();

    string CRC_ENC = to_string(CRC_Control);
    string CRC_INV_ENC = CRC_ENC;
    reverse(CRC_INV_ENC.begin(), CRC_INV_ENC.end());
    uint64_t Semilla = Generador_String(Valor_Header) ^ Clave_Semilla_Principal;

    for (uint64_t i = 0; i < Valor_Header.length() && i < 8ULL; i++)
        Constante_Dispersion |= (static_cast<uint64_t>(static_cast<uint8_t>(Valor_Header[i])) << (i * 8ULL));

    const uint64_t Semilla_Dispersion = ((Constante_Dispersion + REFERENCIA) ^ (CRC_Control * LAMBDA + 1ULL)) * (LAMBDA % 10007ULL) + 1ULL;
    uint64_t Control_Semilla = Semilla_Dispersion ^ (CRC_Control << 32ULL | CRC_Control);

    string Firma_Control = "";
    for (int64_t i = 0LL; i < 8LL; i++)
    {
        uint8_t Caracter = static_cast<uint8_t>((Semilla_Dispersion >> (i * 8LL)) & 0xFFLL);
        if (Caracter == 0)
            Caracter = (uint8_t)(i + 1LL);
        Firma_Control += Caracter;
    }


    _lseeki64(fdIn, 0, SEEK_SET);

    Modo_Uso = perfil;
if (Modo_Uso < 1 || Modo_Uso > 5)
    Modo_Uso = 3;

    switch (Modo_Uso)
    {
    case 1:
        Seleccion_Vueltas = 1ULL;
        Seleccion_Capas = 1ULL;
        Variabilidad = 1ULL;
        break;
    case 2:
        Seleccion_Vueltas = 1ULL;
        Seleccion_Capas = 2ULL;
        Variabilidad = 3ULL;
        break;
    case 3:
        if (Total_Bytes_Orig < 100ULL * 1024ULL * 1024ULL)
        {
            Seleccion_Vueltas = 200ULL;
            Seleccion_Capas = 205ULL;
            Variabilidad = 40ULL;
        }
        else if (Total_Bytes_Orig < 1024ULL * 1024ULL * 1024ULL)
        {
            Seleccion_Vueltas = 80ULL;
            Seleccion_Capas = 83ULL;
            Variabilidad = 20ULL;
        }
        else
        {
            Seleccion_Vueltas = 3ULL;
            Seleccion_Capas = 4ULL;
            Variabilidad = 5ULL;
        }
        break;
    case 4:
        if (Total_Bytes_Orig < 100ULL * 1024ULL * 1024ULL)
        {
            Seleccion_Vueltas = 400ULL;
            Seleccion_Capas = 405ULL;
            Variabilidad = 60ULL;
        }
        else if (Total_Bytes_Orig < 1024ULL * 1024ULL * 1024ULL)
        {
            Seleccion_Vueltas = 150ULL;
            Seleccion_Capas = 153ULL;
            Variabilidad = 30ULL;
        }
        else
        {
            Seleccion_Vueltas = 5ULL;
            Seleccion_Capas = 6ULL;
            Variabilidad = 10ULL;
        }
        break;
    case 5:
        if (Total_Bytes_Orig < 100ULL * 1024ULL * 1024ULL)
        {
            Seleccion_Vueltas = 600ULL;
            Seleccion_Capas = 605ULL;
            Variabilidad = 80ULL;
        }
        else if (Total_Bytes_Orig < 1024ULL * 1024ULL * 1024ULL)
        {
            Seleccion_Vueltas = 250ULL;
            Seleccion_Capas = 253ULL;
            Variabilidad = 50ULL;
        }
        else
        {
            Seleccion_Vueltas = 7ULL;
            Seleccion_Capas = 8ULL;
            Variabilidad = 15ULL;
        }
        break;
    default:
        Seleccion_Vueltas = 1ULL;
        Seleccion_Capas = 2ULL;
        Variabilidad = 3ULL;
    }

    uint64_t Vuelta_L = Seleccion_Vueltas + (CRC_Control % Variabilidad) + (Clave_Semilla_Principal % Variabilidad);
    uint64_t Vuelta_R = Seleccion_Capas + (CRC_Control % Variabilidad) + (Clave_Semilla_Principal % Variabilidad);

    if (Vuelta_L < 1ULL)
        Vuelta_L = 1ULL;

    struct PerfilDatos
    {
        uint64_t Vuelta_L;
        uint64_t Vuelta_R;
    };

    PerfilDatos p;
    p.Vuelta_L = Vuelta_L;
    p.Vuelta_R = Vuelta_R;
    uint8_t *pPtr = reinterpret_cast<uint8_t *>(&p);
    vector<uint8_t> hBuf(Firma_Control.begin(), Firma_Control.end());

    for (size_t i = 0; i < sizeof(PerfilDatos); i++)
    {
        hBuf.push_back(pPtr[i]);
    }
    uint64_t Semilla_HBuf = LAMBDA ^ Clave_Semilla_Principal;
    for (uint64_t i = 0ULL; i < hBuf.size(); i++)
    {
        hBuf[i] ^= static_cast<uint8_t>((Semilla_HBuf >> (i % 8ULL)) % 256ULL);
        hBuf[i] = Encriptacion_Secundaria_Individual(hBuf[i], REFERENCIA , i, true, Clave_Semilla_Principal, 0);
    }

    int64_t hSize = (int)hBuf.size();
    _write(fdOut, &hSize, sizeof(int));
    _write(fdOut, hBuf.data(), static_cast<size_t>(hSize));
    _write(fdOut, &Control_Semilla, sizeof(uint64_t));
    _write(fdOut, &CRC_Control, sizeof(uint64_t));
    uint64_t Fin_Header = _lseeki64(fdOut, 0, SEEK_CUR);
    uint64_t Clave_Semilla_Alterna = _rotr64(Clave_Semilla_Principal ^ LAMBDA, Semilla % 32ULL);
    uint64_t Control_Semilla_Alterno = _rotr64(Control_Semilla ^ Vuelta_L, Semilla % 13ULL);
    uint64_t Clave_ENC2 = _rotl64(Clave_ENC ^ Clave_Semilla_Principal, Semilla % 64ULL);
    _lseeki64(fdOut, Fin_Header, SEEK_SET);
    _lseeki64(fdIn, 0, SEEK_SET);
    uint64_t Frecuencia_Orig = Clave_Semilla_Principal % REFERENCIA ;
    cout << "[*] Cifrando..." << endl;
    auto Tiempo_Inicio = std::chrono::high_resolution_clock::now();
    int64_t numHilos = Optimizar_Hilos_CPU(Tam_Bloque_Hilo);
    size_t bytesALeer = (size_t)Tam_Bloque_Hilo * numHilos;
        g_Pool.inicializar(static_cast<size_t>(numHilos));
    vector<uint8_t> buffer(bytesALeer);
    const uint8_t Salto_Cuantico = static_cast<uint8_t>(Semilla % 256ULL);
 uint64_t UMBRAL_EVOLUCION = UMBRAL_EVOLUCION_32GB;

    while ((Sector_Principal = _read(fdIn, buffer.data(), static_cast<size_t>(bytesALeer))) > 0)
    {
        size_t BytesLeidos = static_cast<size_t>(Sector_Principal);

        Inicializar_Rigidez_Adelica(Brana_OK, buffer.data(), BytesLeidos);


        if (BytesLeidos > 0)
        {
            uint64_t start_blk = BytesProcesadosTotales / (uint64_t)BRANA_BLOCK_BYTES;
            if (brana_v5_flow_xor(buffer.data(), buffer.data(), BytesLeidos,
                    K_master, BRANA_KEY_BYTES,
                    stream_nonce, 16, start_blk) != 0)
            {
                cerr << "[ERROR] Stream wide fallo.\n";
                exit(1);
            }
        }

        if (BytesLeidos > 0)
        {
            vector<uint64_t> Vector_Frecuencia_1;
            Vector_Frecuencia_1.reserve(Vuelta_L);
            uint64_t Frecuencia_Temporal_Primaria = Frecuencia_Orig;
            for (uint64_t v = 0ULL; v < Vuelta_L; v++)
            {
                Vector_Frecuencia_1.push_back(Frecuencia_Temporal_Primaria);
                if (Frecuencia_Temporal_Primaria % 2ULL == 0ULL)
                {
                    Frecuencia_Temporal_Primaria = (Frecuencia_Temporal_Primaria / 2ULL) ^ (Frecuencia_Temporal_Primaria + LAMBDA);
                }
                else
                {
                    Frecuencia_Temporal_Primaria = (Frecuencia_Temporal_Primaria * 3ULL + LAMBDA) ^ (Frecuencia_Temporal_Primaria >> 1ULL);
                }
                Frecuencia_Temporal_Primaria %= REFERENCIA ;
            }

            for (uint64_t v = 0ULL; v < Vuelta_L; ++v)
            {
                uint64_t Frecuencia_Final = Vector_Frecuencia_1[v];

                for (size_t i = 0; i < static_cast<size_t>(numHilos); ++i)
                {
                    size_t Inicio = i * Tam_Bloque_Hilo;
                    if (Inicio >= BytesLeidos)
                        break;
                    size_t Final = (std::min)(Inicio + Tam_Bloque_Hilo, BytesLeidos);

                    g_Pool.encolar([&, Inicio, Final, Frecuencia_Final]() {
                        Encriptacion_Principal(
                            buffer, Inicio, Final, Frecuencia_Final,
                            Clave_Semilla_Principal, true, Control_Semilla,
                            Clave_ENC, REFERENCIA, Semilla, true);
                    });
                }
                g_Pool.esperar_tareas();

                double Avance_Vuelta = ((double)v / (Vuelta_L + Vuelta_R)) * (double)BytesLeidos;
                double Progreso_Real = ((double)BytesProcesadosTotales + Avance_Vuelta) / (double)Total_Bytes_Orig * 100.0;
                cout << "\r[*] Progreso: [" << fixed << setprecision(1)
                     << (Progreso_Real > 99.9 ? 99.9 : Progreso_Real) << "%]" << flush;
            }
        }
        if (BytesLeidos > 0)
        {
            uint64_t Salto = (Semilla % 7ULL) + 1ULL;

            for (uint64_t i = 0ULL; i < BytesLeidos; i++)
            {
                uint64_t Posicion = (i * Salto) % BytesLeidos;
                if (i != Posicion)
                {
                    std::swap(buffer[i], buffer[Posicion]);
                }
            }
        }

        for (uint64_t i = 0; i < BytesLeidos; i++)
        {
            uint64_t Posicion_Global = BytesProcesadosTotales + i;
            uint64_t Posicion = Semilla ^ i;
            buffer[i] ^= static_cast<uint8_t>((Posicion_Global ^ (Posicion_Global >> 8ULL)) & 0xFFULL);
            buffer[i] ^= static_cast<uint8_t>((Posicion ^ (Posicion >> 8)) & 0xFFULL);
            buffer[i] = _rotl8(buffer[i], (Posicion % 7ULL) + 1ULL);
            buffer[i] ^= 0x62ULL;
            if (i > 0ULL)
            {
                buffer[i] ^= (buffer[i - 1ULL] >> 4ULL);
            }
        }

        for (size_t i = 0; i < BytesLeidos; i++)
        {
            buffer[i] = Encriptacion_Secundaria_Individual(buffer[i], REFERENCIA , i, true, Clave_Semilla_Principal, Salto_Cuantico);
            if (i > 0)
            {
                buffer[i] ^= (buffer[i - 1] >> 4);
            }
        }

        if (BytesLeidos > 0)
        {
            vector<uint64_t> Vector_Frecuencia_2;
            Vector_Frecuencia_2.reserve(Vuelta_R);
            uint64_t Frecuencia_Temporal_Secundaria = Frecuencia_Orig;

            for (uint64_t v = 0ULL; v < Vuelta_R; v++)
            {
                Vector_Frecuencia_2.push_back(Frecuencia_Temporal_Secundaria);
                if (Frecuencia_Temporal_Secundaria % 2ULL == 0ULL)
                {
                    Frecuencia_Temporal_Secundaria = (Frecuencia_Temporal_Secundaria / 2ULL) ^ (Frecuencia_Temporal_Secundaria + LAMBDA);
                }
                else
                {
                    Frecuencia_Temporal_Secundaria = (Frecuencia_Temporal_Secundaria * 3ULL + LAMBDA) ^ (Frecuencia_Temporal_Secundaria >> 1ULL);
                }
                Frecuencia_Temporal_Secundaria %= REFERENCIA ;
            }
            for (uint64_t v = 0ULL; v < Vuelta_R; ++v)
            {
                uint64_t Frecuencia_Final = Vector_Frecuencia_2[v];

                for (size_t i = 0; i < static_cast<size_t>(numHilos); ++i)
                {
                    size_t Inicio = i * Tam_Bloque_Hilo;
                    if (Inicio >= BytesLeidos)
                        break;
                    size_t Final = (std::min)(Inicio + Tam_Bloque_Hilo, BytesLeidos);

                    g_Pool.encolar([&, Inicio, Final, Frecuencia_Final]() {
                        Encriptacion_Principal(
                            buffer, Inicio, Final, Frecuencia_Final,
                            Clave_Semilla_Alterna, true, Control_Semilla_Alterno,
                            Clave_ENC2, REFERENCIA, Semilla, true);
                    });
                }
                g_Pool.esperar_tareas();

                double Avance_Vuelta = ((double)(Vuelta_L + v) / (Vuelta_L + Vuelta_R)) * (double)BytesLeidos;
                double Progreso_Real = ((double)BytesProcesadosTotales + Avance_Vuelta) / (double)Total_Bytes_Orig * 100.0;
                cout << "\r[*] Progreso: [" << fixed << setprecision(1)
                     << (Progreso_Real > 99.9 ? 99.9 : Progreso_Real) << "%]" << flush;
            }
        }

        if (BytesLeidos > 0)
        {
            uint64_t Salto = (Semilla % 7ULL) + 1ULL;

            for (uint64_t i = 0ULL; i < BytesLeidos; i++)
            {
                uint64_t Posicion = (i * Salto) % BytesLeidos;
                if (i != Posicion)
                {
                    std::swap(buffer[i], buffer[Posicion]);
                }
            }
        }

        for (uint64_t i = 0ULL; i < BytesLeidos; i++)
        {
            uint64_t Posicion = Semilla ^ i;
            uint8_t Rotacion = static_cast<uint8_t>(Posicion % 5ULL + 1ULL);
            buffer[i] = (buffer[i] << Rotacion) | (buffer[i] >> (8ULL - Rotacion));
            buffer[i] ^= 0x13ULL;
            if (i > 0ULL)
            {
                buffer[i] ^= (buffer[i - 1ULL] >> 4ULL);
            }
        }

        for (int64_t i = 0LL; i < BytesLeidos; i++)
        {
            buffer[i] = Encriptacion_Secundaria_Individual(buffer[i], REFERENCIA , i, true, Clave_Semilla_Alterna, Salto_Cuantico);
            if (i > 0LL)
            {
                buffer[i] ^= (buffer[i - 1LL] >> 4LL);
            }
        }

        Procesar_Ovillo(Brana_OK, Semilla_Dual_ENC);
        Estabilizar_Brana(Brana_OK, buffer.data(), BytesLeidos, &Torsor_Global);

        {
            int hodge_try = 0;
            while (!Validar_Ciclos_Hodge(Brana_OK) && hodge_try < 3)
            {
                Procesar_Ovillo(Brana_OK, Semilla_Dual_ENC ^ static_cast<uint64_t>(hodge_try + 1));
                ++hodge_try;
            }
            if (!Validar_Ciclos_Hodge(Brana_OK))
                hodge_critico = true;
        }
        memcpy(Brana_OK->Espejo_Adelico, Brana_OK->Fase_Vorticidad, sizeof(Brana_OK->Fase_Vorticidad));
        _write(fdOut, buffer.data(), static_cast<size_t>(BytesLeidos));
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
        double ProgresoFinalBloque = ((double)BytesProcesadosTotales / Total_Bytes_Orig) * 100.0;
        cout << "\r[*] Progreso: [" << fixed << setprecision(1) << (ProgresoFinalBloque > 100.00 ? 100.00 : ProgresoFinalBloque) << "%]" << flush;

        if (Frecuencia_Orig % 2ULL == 0ULL)
        {
            Frecuencia_Orig = (Frecuencia_Orig / 2ULL) ^ (Frecuencia_Orig + LAMBDA);
        }
        else
        {
            Frecuencia_Orig = (Frecuencia_Orig * 3ULL + LAMBDA) ^ (Frecuencia_Orig >> 1ULL);
        }
        Frecuencia_Orig %= REFERENCIA ;
    }

    auto Tiempo_Final = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> Duracion_Total = Tiempo_Final - Tiempo_Inicio;
    cout << "\n\n[*] Cifrado listo (" << fixed << setprecision(1) << Duracion_Total.count() << " s)." << endl;
    _mm_free(Brana_OK);
    g_Pool.cerrar();
#ifdef _WIN32
    _commit(fdOut);
#else
    fsync(fdOut);
#endif

    _lseeki64(fdOut, 0, SEEK_END);
    if (hodge_critico)
    {
        std::cerr << "\n[!] No se pudo completar el cifrado (estado interno inestable).\n"
                  << "No es un juicio de la clave: el estado interno no equilibro.\n"
                  << "Se aborta para no emitir un contenedor con ovillo degenerado.\n";
        _close(fdOut);
        _close(fdIn);
#ifdef _WIN32
        _unlink(Nombre_Salida.c_str());
#else
        unlink(Nombre_Salida.c_str());
#endif
        return 1;
    }

    int64_t Basura_Relleno_Final = Calcular_Longitud_Relleno(Control_Semilla, CRC_Control);
    uint64_t Tam_Fisico_Actual = _lseeki64(fdOut, 0, SEEK_CUR);
    uint64_t Semilla_Ofuscacion = Generador_String(Valor_Header) ^ ((Control_Semilla ^ CRC_Control) ^ LAMBDA);
    uint64_t Fatiga_Final = (Generador_String(Valor_Header) ^ CRC_Control) + (Control_Semilla ^ LAMBDA);
    uint64_t Fin_Data_Util = Tam_Fisico_Actual;
    uint64_t espacioDataPura = (Fin_Data_Util > Fin_Header) ? (Fin_Data_Util - Fin_Header) : 0ULL;
    uint64_t Bytes_A_Defender = (espacioDataPura < Zona_Defensa_Activa) ? espacioDataPura : Zona_Defensa_Activa;


    uint64_t ct_fp = 0ULL;
    const uint64_t ct_size = espacioDataPura;
    if (ct_size > 0ULL)
    {
        const size_t CH = 1024ULL * 1024ULL;
        std::vector<uint8_t> chunk(CH);
        uint64_t left = ct_size;
        _lseeki64(fdOut, static_cast<int64_t>(Fin_Header), SEEK_SET);
        while (left > 0ULL)
        {
            size_t n = static_cast<size_t>(left > CH ? CH : left);
            int64_t nr = _read(fdOut, chunk.data(), static_cast<unsigned int>(n));
            if (nr <= 0)
                break;
            ct_fp = brana_mac_update_fp(ct_fp, chunk.data(), static_cast<size_t>(nr));
            left -= static_cast<uint64_t>(nr);
        }
        _lseeki64(fdOut, 0, SEEK_END);
    }

    if (Bytes_A_Defender > 0ULL)
    {
        Aplicar_Defensa_Activa(fdOut, Fin_Header, Fatiga_Final, N_inicial, Semilla_Ofuscacion, Bytes_A_Defender);
    }

#ifdef _WIN32
    _commit(fdOut);
#else
    fsync(fdOut);
#endif

    uint64_t Header_y_Masa = _lseeki64(fdOut, 0, SEEK_END);

    uint64_t Ancla_Final_Faro = Generador_String(to_string(Semilla_Dual_ENC ^ Clave_Semilla_Principal));
    uint64_t nudoIdentidad = (Usuario_Semilla_Principal ^ Clave_ENC) * LAMBDA;
    uint64_t firmaInercia = (Fatiga_Final ^ nudoIdentidad) ^ ((Header_y_Masa * Clave_Semilla_Principal) + Semilla_Ofuscacion);
    std::vector<uint8_t> registroAtaques(ZONA_REGISTRO);

    for (uint64_t j = 0; j < ZONA_REGISTRO; j++)
    {
        uint64_t v = (j + firmaInercia) * (Clave_ENC | 1);
        registroAtaques[j] = static_cast<uint8_t>((v >> 16) ^ (v >> 8));
    }

    uint64_t posicionRealDelFaro = _lseeki64(fdOut, 0, SEEK_END);
    _write(fdOut, &Ancla_Final_Faro, sizeof(uint64_t));
    _write(fdOut, &N_inicial, sizeof(uint64_t));
    _write(fdOut, &Fatiga_Final, sizeof(uint64_t));
    _write(fdOut, registroAtaques.data(), ZONA_REGISTRO);


    {
        uint8_t mac_msg[BRANA_MAC_MSG_LEN];
        uint8_t mac_tag_ct[BRANA_MAC_LEN];
        uint8_t mac_tag_plain[BRANA_MAC_LEN];
        brana_mac_build_msg(mac_msg, salt_kdf, profile_kdf,
            CRC_Control, Control_Semilla, Ancla_Final_Faro, Fatiga_Final,
            BRANA_MAC_DOM_CT, ct_size, ct_fp);
        if (brana_mac(K_master, mac_msg, BRANA_MAC_MSG_LEN, mac_tag_ct) != 0)
        {
            cerr << "[ERROR] MAC-CT fallo.\n";
            exit(1);
        }
        brana_mac_build_msg(mac_msg, salt_kdf, profile_kdf,
            CRC_Control, Control_Semilla, Ancla_Final_Faro, Fatiga_Final,
            BRANA_MAC_DOM_PLAIN, plain_size, plain_fp);
        if (brana_mac(K_master, mac_msg, BRANA_MAC_MSG_LEN, mac_tag_plain) != 0)
        {
            cerr << "[ERROR] MAC-PLAIN fallo.\n";
            exit(1);
        }
        _write(fdOut, mac_tag_ct, BRANA_MAC_LEN);
        _write(fdOut, mac_tag_plain, BRANA_MAC_LEN);
    }


    if (Basura_Relleno_Final < 47LL)
        Basura_Relleno_Final = 47LL;

    std::vector<uint8_t> basura(static_cast<size_t>(Basura_Relleno_Final));

    for (int64_t i = 0LL; i < Basura_Relleno_Final; i++)
    {
        uint64_t variacion = (i + ZONA_REGISTRO) ^ Clave_Semilla_Alterna ^ Factor_Frecuencia_CPU;
        basura[static_cast<size_t>(i)] = static_cast<uint8_t>((variacion * LAMBDA) % 256ULL);
    }


    for (int si = 0; si < 16; ++si)
        basura[static_cast<size_t>(si)] = salt_kdf[si];
    basura[16] = static_cast<uint8_t>(profile_kdf);

    {
        uint64_t mask_senuelo =
            Generador_String(Valor_Header) ^ CRC_Control ^ Control_Semilla ^ LAMBDA;
        uint64_t token_senuelo;

        if (tiene_senuelo)
        {
            token_senuelo = Generador_String(Clave_Senuelo) ^ mask_senuelo;
        }
        else
        {
            token_senuelo =
                (Factor_Frecuencia_CPU * LAMBDA) ^ (CRC_Control << 3)
                ^ 0xA5A5A5A5A5A5A5A5ULL;
            token_senuelo ^= (token_senuelo << 13) | (token_senuelo >> 7);
        }


        for (int b = 0; b < 8; ++b)
        {
            basura[static_cast<size_t>(17 + b)] =
                static_cast<uint8_t>((token_senuelo >> (8 * b)) & 0xFFULL);
        }
    }
    for (int ni = 0; ni < 16; ++ni)
        basura[static_cast<size_t>(25 + ni)] = stream_nonce[ni];

    {
        uint32_t bits_le = static_cast<uint32_t>(BRANA_BITS);
        for (int bi = 0; bi < 4; ++bi)
            basura[static_cast<size_t>(BRANA_BASURA_OFF_BITS + bi)] =
                static_cast<uint8_t>((bits_le >> (8 * bi)) & 0xFFu);
        basura[BRANA_BASURA_OFF_BITS_MAGIC]     = (uint8_t)BRANA_BASURA_MAGIC_0;
        basura[BRANA_BASURA_OFF_BITS_MAGIC + 1] = (uint8_t)BRANA_BASURA_MAGIC_1;
    }

    if (Basura_Relleno_Final > 0LL)
    {
        _write(fdOut, basura.data(), static_cast<size_t>(Basura_Relleno_Final));
    }


#ifdef _WIN32
    _commit(fdOut);
#else
    fsync(fdOut);
#endif

    uint64_t posicionPostBasura = _lseeki64(fdOut, 0, SEEK_CUR);

#ifdef _WIN32
    _commit(fdOut);
#else
    fsync(fdOut);
#endif

    uint64_t Total_Bytes_Brana = _lseeki64(fdOut, 0, SEEK_END);
    uint64_t Bytes_Header = (Total_Bytes_Brana < (ZONA_header * 2ULL)) ? ZONA_header : ZONA_header;
    if (Bytes_Header > Total_Bytes_Brana)
        Bytes_Header = Total_Bytes_Brana;
    std::vector<uint8_t> bufferCierre(Bytes_Header);
    _lseeki64(fdOut, 0, SEEK_SET);
    int64_t Bytes_Leidos_Cierre = _read(fdOut, bufferCierre.data(), static_cast<size_t>(Bytes_Header));

    if (Bytes_Leidos_Cierre > 0LL)
    {
        Aplicar_Torsion_Principal(bufferCierre, Total_Bytes_Brana);
        _lseeki64(fdOut, 0, SEEK_SET);
        _write(fdOut, bufferCierre.data(), static_cast<size_t>(Bytes_Leidos_Cierre));
#ifdef _WIN32
        _commit(fdOut);
#else
        fsync(fdOut);
#endif
    }

    if (Total_Bytes_Brana > (Bytes_Header + 128ULL))
    {
        uint64_t Espacio_Restante = Total_Bytes_Brana - Bytes_Header;
        uint64_t BytesALeerFaro = (Espacio_Restante < ZONA_faro) ? ZONA_header : ZONA_faro;

        if (BytesALeerFaro > Espacio_Restante)
            BytesALeerFaro = Espacio_Restante;
        _lseeki64(fdOut, -static_cast<int64_t>(BytesALeerFaro), SEEK_END);

        std::vector<uint8_t> bufferFaro(BytesALeerFaro);
        int64_t Bytes_Leidos_Faro = _read(fdOut, bufferFaro.data(), static_cast<size_t>(BytesALeerFaro));

        if (Bytes_Leidos_Faro > 0)
        {
            Aplicar_Torsion_Principal(bufferFaro, Total_Bytes_Brana);
            _lseeki64(fdOut, -static_cast<int64_t>(Bytes_Leidos_Faro), SEEK_END);
            _write(fdOut, bufferFaro.data(), static_cast<size_t>(Bytes_Leidos_Faro));
#ifdef _WIN32
            _commit(fdOut);
#else
            fsync(fdOut);
#endif
        }

        if (Total_Bytes_Brana > UMBRAL_CUANTICO)
        {
            uint64_t EspacioLibreCentro = Total_Bytes_Brana - Bytes_Header - BytesALeerFaro;

            if (EspacioLibreCentro > ZONA_media)
            {
                uint64_t SemillaPos = (Total_Bytes_Brana ^ LAMBDA);
                uint64_t Porcentaje = 15ULL + (SemillaPos % 60ULL);
                uint64_t Ubicacion_Cuantica_Real = (Total_Bytes_Brana * Porcentaje) / 100ULL;

                if (Ubicacion_Cuantica_Real < Bytes_Header)
                {
                    Ubicacion_Cuantica_Real = Bytes_Header + 1024ULL;
                }
                if (Ubicacion_Cuantica_Real + ZONA_media > (Total_Bytes_Brana - BytesALeerFaro))
                {
                    Ubicacion_Cuantica_Real = (Total_Bytes_Brana - BytesALeerFaro) - ZONA_media - 1024ULL;
                }

                _lseeki64(fdOut, Ubicacion_Cuantica_Real, SEEK_SET);
                std::vector<uint8_t> bufferMedia(ZONA_media);
                int64_t B_Leidos_Z_Media = _read(fdOut, bufferMedia.data(), static_cast<size_t>(ZONA_media));

                if (B_Leidos_Z_Media > 0)
                {
                    Aplicar_Torsion_Principal(bufferMedia, Total_Bytes_Brana);
                    _lseeki64(fdOut, Ubicacion_Cuantica_Real, SEEK_SET);
                    _write(fdOut, bufferMedia.data(), static_cast<size_t>(B_Leidos_Z_Media));
#ifdef _WIN32
                    _commit(fdOut);
#else
                    fsync(fdOut);
#endif
                }
            }
        }
    }
#ifdef _WIN32
    _commit(fdOut);
#else
    fsync(fdOut);
#endif

#ifdef _WIN32
    UnlockFileEx(hOut, 0, 0, 0xFFFFFFFF, &ovOut);
    UnlockFileEx(hFile, 0, 0, 0xFFFFFFFF, &ovIn);
#else
    flock(fdOut, LOCK_UN);
#endif

    _close(fdOut);
    cout << "\n[*] Salida: " << Nombre_Salida << endl;
    _close(fdIn);
           Limpiar_Dir_Temporal();

    bool entrada_es_carpeta =
        (lista_entrada.size() == 1 && Es_Directorio(lista_entrada[0]));

    if (entrada_es_carpeta)
    {
        if (flag_wipe || !modo_cli)
        {
            if (flag_wipe)
                cout << "[*] Borrado seguro omitido (entrada tipo carpeta) "
                        "(no se borran arboles enteros en esta version).\n";
        }
    }
    else
    {
        bool hacer_wipe = false;

        if (modo_cli)
        {
            hacer_wipe = flag_wipe;
        }
        else
        {
            cout << "\n========================================\n";
            cout << " ELIMINAR ORIGINALES (wipe)\n";
            cout << " Se sobrescribira y borrara cada archivo de entrada.\n";
            cout << " Archivos grandes: puede TARDAR varios minutos.\n";
            cout << " Esta accion NO se puede deshacer.\n";
            cout << " El archivo cifrado NO se borra.\n";
            cout << "========================================\n";
            cout << "Eliminar originales? (S/N): ";
            char r = 'N';
            cin >> r;
            cin.ignore(1024, '\n');
            hacer_wipe = (toupper(static_cast<unsigned char>(r)) == 'S');
        }

        if (hacer_wipe)
        {
            cout << "\n[*] Borrado seguro de "
                 << lista_entrada.size() << " archivo(s)...\n";
            for (size_t i = 0; i < lista_entrada.size(); ++i)
            {
                cout << "    (" << (i + 1) << "/" << lista_entrada.size()
                     << ") " << lista_entrada[i] << "\n";
                if (Wipe_Archivo(lista_entrada[i]))
                    cout << "[*] Eliminado: " << lista_entrada[i] << "\n";
                else
                    cerr << "[!] No se pudo eliminar: " << lista_entrada[i] << "\n";
            }
            cout << "[*] Borrado seguro terminado.\n";
        }
    }

}

