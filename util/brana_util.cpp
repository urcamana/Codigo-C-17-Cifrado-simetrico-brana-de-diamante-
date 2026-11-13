/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */

#include "util/brana_util.h"
#include "crypto/brana_crypto.h"
#include <iomanip>
#include <vector>
#include <iostream>
#include <cstring>
#include <fstream>
#include <algorithm>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstdio>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <direct.h>
#include <sys/stat.h>
#ifndef _S_IREAD
#define _S_IREAD 0x0100
#endif
#ifndef _S_IWRITE
#define _S_IWRITE 0x0080
#endif
#define Brana_Mkdir(path) _mkdir(path)
#else
#include <dirent.h>
#include <unistd.h>
#include <sys/file.h>
#define Brana_Mkdir(path) mkdir(path, 0700)
#define _read(fd, buf, count) read(fd, buf, count)
#define _write(fd, buf, count) write(fd, buf, count)
#define _close(fd) close(fd)
#define _lseeki64(fd, offset, origin) lseek(fd, offset, origin)
#define _commit(fd) fsync(fd)
#endif

using namespace std;

string Dir_Temporal;
string path_bulk_intermedio;
string path_ov_intermedio;

bool Clave_Cumple_Politica(const string &clave, string &motivo)
{
    if (clave.length() < 8)
    {
        motivo = "debe tener al menos 8 caracteres";
        return false;
    }
    bool may = false, min = false, dig = false, sim = false;
    for (size_t i = 0; i < clave.length(); i++)
    {
        unsigned char c = static_cast<unsigned char>(clave[i]);
        if (c >= 'A' && c <= 'Z') may = true;
        else if (c >= 'a' && c <= 'z') min = true;
        else if (c >= '0' && c <= '9') dig = true;
        else sim = true;
    }
    if (!may) { motivo = "debe incluir al menos una mayuscula (A-Z)"; return false; }
    if (!min) { motivo = "debe incluir al menos una minuscula (a-z)"; return false; }
    if (!dig) { motivo = "debe incluir al menos un digito (0-9)"; return false; }
    if (!sim) { motivo = "debe incluir al menos un simbolo (ej: !@#$%)"; return false; }
    return true;
}

#include "pool/brana_pool.hpp"
static ThreadPool g_Pool;

void Mostrar_Ayuda_Encriptador()
{
    cout << "Brana de Diamante - Encriptador\n\n"
         << "Uso:\n"
         << "  Interactivo:  encriptador\n"
         << "  CLI:          encriptador -i <entrada> -u <usuario> -p <clave> [opciones]\n\n"
         << "Entrada / salida:\n"
         << "  -i <ruta>     Archivo, carpeta o varios (repetible: -i a -i b)\n"
         << "  -o <ruta>     Nombre de salida (se agrega .brana si falta)\n\n"
         << "Credenciales:\n"
         << "  -u <usuario>  Usuario (obligatorio en CLI)\n"
         << "  -p <clave>    Clave (obligatorio en CLI; min. 8;\n"
         << "                mayuscula, minuscula, digito y simbolo)\n"
         << "  -s <8 chars>  Clave senuelo / panico (opcional; exactamente 8)\n\n"
         << "Opciones:\n"
         << "  -m <1-5>      Intensidad (1=rapido ... 5=lento; defecto 3)\n"
         << "  -k <0-2>      Esfuerzo al derivar la clave (0=rapido, 1=normal, 2=alto;\n"
         << "                defecto 1)\n"
         << "  -y            Comprimir antes de cifrar cuando convenga (sin preguntar)\n"
         << "                (alias: --yes-compress)\n"
         << "  -w            Tras cifrar, borrar de forma segura los archivos de entrada\n"
         << "                (alias: --wipe; no aplica si la entrada es una carpeta)\n"
         << "  -h            Esta ayuda (alias: --help)\n\n"
         << "Ejemplos:\n"
         << "  encriptador -i doc.pdf -u ana -p \"Clave1!x\" -m 3\n"
         << "  encriptador -i carpeta -u ana -p \"Clave1!x\" -o respaldo -y\n"
         << "  encriptador -i a.txt -i b.txt -u ana -p \"Clave1!x\" -w\n";
}

string Solo_Nombre(const string &path)
{
    size_t p = path.find_last_of("/\\");
    if (p == string::npos) return path;
    return path.substr(p + 1);
}

bool Es_Directorio(const string &path)
{
#ifdef _WIN32
    DWORD att = GetFileAttributesA(path.c_str());
    return (att != INVALID_FILE_ATTRIBUTES) &&
           (att & FILE_ATTRIBUTE_DIRECTORY);
#else
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return false;
    return S_ISDIR(st.st_mode);
#endif
}

void Listar_Archivos_Recursivo(const string &dir, const string &prefijo,
                               std::vector<string> &out_paths,
                               std::vector<string> &out_nombres_rel)
{
#ifdef _WIN32
    string patron = dir;
    if (!patron.empty() && patron.back() != '\\' && patron.back() != '/')
        patron += '\\';
    patron += "*";

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(patron.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;

    do {
        string name = fd.cFileName;
        if (name == "." || name == "..")
            continue;

        string full = dir;
        if (!full.empty() && full.back() != '\\' && full.back() != '/')
            full += '\\';
        full += name;

        string rel = prefijo.empty() ? name : (prefijo + "\\" + name);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            Listar_Archivos_Recursivo(full, rel, out_paths, out_nombres_rel);
        }
        else
        {
            out_paths.push_back(full);
            out_nombres_rel.push_back(rel);
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR *d = opendir(dir.c_str());
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d)) != nullptr)
    {
        string name = ent->d_name;
        if (name == "." || name == "..") continue;

        string full = dir;
        if (!full.empty() && full.back() != '/') full += '/';
        full += name;

        string rel = prefijo.empty() ? name : (prefijo + "/" + name);

        if (Es_Directorio(full))
            Listar_Archivos_Recursivo(full, rel, out_paths, out_nombres_rel);
        else
        {
            out_paths.push_back(full);
            out_nombres_rel.push_back(rel);
        }
    }
    closedir(d);
#endif
}

bool Listar_Archivos_En_Carpeta(const string &dir, std::vector<string> &out)
{
    out.clear();
    std::vector<string> nombres;
    Listar_Archivos_Recursivo(dir, "", out, nombres);
    return !out.empty();
}

string Nombre_Base_Carpeta(const string &dir)
{
    string s = dir;
    while (!s.empty() && (s.back() == '/' || s.back() == '\\'))
        s.pop_back();
    size_t p = s.find_last_of("/\\");
    if (p == string::npos) return s.empty() ? string("carpeta") : s;
    return s.substr(p + 1);
}

string Crear_Dir_Temporal()
{

    uint64_t t = static_cast<uint64_t>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count());
#ifdef _WIN32
    string dir = "brana_tmp_" + std::to_string(t % 1000000000ULL);
#else
    string dir = "brana_tmp_" + std::to_string(t % 1000000000ULL);
#endif

    if (Brana_Mkdir(dir.c_str()) != 0)
    {

        dir += "_2";
        if (Brana_Mkdir(dir.c_str()) != 0)
            return string();
    }

#ifdef _WIN32
    SetFileAttributesA(dir.c_str(), FILE_ATTRIBUTE_HIDDEN);
#endif
    return dir;
}

void Borrar_Archivo_Si_Existe(const string &path)
{
    if (path.empty()) return;
#ifdef _WIN32
    _unlink(path.c_str());
#else
    unlink(path.c_str());
#endif
}

void Limpiar_Dir_Temporal()
{
    Borrar_Archivo_Si_Existe(path_ov_intermedio);
    Borrar_Archivo_Si_Existe(path_bulk_intermedio);
    path_ov_intermedio.clear();
    path_bulk_intermedio.clear();

    if (Dir_Temporal.empty()) return;

#ifdef _WIN32
    SetFileAttributesA(Dir_Temporal.c_str(), FILE_ATTRIBUTE_NORMAL);

    string comodin = Dir_Temporal + "\\*.*";
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(comodin.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            string fname = fd.cFileName;
            if (fname != "." && fname != "..") {
                string ffull = Dir_Temporal + "\\" + fname;
                SetFileAttributesA(ffull.c_str(), FILE_ATTRIBUTE_NORMAL);
                _unlink(ffull.c_str());
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }

    _rmdir(Dir_Temporal.c_str());
#else
    rmdir(Dir_Temporal.c_str());
#endif
    Dir_Temporal.clear();
}

string Path_En_Temp(const string &nombre)
{
    if (Dir_Temporal.empty())
        return nombre;
#ifdef _WIN32
    return Dir_Temporal + "\\" + nombre;
#else
    return Dir_Temporal + "/" + nombre;
#endif
}


void Mostrar_Ayuda_Desencriptador()
{
    cout << "Brana de Diamante - Desencriptador\n\n"
         << "Uso:\n"
         << "  Interactivo:  desencriptador\n"
         << "  CLI:          desencriptador -i <archivo.brana> -u <usuario> -p <clave>\n"
         << "  Verificar:    desencriptador -v -i <archivo.brana>\n\n"
         << "Opciones:\n"
         << "  -i <ruta>     Archivo .brana (obligatorio en CLI)\n"
         << "  -u <usuario>  Usuario (obligatorio salvo -v)\n"
         << "  -p <clave>    Clave (obligatorio salvo -v)\n"
         << "  -v            Solo comprobar si parece un contenedor valido\n"
         << "                (solo lectura; sin clave; no modifica el archivo)\n"
         << "  -h            Esta ayuda (alias: --help, -ayuda, --ayuda)\n\n"
         << "Notas:\n"
         << "  - El descifrado modifica el archivo .brana en el proceso.\n"
         << "  - Conviene tener una copia de respaldo antes de continuar.\n"
         << "  - Ejemplo: desencriptador -i doc.pdf.brana -u ana -p \"Clave1!x\"\n";
}

#include <thread>
#include <algorithm>
#include <fstream>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/sysinfo.h>
#include <sys/resource.h>
#endif

static const double FACTOR_SEGURIDAD = 0.80;
static const int64_t HILOS_DEFAULT = 4LL;
static const uint64_t SEGMENTO_DEFAULT = 1024ULL * 1024ULL;

size_t Verificar_Ram_Libre()
{
#if defined(_WIN32) || defined(_WIN64)
    MEMORYSTATUSEX estado;
    estado.dwLength = sizeof(estado);
    if (GlobalMemoryStatusEx(&estado))
        return static_cast<size_t>(estado.ullAvailPhys);
#elif defined(__linux__) || defined(__gnu_linux__)
    struct sysinfo info;
    if (sysinfo(&info) == 0)
        return static_cast<size_t>((info.freeram + info.bufferram) * info.mem_unit);
#endif
    return 0;
}

int64_t Optimizar_Hilos_CPU(uint64_t Tam_Segm_Fijo)
{
    int64_t Total_Hilos_CPU = static_cast<int64_t>(std::thread::hardware_concurrency());
    if (Total_Hilos_CPU <= 0LL)
        Total_Hilos_CPU = HILOS_DEFAULT;
    int64_t RAM_Disponible = static_cast<int64_t>(Verificar_Ram_Libre());
    if (RAM_Disponible <= 0LL)
        return (std::min)(Total_Hilos_CPU, static_cast<int64_t>(4));
    int64_t RAM_MAX_permitida = static_cast<int64_t>(static_cast<double>(RAM_Disponible) * FACTOR_SEGURIDAD);
    if (Tam_Segm_Fijo == 0ULL) Tam_Segm_Fijo = SEGMENTO_DEFAULT;
    int64_t hilosPorRam = RAM_MAX_permitida / static_cast<int64_t>(Tam_Segm_Fijo);
    int64_t Hilos_Finales = (std::min)(Total_Hilos_CPU, hilosPorRam);
    return (std::max)(Hilos_Finales, static_cast<int64_t>(1));
}

float Obtener_Frecuencia_Cpu()
{
#ifdef _WIN32
    HKEY hKey;
    DWORD MHz = 0;
    DWORD size = sizeof(MHz);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        if (RegQueryValueExA(hKey, "~MHz", NULL, NULL, (LPBYTE)&MHz, &size) == ERROR_SUCCESS)
        {
            RegCloseKey(hKey);
            return static_cast<float>(MHz) / 1000.0f;
        }
        RegCloseKey(hKey);
    }
    return 0.0f;
#else
    std::ifstream max_freq_file("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq");
    if (max_freq_file.is_open()) {
        std::string val;
        std::getline(max_freq_file, val);
        try { return std::stof(val) / 1000000.0f; } catch (...) { return 0.0f; }
    }
    return 0.0f;
#endif
}

void Optimizar_Sistema()
{
#ifdef _WIN32
    PROCESS_POWER_THROTTLING_STATE powerThrottling = {};
    powerThrottling.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
    powerThrottling.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
    powerThrottling.StateMask = 0;
    SetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling, &powerThrottling, sizeof(powerThrottling));
#else
    setpriority(PRIO_PROCESS, 0, -20);
#endif
}

bool Bloquear_Archivo(int fd)
{
#ifdef _WIN32
    HANDLE hFile = (HANDLE)_get_osfhandle(fd);
    OVERLAPPED ov = {0};
    return LockFileEx(hFile, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 0xFFFFFFFF, 0xFFFFFFFF, &ov) != 0;
#else
    return ::flock(fd, LOCK_EX | LOCK_NB) == 0;
#endif
}

void Desbloquear_Archivo(int fd)
{
#ifdef _WIN32
    HANDLE hFile = (HANDLE)_get_osfhandle(fd);
    OVERLAPPED ov = {0};
    UnlockFileEx(hFile, 0, 0xFFFFFFFF, 0xFFFFFFFF, &ov);
#else
    ::flock(fd, LOCK_UN);
#endif
}

uint64_t Calcular_Longitud_Relleno(uint64_t Control_Semilla, uint64_t CRC_Control)
{
    uint64_t SemillaArchivo = Control_Semilla ^ CRC_Control;
    return 56ULL + (SemillaArchivo % 9ULL);
}

bool Wipe_Archivo(const std::string &path)
{
    const uint64_t UMBRAL_PROGRESO = 8ULL * 1024ULL * 1024ULL;
    const size_t BUF = 4ULL * 1024ULL * 1024ULL;
    int fd = -1;
#ifdef _WIN32
    fd = _open(path.c_str(), _O_RDWR | _O_BINARY);
#else
    fd = open(path.c_str(), O_RDWR);
#endif
    if (fd < 0)
        return false;

    int64_t total = _lseeki64(fd, 0, SEEK_END);
    if (total < 0)
    {
        _close(fd);
        return false;
    }
    _lseeki64(fd, 0, SEEK_SET);

    std::vector<uint8_t> buf(BUF);
    uint64_t estado = Generador_String(path) ^ LAMBDA ^ static_cast<uint64_t>(total);

    uint64_t left = static_cast<uint64_t>(total);
    uint64_t done = 0;
    while (left > 0)
    {
        size_t n = static_cast<size_t>(left > BUF ? BUF : left);
        for (size_t i = 0; i < n; ++i)
        {
            estado = Actualizar_Siguiente_Estado(estado);
            buf[i] = static_cast<uint8_t>(estado & 0xFFULL);
        }
        if (_write(fd, buf.data(), static_cast<unsigned int>(n)) != static_cast<int64_t>(n))
        {
            _close(fd);
            return false;
        }
        left -= n;
        done += n;
        if (total > static_cast<int64_t>(UMBRAL_PROGRESO))
        {
            double pct = 100.0 * (double)done / (double)total;
            std::cout << "\r[WIPE] Sobrescribiendo: " << std::fixed << std::setprecision(1)
                 << pct << "% (" << (done / (1024 * 1024)) << " / "
                 << (static_cast<uint64_t>(total) / (1024 * 1024)) << " MB)" << std::flush;
        }
    }
#ifdef _WIN32
    _commit(fd);
#else
    fsync(fd);
#endif
    _close(fd);

    if (total > static_cast<int64_t>(UMBRAL_PROGRESO))
        std::cout << "\n";

#ifdef _WIN32
    return (_unlink(path.c_str()) == 0);
#else
    return (unlink(path.c_str()) == 0);
#endif
}
