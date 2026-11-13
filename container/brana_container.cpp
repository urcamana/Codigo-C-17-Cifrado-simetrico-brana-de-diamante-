/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */

#include "container/brana_container.h"
#include "util/brana_util.h"
#ifndef MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#endif
#include "miniz.h"
#include <iostream>
#include <cstring>
#include <vector>
#include <string>
#include <fcntl.h>
#include <cstdio>
#include <iomanip>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <sys/stat.h>
#ifndef _S_IREAD
#define _S_IREAD  0x0100
#endif
#ifndef _S_IWRITE
#define _S_IWRITE 0x0080
#endif
#else
#include <unistd.h>
#define _read(fd, buf, count) read(fd, buf, count)
#define _write(fd, buf, count) write(fd, buf, count)
#define _close(fd) close(fd)
#define _lseeki64(fd, offset, origin) lseek(fd, offset, origin)
#endif

using namespace std;

static const char OV_MAGIC[8] = { 'O','V','I','L','L','O','0','1' };
static const char BULK_MAGIC[8] = { 'B','U','L','K','0','0','0','1' };
const size_t BULK_IO_BUF = 4ULL * 1024ULL * 1024ULL;
const size_t OV_IO_BUF = 4ULL * 1024ULL * 1024ULL;
const double UMBRAL_ENTROPIA_OV = 7.5;
const size_t MUESTRA_ENTROPIA_MAX = 256 * 1024;
const uint64_t UMBRAL_PROGRESO = 8ULL * 1024ULL * 1024ULL;


#include <cmath>
#define CONTADOR_ENTROPIA_MAXIMA 65536ULL
static double TABLA_ENTROPIA_C[CONTADOR_ENTROPIA_MAXIMA];
static bool Tabla_Entropia_Lista = false;
static void Inicializar_TABLA_ENTROPIA_C()
{
    for (int64_t i = 1; i < (int64_t)CONTADOR_ENTROPIA_MAXIMA; i++)
        TABLA_ENTROPIA_C[i] = static_cast<double>(i) * log2(static_cast<double>(i));
    TABLA_ENTROPIA_C[0] = 0.0;
    Tabla_Entropia_Lista = true;
}
static double Calcular_Entropia_Shannon(const uint8_t *datos, size_t tam)
{
    if (tam == 0) return 0.0;
    if (!Tabla_Entropia_Lista) Inicializar_TABLA_ENTROPIA_C();
    unsigned long counts[256] = {0};
    for (size_t i = 0; i < tam; i++) counts[datos[i]]++;
    double suma_n_log_n = 0.0;
    double N = static_cast<double>(tam);
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            if (counts[i] < CONTADOR_ENTROPIA_MAXIMA)
                suma_n_log_n += TABLA_ENTROPIA_C[counts[i]];
            else {
                double c = static_cast<double>(counts[i]);
                suma_n_log_n += c * log2(c);
            }
        }
    }
    return log2(N) - (suma_n_log_n / N);
}

double Entropia_Shannon(const string &path)
{
    int fd = -1;
#ifdef _WIN32
    fd = _open(path.c_str(), _O_RDONLY | _O_BINARY);
#else
    fd = open(path.c_str(), O_RDONLY);
#endif
    if (fd < 0)
        return 8.0;

    int64_t total = _lseeki64(fd, 0, SEEK_END);
    if (total <= 0)
    {
        _close(fd);
        return 8.0;
    }

    size_t a_leer = static_cast<size_t>(
        (total < static_cast<int64_t>(MUESTRA_ENTROPIA_MAX))
            ? total
            : static_cast<int64_t>(MUESTRA_ENTROPIA_MAX));

    std::vector<uint8_t> buf(a_leer);
    _lseeki64(fd, 0, SEEK_SET);
    int64_t n = _read(fd, buf.data(), static_cast<unsigned int>(a_leer));
    _close(fd);
    if (n <= 0)
        return 8.0;

    return Calcular_Entropia_Shannon(buf.data(), static_cast<size_t>(n));
}

bool Entropia_Es_Alta(const string &path)
{
    return Entropia_Shannon(path) >= UMBRAL_ENTROPIA_OV;
}

bool Comprimir_Buffer(const uint8_t *in, size_t in_len,
                      std::vector<uint8_t> &out, int nivel)
{
    if (in == nullptr || in_len == 0)
        return false;

    mz_ulong bound = mz_compressBound(static_cast<mz_ulong>(in_len));
    out.resize(static_cast<size_t>(bound));
    mz_ulong out_len = bound;

    int st = mz_compress2(out.data(), &out_len,
                          in, static_cast<mz_ulong>(in_len),
                          nivel);
    if (st != MZ_OK)
    {
        out.clear();
        return false;
    }
    out.resize(static_cast<size_t>(out_len));
    return true;
}

bool Descomprimir_Buffer(const uint8_t *in, size_t in_len,
                         std::vector<uint8_t> &out, size_t size_orig)
{
    if (in == nullptr || in_len == 0 || size_orig == 0)
        return false;

    out.resize(size_orig);
    mz_ulong out_len = static_cast<mz_ulong>(size_orig);
    int st = mz_uncompress(out.data(), &out_len,
                           in, static_cast<mz_ulong>(in_len));
    if (st != MZ_OK || out_len != static_cast<mz_ulong>(size_orig))
    {
        out.clear();
        return false;
    }
    return true;
}

bool Crear_Archivo_OV(const string &path_in, const string &path_ov)
{
    int fdIn = -1;
#ifdef _WIN32
    fdIn = _open(path_in.c_str(), _O_RDONLY | _O_BINARY);
#else
    fdIn = open(path_in.c_str(), O_RDONLY);
#endif
    if (fdIn < 0)
        return false;

    int64_t total = _lseeki64(fdIn, 0, SEEK_END);
    if (total <= 0)
    {
        _close(fdIn);
        return false;
    }
    uint64_t size_orig = static_cast<uint64_t>(total);
    _lseeki64(fdIn, 0, SEEK_SET);

    int fdOut = -1;
#ifdef _WIN32
    fdOut = _open(path_ov.c_str(),
                  _O_RDWR | _O_CREAT | _O_TRUNC | _O_BINARY,
                  _S_IREAD | _S_IWRITE);
#else
    fdOut = open(path_ov.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
#endif
    if (fdOut < 0)
    {
        _close(fdIn);
        return false;
    }

    uint64_t size_comp = 0;
    uint32_t crc32_out = 0;
    bool ok = true;
    if (_write(fdOut, OV_MAGIC, 8) != 8) ok = false;
    if (ok && _write(fdOut, &size_orig, 8) != 8) ok = false;
    if (ok && _write(fdOut, &size_comp, 8) != 8) ok = false;
    if (ok && _write(fdOut, &crc32_out, 4) != 4) ok = false;
    if (!ok)
    {
        _close(fdIn);
        _close(fdOut);
#ifdef _WIN32
        _unlink(path_ov.c_str());
#else
        unlink(path_ov.c_str());
#endif
        return false;
    }

    mz_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (mz_deflateInit(&strm, 6) != MZ_OK)
    {
        _close(fdIn);
        _close(fdOut);
#ifdef _WIN32
        _unlink(path_ov.c_str());
#else
        unlink(path_ov.c_str());
#endif
        return false;
    }

    std::vector<uint8_t> inbuf(OV_IO_BUF);
    std::vector<uint8_t> outbuf(OV_IO_BUF);
    mz_ulong crc = MZ_CRC32_INIT;
    uint64_t leidos = 0;
    bool got_stream_end = false;

    while (ok && leidos < size_orig)
    {
        size_t chunk = static_cast<size_t>(
            ((size_orig - leidos) > OV_IO_BUF) ? OV_IO_BUF : (size_orig - leidos));
        int64_t n = _read(fdIn, inbuf.data(), static_cast<unsigned int>(chunk));
        if (n <= 0)
        {
            ok = false;
            break;
        }
        crc = mz_crc32(crc, inbuf.data(), static_cast<size_t>(n));
        leidos += static_cast<uint64_t>(n);

        if (size_orig > 8ULL * 1024ULL * 1024ULL)
        {
            double pct = 100.0 * (double)leidos / (double)size_orig;
            cout << "\r[OV] Comprimiendo: " << fixed << setprecision(1)
                 << pct << "% (" << (leidos / (1024 * 1024)) << " / "
                 << (size_orig / (1024 * 1024)) << " MB)" << std::flush;
        }

        strm.next_in = inbuf.data();
        strm.avail_in = static_cast<unsigned int>(n);
        int flush_mode = (leidos >= size_orig) ? MZ_FINISH : MZ_NO_FLUSH;


        do
        {
            strm.next_out = outbuf.data();
            strm.avail_out = static_cast<unsigned int>(outbuf.size());
            int st = mz_deflate(&strm, flush_mode);
            if (st == MZ_STREAM_ERROR)
            {
                ok = false;
                break;
            }
            size_t have = outbuf.size() - strm.avail_out;
            if (have > 0)
            {
                if (_write(fdOut, outbuf.data(), static_cast<unsigned int>(have)) !=
                    static_cast<int64_t>(have))
                {
                    ok = false;
                    break;
                }
                size_comp += static_cast<uint64_t>(have);
            }
            if (st == MZ_STREAM_END)
            {
                got_stream_end = true;
                break;
            }
        } while (ok && (strm.avail_in > 0 ||
                        (flush_mode == MZ_FINISH && !got_stream_end)));
    }


    while (ok && !got_stream_end)
    {
        strm.next_out = outbuf.data();
        strm.avail_out = static_cast<unsigned int>(outbuf.size());
        int st = mz_deflate(&strm, MZ_FINISH);
        if (st == MZ_STREAM_ERROR)
        {
            ok = false;
            break;
        }
        size_t have = outbuf.size() - strm.avail_out;
        if (have > 0)
        {
            if (_write(fdOut, outbuf.data(), static_cast<unsigned int>(have)) !=
                static_cast<int64_t>(have))
            {
                ok = false;
                break;
            }
            size_comp += static_cast<uint64_t>(have);
        }
        if (st == MZ_STREAM_END)
        {
            got_stream_end = true;
            break;
        }
        if (have == 0 && st != MZ_OK)
        {
            ok = false;
            break;
        }
    }

    mz_deflateEnd(&strm);
    _close(fdIn);

    if (size_orig > 8ULL * 1024ULL * 1024ULL)
        cout << "\n";

    if (!ok || leidos != size_orig || !got_stream_end)
    {
        _close(fdOut);
#ifdef _WIN32
        _unlink(path_ov.c_str());
#else
        unlink(path_ov.c_str());
#endif
        return false;
    }

    if (size_comp >= size_orig)
    {
        _close(fdOut);
#ifdef _WIN32
        _unlink(path_ov.c_str());
#else
        unlink(path_ov.c_str());
#endif
        return false;
    }

    crc32_out = static_cast<uint32_t>(crc);
    _lseeki64(fdOut, 16, SEEK_SET);
    if (_write(fdOut, &size_comp, 8) != 8) ok = false;
    if (ok && _write(fdOut, &crc32_out, 4) != 4) ok = false;
#ifdef _WIN32
    _commit(fdOut);
#endif
    _close(fdOut);
    if (!ok)
    {
#ifdef _WIN32
        _unlink(path_ov.c_str());
#else
        unlink(path_ov.c_str());
#endif
        return false;
    }
    return true;
}

bool Leer_Archivo_Completo(const string &path, std::vector<uint8_t> &out)
{
    int fd = -1;
#ifdef _WIN32
    fd = _open(path.c_str(), _O_RDONLY | _O_BINARY);
#else
    fd = open(path.c_str(), O_RDONLY);
#endif
    if (fd < 0) return false;
    int64_t total = _lseeki64(fd, 0, SEEK_END);
    if (total < 0) { _close(fd); return false; }

    const int64_t CAP = 64LL * 1024LL * 1024LL;
    int64_t a_leer = total > CAP ? CAP : total;
    out.resize(static_cast<size_t>(a_leer));
    _lseeki64(fd, 0, SEEK_SET);
    int64_t got = 0;
    while (got < a_leer)
    {
        size_t chunk = static_cast<size_t>(
            ((a_leer - got) > (4LL * 1024 * 1024)) ? (4ULL * 1024 * 1024)
                                                   : (size_t)(a_leer - got));
        int64_t n = _read(fd, out.data() + got, static_cast<unsigned int>(chunk));
        if (n <= 0) { _close(fd); return false; }
        got += n;
    }
    _close(fd);
    return true;
}


bool Crear_Archivo_BULK(const std::vector<string> &paths,
                        const std::vector<string> &nombres_rel,
                        const string &path_bulk)
{
    if (paths.empty() || paths.size() != nombres_rel.size())
        return false;

    struct Meta {
        string name;
        uint64_t size;
        uint32_t crc32;
    };
    std::vector<Meta> metas;
    metas.reserve(paths.size());


    std::vector<uint8_t> buf(BULK_IO_BUF);

    for (size_t i = 0; i < paths.size(); ++i)
    {
        Meta m;
        m.name = nombres_rel[i];
        if (m.name.empty() || m.name.size() > 65535)
            return false;
        for (size_t k = 0; k < m.name.size(); ++k)
            if (m.name[k] == '\\') m.name[k] = '/';

        int fd = -1;
#ifdef _WIN32
        fd = _open(paths[i].c_str(), _O_RDONLY | _O_BINARY);
#else
        fd = open(paths[i].c_str(), O_RDONLY);
#endif
        if (fd < 0)
            return false;

        int64_t total = _lseeki64(fd, 0, SEEK_END);
        if (total < 0) { _close(fd); return false; }
        m.size = static_cast<uint64_t>(total);
        _lseeki64(fd, 0, SEEK_SET);

        mz_ulong crc = MZ_CRC32_INIT;
        uint64_t rest = m.size;
        while (rest > 0)
        {
            size_t chunk = static_cast<size_t>(
                (rest > BULK_IO_BUF) ? BULK_IO_BUF : rest);
            int64_t n = _read(fd, buf.data(), static_cast<unsigned int>(chunk));
            if (n <= 0) { _close(fd); return false; }
            crc = mz_crc32(crc, buf.data(), static_cast<size_t>(n));
            rest -= static_cast<uint64_t>(n);
        }
        _close(fd);
        m.crc32 = static_cast<uint32_t>(crc);
        metas.push_back(std::move(m));
    }


    int fdOut = -1;
#ifdef _WIN32
    fdOut = _open(path_bulk.c_str(),
                  _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY,
                  _S_IREAD | _S_IWRITE);
#else
    fdOut = open(path_bulk.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
#endif
    if (fdOut < 0) return false;

    bool ok = true;
    if (_write(fdOut, BULK_MAGIC, 8) != 8) ok = false;
    uint32_t ver = 1;
    uint32_t n = static_cast<uint32_t>(metas.size());
    if (ok && _write(fdOut, &ver, 4) != 4) ok = false;
    if (ok && _write(fdOut, &n, 4) != 4) ok = false;

    for (size_t i = 0; i < metas.size() && ok; ++i)
    {
        uint16_t nl = static_cast<uint16_t>(metas[i].name.size());
        if (_write(fdOut, &nl, 2) != 2) ok = false;
        if (ok && _write(fdOut, metas[i].name.data(), nl) != (int)nl) ok = false;
        if (ok && _write(fdOut, &metas[i].size, 8) != 8) ok = false;
        if (ok && _write(fdOut, &metas[i].crc32, 4) != 4) ok = false;
    }


    for (size_t i = 0; i < paths.size() && ok; ++i)
    {
        if (metas[i].size == 0)
            continue;

        cout << "[BULK] (" << (i + 1) << "/" << paths.size() << ") "
             << nombres_rel[i] << "\n";

        int fdIn = -1;
#ifdef _WIN32
        fdIn = _open(paths[i].c_str(), _O_RDONLY | _O_BINARY);
#else
        fdIn = open(paths[i].c_str(), O_RDONLY);
#endif
        if (fdIn < 0) { ok = false; break; }

        uint64_t rest = metas[i].size;
        while (rest > 0 && ok)
        {
            size_t chunk = static_cast<size_t>(
                (rest > BULK_IO_BUF) ? BULK_IO_BUF : rest);
            int64_t nread = _read(fdIn, buf.data(), static_cast<unsigned int>(chunk));
            if (nread <= 0) { ok = false; break; }
            if (_write(fdOut, buf.data(), static_cast<unsigned int>(nread)) != nread)
            { ok = false; break; }
            rest -= static_cast<uint64_t>(nread);

            if (metas[i].size > 8ULL * 1024ULL * 1024ULL)
            {
                uint64_t done = metas[i].size - rest;
                double pct = 100.0 * (double)done / (double)metas[i].size;
                cout << "\r[BULK]   " << fixed << setprecision(1) << pct << "%" << std::flush;
            }
        }
        if (metas[i].size > 8ULL * 1024ULL * 1024ULL)
            cout << "\n";
        _close(fdIn);
    }

    _close(fdOut);
    if (!ok)
    {
#ifdef _WIN32
        _unlink(path_bulk.c_str());
#else
        unlink(path_bulk.c_str());
#endif
    }
    return ok;
}

bool Crear_Archivo_BULK(const std::vector<string> &paths, const string &path_bulk)
{
    std::vector<string> nombres;
    for (size_t i = 0; i < paths.size(); ++i)
        nombres.push_back(Solo_Nombre(paths[i]));
    return Crear_Archivo_BULK(paths, nombres, path_bulk);
}

bool Extraer_OV(const string &path_in, string &path_out_generado)
{
    int fdIn = -1;
#ifdef _WIN32
    fdIn = _open(path_in.c_str(), _O_RDONLY | _O_BINARY);
#else
    fdIn = open(path_in.c_str(), O_RDONLY);
#endif
    if (fdIn < 0)
        return false;

    int64_t file_sz = _lseeki64(fdIn, 0, SEEK_END);
    if (file_sz < 28)
    {
        _close(fdIn);
        return false;
    }
    _lseeki64(fdIn, 0, SEEK_SET);

    char magic[8];
    if (_read(fdIn, magic, 8) != 8 || memcmp(magic, OV_MAGIC, 8) != 0)
    {
        _close(fdIn);
        return false;
    }

    uint64_t size_orig = 0, size_comp_hdr = 0;
    uint32_t crc_esp = 0;
    if (_read(fdIn, &size_orig, 8) != 8 ||
        _read(fdIn, &size_comp_hdr, 8) != 8 ||
        _read(fdIn, &crc_esp, 4) != 4)
    {
        _close(fdIn);
        return false;
    }
    if (size_orig == 0)
    {
        _close(fdIn);
        return false;
    }

    path_out_generado = path_in;
    if (path_out_generado.size() >= 3 &&
        path_out_generado.substr(path_out_generado.size() - 3) == ".ov")
        path_out_generado = path_out_generado.substr(0, path_out_generado.size() - 3);
    else
        path_out_generado = path_in + ".out";

    int fdOut = -1;
#ifdef _WIN32
    fdOut = _open(path_out_generado.c_str(),
                  _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY,
                  _S_IREAD | _S_IWRITE);
#else
    fdOut = open(path_out_generado.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
#endif
    if (fdOut < 0)
    {
        _close(fdIn);
        return false;
    }

    mz_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (mz_inflateInit(&strm) != MZ_OK)
    {
        _close(fdIn);
        _close(fdOut);
        return false;
    }

    std::vector<uint8_t> inbuf(OV_IO_BUF);
    std::vector<uint8_t> outbuf(OV_IO_BUF);
    mz_ulong crc = MZ_CRC32_INIT;
    uint64_t plain_written = 0;
    uint64_t comp_read = 0;
    bool ok = true;
    bool eof_in = false;
    bool got_stream_end = false;
    int last_st = MZ_OK;

    while (ok && !got_stream_end)
    {
        if (strm.avail_in == 0 && !eof_in)
        {
            int64_t n = _read(fdIn, inbuf.data(), static_cast<unsigned int>(OV_IO_BUF));
            if (n < 0)
            {
                ok = false;
                break;
            }
            if (n == 0)
                eof_in = true;
            else
            {
                strm.next_in = inbuf.data();
                strm.avail_in = static_cast<unsigned int>(n);
                comp_read += static_cast<uint64_t>(n);
            }
        }

        strm.next_out = outbuf.data();
        strm.avail_out = static_cast<unsigned int>(outbuf.size());
        int flush_mode = eof_in ? MZ_FINISH : MZ_NO_FLUSH;
        last_st = mz_inflate(&strm, flush_mode);

        size_t have = outbuf.size() - strm.avail_out;
        if (have > 0)
        {
            if (_write(fdOut, outbuf.data(), static_cast<unsigned int>(have)) !=
                static_cast<int64_t>(have))
            {
                ok = false;
                break;
            }
            crc = mz_crc32(crc, outbuf.data(), have);
            plain_written += static_cast<uint64_t>(have);

            if (size_orig > 8ULL * 1024ULL * 1024ULL)
            {
                double pct = 100.0 * (double)plain_written / (double)size_orig;
                if (pct > 100.0) pct = 100.0;
                cout << "\r[OV] Descomprimiendo: " << fixed << setprecision(1)
                     << pct << "% (" << (plain_written / (1024 * 1024)) << " / "
                     << (size_orig / (1024 * 1024)) << " MB)" << std::flush;
            }
        }

        if (last_st == MZ_STREAM_END)
        {
            got_stream_end = true;
            break;
        }
        if (last_st != MZ_OK && last_st != MZ_BUF_ERROR)
        {
            ok = false;
            break;
        }
        if (eof_in && strm.avail_in == 0 && have == 0)
            break;
    }

    mz_inflateEnd(&strm);
    _close(fdIn);
    _close(fdOut);

    if (size_orig > 8ULL * 1024ULL * 1024ULL)
        cout << "\n";

    uint32_t crc_got = static_cast<uint32_t>(crc);
    bool size_ok = (plain_written == size_orig);
    bool crc_ok = (crc_got == crc_esp);

    if (ok && got_stream_end && size_ok && crc_ok)
        return true;

    if (ok && got_stream_end && size_ok)
    {
        cerr << "[OV] Aviso: CRC distinto pero tamano OK; se acepta.\n";
        return true;
    }

    cerr << "[OV] Fallo: st=" << last_st
         << " end=" << (got_stream_end ? 1 : 0)
         << " plain=" << plain_written << "/" << size_orig
         << " crc=" << hex << crc_got << "/" << crc_esp << dec
         << " comp_read=" << comp_read
         << " comp_hdr=" << size_comp_hdr
         << "\n";
#ifdef _WIN32
    _unlink(path_out_generado.c_str());
#else
    unlink(path_out_generado.c_str());
#endif
    return false;
}


#ifdef _WIN32
static bool Crear_Directorios_Para_Archivo(const string &path_completo)
{

    string s = path_completo;
    for (size_t i = 0; i < s.size(); ++i)
        if (s[i] == '/') s[i] = '\\';

    size_t start = 0;
    if (s.size() >= 2 && s[1] == ':') start = 2;
    if (start < s.size() && (s[start] == '\\')) start++;

    for (size_t i = start; i < s.size(); ++i)
    {
        if (s[i] == '\\')
        {
            string sub = s.substr(0, i);
            if (!sub.empty())
                CreateDirectoryA(sub.c_str(), NULL);
        }
    }
    return true;
}
#else
#include <sys/stat.h>
static bool Crear_Directorios_Para_Archivo(const string &path_completo)
{
    string s = path_completo;
    for (size_t i = 1; i < s.size(); ++i)
    {
        if (s[i] == '/')
        {
            string sub = s.substr(0, i);
            mkdir(sub.c_str(), 0755);
        }
    }
    return true;
}
#endif


bool Extraer_BULK(const string &path_bulk, const string &carpeta_destino)
{
    int fd = -1;
#ifdef _WIN32
    fd = _open(path_bulk.c_str(), _O_RDONLY | _O_BINARY);
#else
    fd = open(path_bulk.c_str(), O_RDONLY);
#endif
    if (fd < 0) return false;

    char magic[8];
    if (_read(fd, magic, 8) != 8 || memcmp(magic, BULK_MAGIC, 8) != 0)
    { _close(fd); return false; }

    uint32_t ver = 0, n = 0;
    if (_read(fd, &ver, 4) != 4 || _read(fd, &n, 4) != 4 || ver != 1 || n == 0)
    { _close(fd); return false; }

    struct Item { string name; uint64_t size; uint32_t crc; };
    std::vector<Item> items;
    items.reserve(n);

    for (uint32_t i = 0; i < n; ++i)
    {
        uint16_t nl = 0;
        if (_read(fd, &nl, 2) != 2) { _close(fd); return false; }
        Item it;
        it.name.resize(nl);
        if (nl > 0 && _read(fd, &it.name[0], nl) != (int)nl)
        { _close(fd); return false; }
        if (_read(fd, &it.size, 8) != 8 || _read(fd, &it.crc, 4) != 4)
        { _close(fd); return false; }
        if (it.name.find("..") != string::npos) { _close(fd); return false; }
        items.push_back(std::move(it));
    }

#ifdef _WIN32
    CreateDirectoryA(carpeta_destino.c_str(), NULL);
#else
    mkdir(carpeta_destino.c_str(), 0755);
#endif

    std::vector<uint8_t> buf(BULK_IO_BUF);

    for (uint32_t i = 0; i < n; ++i)
    {
        string dest = carpeta_destino;
#ifdef _WIN32
        if (!dest.empty() && dest.back() != '\\') dest += '\\';
        string rel = items[i].name;
        for (size_t k = 0; k < rel.size(); ++k)
            if (rel[k] == '/') rel[k] = '\\';
        dest += rel;
#else
        if (!dest.empty() && dest.back() != '/') dest += '/';
        dest += items[i].name;
#endif
        Crear_Directorios_Para_Archivo(dest);

        int fdOut = -1;
#ifdef _WIN32
        fdOut = _open(dest.c_str(),
                      _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY,
                      _S_IREAD | _S_IWRITE);
#else
        fdOut = open(dest.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
#endif
        if (fdOut < 0) { _close(fd); return false; }

        mz_ulong crc = MZ_CRC32_INIT;
        uint64_t rest = items[i].size;
        while (rest > 0)
        {
            size_t chunk = static_cast<size_t>(
                (rest > BULK_IO_BUF) ? BULK_IO_BUF : rest);
            int64_t nread = _read(fd, buf.data(), static_cast<unsigned int>(chunk));
            if (nread <= 0)
            { _close(fdOut); _close(fd); return false; }
            if (_write(fdOut, buf.data(), static_cast<unsigned int>(nread)) != nread)
            { _close(fdOut); _close(fd); return false; }
            crc = mz_crc32(crc, buf.data(), static_cast<size_t>(nread));
            rest -= static_cast<uint64_t>(nread);
        }
        _close(fdOut);

        if (static_cast<uint32_t>(crc) != items[i].crc)
        {
            cerr << "[BULK] CRC fallido: " << items[i].name << "\n";
            _close(fd);
            return false;
        }
    }

    _close(fd);
    return true;
}


static bool Leer_Prefijo(const string &path, uint8_t *buf, size_t n)
{
    int fd = -1;
#ifdef _WIN32
    fd = _open(path.c_str(), _O_RDONLY | _O_BINARY);
#else
    fd = open(path.c_str(), O_RDONLY);
#endif
    if (fd < 0) return false;
    int64_t got = _read(fd, buf, static_cast<unsigned int>(n));
    _close(fd);
    return got == static_cast<int64_t>(n);
}

void Postproceso_Capas(string &path_recuperado)
{

    {
        uint8_t magic8[8];
        if (Leer_Prefijo(path_recuperado, magic8, 8) &&
            memcmp(magic8, OV_MAGIC, 8) == 0)
        {
            string out_ov;
            cout << "[INFO] Detectado contenedor .ov; descomprimiendo..." << endl;
            if (Extraer_OV(path_recuperado, out_ov))
            {
                cout << "[INFO] Descomprimido: " << out_ov << endl;
                if (out_ov != path_recuperado)
                {
#ifdef _WIN32
                    _unlink(path_recuperado.c_str());
#else
                    unlink(path_recuperado.c_str());
#endif
                }
                path_recuperado = out_ov;
            }
            else
            {
                cerr << "[AVISO] No se pudo descomprimir .ov; se deja: " << path_recuperado << endl;
                return;
            }
        }
    }


    {
        uint8_t magic8[8];
        if (Leer_Prefijo(path_recuperado, magic8, 8) &&
            memcmp(magic8, BULK_MAGIC, 8) == 0)
        {
            string carpeta;
            if (path_recuperado.size() >= 5 &&
                path_recuperado.substr(path_recuperado.size() - 5) == ".bulk")
            {
                carpeta = path_recuperado.substr(0, path_recuperado.size() - 5)
                          + "_extraido";
            }
            else
            {
                carpeta = path_recuperado + "_extraido";
            }

            cout << "[INFO] Detectado contenedor .bulk; extrayendo a "
                 << carpeta << " ...\n";

            if (Extraer_BULK(path_recuperado, carpeta))
            {
                cout << "[INFO] Extraccion .bulk OK.\n";
#ifdef _WIN32
                _unlink(path_recuperado.c_str());
#else
                unlink(path_recuperado.c_str());
#endif
                path_recuperado = carpeta;
            }
            else
            {
                cerr << "[AVISO] Fallo al extraer .bulk.\n";
            }
        }
    }
}

