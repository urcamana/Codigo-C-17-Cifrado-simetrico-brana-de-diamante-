/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */

#include "crypto/brana_crypto.h"
#include <cmath>

#include <fcntl.h>
#include <cstdio>
#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#define _read(fd, buf, count) read(fd, buf, count)
#define _write(fd, buf, count) write(fd, buf, count)
#define _close(fd) close(fd)
#define _lseeki64(fd, offset, origin) lseek(fd, offset, origin)
#define _commit(fd) fsync(fd)
#endif

static const uint64_t Bloque_MAX = 1024ULL * 1024ULL * 16ULL;

#include <string>
using namespace std;

uint8_t TABLA_VISCOSA[256];
// Constantes del motor (editables con criterio)
uint64_t LAMBDA = 577215664ULL;
uint64_t REFERENCIA = 528000000ULL;
uint64_t ANCLAJE_SIGMA = 4040509648ULL;
uint32_t OPERADOR_DIRAC = 0x5F3759DF;
// Valor_Header: constante institucional editable
string Valor_Header = "Valor_Header";
// Version del protocolo
string Version = "V6.0";

uint64_t Actualizar_Siguiente_Estado(uint64_t &Estado)
{
    Estado += 0x9E3779B97F4A7C15ULL;
    uint64_t z = Estado;
    z = (z ^ (z >> 30ULL)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27ULL)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31ULL) ^ (LAMBDA >> 8ULL);
}

uint8_t rotl8(uint8_t Valor, uint8_t Bits) {
    Bits &= 7ULL;
    return static_cast<uint8_t>((Valor << Bits) | (Valor >> (8ULL - Bits)));
}

uint64_t rotl64(uint64_t Valor, uint64_t Bits) {
    Bits &= 63ULL;
    return (Bits == 0ULL) ? Valor : ((Valor << Bits) | (Valor >> (64ULL - Bits)));
}
uint64_t rotr64(uint64_t Valor, uint64_t Bits) {
    Bits &= 63ULL;
    return (Valor >> Bits) | (Valor << (64ULL - Bits));
}


uint8_t Encriptacion_Secundaria_Individual(uint8_t buffer, uint64_t Frecuencia_Final_TEMP, uint64_t i, bool Modo, uint64_t Clave_Semilla_Principal, uint8_t VEV)
{
    uint64_t Desplazamiento = (i * ((LAMBDA >> 22ULL) + 3ULL)) & 63ULL;
    uint64_t Salto_Masa = rotl64(static_cast<uint64_t>(VEV), Desplazamiento);
    uint64_t Fase_Espectral = (Frecuencia_Final_TEMP ^ (i * 0x94D049BBULL)) ^ (Salto_Masa ^ (Clave_Semilla_Principal << 5ULL));
    uint8_t Componente_Torsion = static_cast<uint8_t>(((Fase_Espectral >> ((i * 19ULL) & 63ULL)) ^ Clave_Semilla_Principal) & 0xFFULL);
    uint8_t Aleatoriedad_cifrado = (Componente_Torsion ^ static_cast<uint8_t>(Clave_Semilla_Principal >> 12ULL)) ^ static_cast<uint8_t>(Frecuencia_Final_TEMP >> 20ULL);
    return Modo ? (buffer + Aleatoriedad_cifrado) : (buffer - Aleatoriedad_cifrado);
}

uint8_t Encriptacion_Dual_Esclavo_1(uint8_t buffer, uint64_t Frecuencia_Final_TEMP, uint64_t i, bool Modo, uint64_t Clave_CRC, uint8_t VEV)
{
    uint64_t Desplazamiento = (i * (LAMBDA >> 20ULL)) & 63ULL;
    uint64_t Salto_Masa = rotl64(static_cast<uint64_t>(VEV), Desplazamiento);

    uint64_t Fase_Espectral = (Frecuencia_Final_TEMP ^ (i * 0x9E3779B9ULL)) ^ (Salto_Masa ^ (Clave_CRC << 1ULL));

    uint8_t Aleatoriedad_cifrado = static_cast<uint8_t>(((Fase_Espectral ^ LAMBDA) >> ((i * 13ULL) & 63ULL)) ^
                                       (Clave_CRC >> 32ULL) ^ (Frecuencia_Final_TEMP >> 8ULL));

    return Modo ? (buffer + Aleatoriedad_cifrado) : (buffer - Aleatoriedad_cifrado);
}

uint8_t Encriptacion_Dual_Esclavo_2(uint8_t buffer, uint64_t Frecuencia_Final_TEMP, uint64_t i, bool Modo, uint64_t Clave_CRC, uint8_t VEV)
{
    uint64_t Desplazamiento = (i * ((LAMBDA >> 20ULL) + 1ULL)) & 63ULL;
    uint64_t Salto_Masa = rotl64(static_cast<uint64_t>(VEV), Desplazamiento);

    uint64_t Fase_Espectral = (Frecuencia_Final_TEMP ^ (i * 0xBF58476DULL)) ^ (Salto_Masa ^ (Clave_CRC << 3ULL));

    uint8_t Aleatoriedad_cifrado = static_cast<uint8_t>(((Fase_Espectral ^ (LAMBDA + 1ULL)) >> ((i * 17ULL) & 63ULL)) ^
                                       (Clave_CRC >> 24ULL) ^ (Frecuencia_Final_TEMP >> 16ULL));

    return Modo ? (buffer + Aleatoriedad_cifrado) : (buffer - Aleatoriedad_cifrado);
}

uint8_t Encriptacion_Secundaria_Dual(uint8_t buffer, uint64_t Frecuencia_Final_TEMP, uint64_t i, bool Modo, uint64_t Clave_Semilla_Principal, uint8_t VEV)
{
    bool Usar_Esclavo_2 = (VEV & 0x01);
    uint8_t Resultado = Usar_Esclavo_2 ?
        Encriptacion_Dual_Esclavo_2(buffer, Frecuencia_Final_TEMP, i, Modo, Clave_Semilla_Principal, VEV) :
        Encriptacion_Dual_Esclavo_1(buffer, Frecuencia_Final_TEMP, i, Modo, Clave_Semilla_Principal, VEV);
    return Resultado;
}

uint64_t Generador_String(string k)
{
    uint64_t h = LAMBDA;

    for (uint64_t i = 0ULL; i < k.length(); i++)
    {
        h ^= (static_cast<uint64_t>(k[i]) + 1ULL) * (i + 137ULL);
        uint64_t h_par = (h >> 7ULL) ^ (h * 31ULL);
        uint64_t h_impar = (h << 13ULL) ^ (h ^ LAMBDA);
        h = (h & 1ULL) ? h_impar : h_par;
        h ^= 0x9E3779B97F4A7C15ULL;
    }
    h ^= (h >> 33ULL);
    h *= 0xff51afd7ed558ccdULL;
    h ^= (h >> 33ULL);
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= (h >> 33ULL);
    return h;
}

void Inicializar_TABLA_VISCOSA()
{
    for (int i = 0; i < 256; i++)
        TABLA_VISCOSA[i] = static_cast<uint8_t>(i);

    uint64_t s = Generador_String(Version) ^ Generador_String(Valor_Header) ^ LAMBDA;
    for (int i = 255; i > 0; i--)
    {
        s = Actualizar_Siguiente_Estado(s);
        int j = static_cast<int>(s % static_cast<uint64_t>(i + 1));
        uint8_t tmp = TABLA_VISCOSA[i];
        TABLA_VISCOSA[i] = TABLA_VISCOSA[j];
        TABLA_VISCOSA[j] = tmp;
    }
}

void Aplicar_Torsion_Principal(std::vector<uint8_t> &buffer, uint64_t Total_Bytes_Brana)
{
    uint64_t SemillaMaestra = Generador_String(Valor_Header) ^ Total_Bytes_Brana ^ LAMBDA;
    uint8_t VEV = static_cast<uint8_t>(SemillaMaestra & 0xFFULL);
    for (size_t i = 0; i < buffer.size(); ++i)
    {
        Actualizar_Siguiente_Estado(SemillaMaestra);
        uint8_t Indice = static_cast<uint8_t>(((SemillaMaestra >> 32ULL) ^ static_cast<uint64_t>(VEV)) & 0xFFULL);
        uint8_t Mascara_Viscosidad = TABLA_VISCOSA[Indice];
        uint8_t Giro = static_cast<uint8_t>(((SemillaMaestra >> 48ULL) & 7ULL) + 1ULL);
        buffer[i] ^= Mascara_Viscosidad;
        buffer[i] = rotl8(buffer[i], Giro);
        buffer[i] ^= VEV;
        VEV = rotl8(VEV, 3ULL) ^ buffer[i] ^ static_cast<uint8_t>(SemillaMaestra & 0xFFULL);
    }
}

uint8_t rotr8(uint8_t Valor, uint8_t Bits)
{
    Bits = static_cast<uint8_t>(Bits & 7);
    return static_cast<uint8_t>((Valor >> Bits) | (Valor << (8 - Bits)));
}

void Restaurar_Torsion_Principal(std::vector<uint8_t> &buffer, uint64_t TotalBytes2)
{
    uint64_t SemillaMaestra = Generador_String(Valor_Header) ^ TotalBytes2 ^ LAMBDA;
    uint8_t VEV = static_cast<uint8_t>(SemillaMaestra & 0xFFULL);
    size_t N_Bytes = buffer.size();
    if (N_Bytes == 0) return;
    std::vector<uint8_t> mascarasViscosas(N_Bytes);
    std::vector<int> GirosAsignados(N_Bytes);
    std::vector<uint8_t> VEVsAplicados(N_Bytes);
    for (size_t i = 0; i < N_Bytes; ++i)
    {
        Actualizar_Siguiente_Estado(SemillaMaestra);
        uint8_t Indice = static_cast<uint8_t>(((SemillaMaestra >> 32ULL) ^ VEV) & 0xFFULL);
        mascarasViscosas[i] = TABLA_VISCOSA[Indice];
        GirosAsignados[i] = static_cast<int>((SemillaMaestra >> 48ULL) & 7ULL) + 1;
        VEVsAplicados[i] = VEV;
        VEV = rotl8(VEV, 3) ^ buffer[i] ^ static_cast<uint8_t>(SemillaMaestra & 0xFFULL);
    }
    for (size_t i = 0; i < N_Bytes; ++i)
    {
        buffer[i] ^= VEVsAplicados[i];
        buffer[i] = rotr8(buffer[i], static_cast<uint8_t>(GirosAsignados[i]));
        buffer[i] ^= mascarasViscosas[i];
    }
}


uint64_t Aplicar_Salto_Masa(uint64_t Dato, uint64_t Semilla_Dual_ENC, uint64_t Offset_Byte, uint64_t Semilla_Mutante)
{
    uint64_t Semilla_Local = (Semilla_Dual_ENC ^ LAMBDA) ^ (Offset_Byte ^ Semilla_Mutante);

    uint64_t Tension = (Semilla_Local ^ ANCLAJE_SIGMA) * 0xBF58476D1CE4E5B9ULL;
    uint64_t Resto = Semilla_Local % 7ULL;
    return Dato ^ Tension ^ Resto;
}

void Torsionar_Base(uint64_t estado[8], uint64_t Constante)
{
    uint64_t Rotador = Constante;

    for (uint64_t i = 0ULL; i < 8ULL; i++)
    {
        uint64_t x = estado[i] ^ estado[(i + 1ULL) & 7ULL] ^ Rotador;
        x = (x ^ (x >> 30ULL)) * 0xBF58476D1CE4E5B9ULL;
        x = (x ^ (x >> 27ULL)) * 0x94D049BB133111EBULL;
        estado[i] = x ^ (x >> 31ULL);
        Rotador = ((Rotador << 13ULL) | (Rotador >> 51ULL)) ^ Constante;
        Rotador ^= estado[i];
    }
}

void Array_Torsion(uint64_t estado[8])
{
    Torsionar_Base(estado, LAMBDA);
    Torsionar_Base(estado, REFERENCIA ^ LAMBDA);
    for (uint64_t i = 0ULL; i < 4ULL; i++) {
        estado[i] ^= estado[7ULL - i];
    }
}


uint8_t Desencriptacion_Secundaria_Individual(uint8_t buffer, uint64_t Frecuencia_Final_TEMP, int64_t i, bool ida, uint64_t Clave_Semilla_Principal, uint8_t VEV)
{
    uint64_t Desplazamiento = (static_cast<uint64_t>(i) * ((LAMBDA >> 22ULL) + 3ULL)) & 63ULL;
    uint64_t Salto_Masa = (static_cast<uint64_t>(VEV) << Desplazamiento) |
                          (static_cast<uint64_t>(VEV) >> (64ULL - Desplazamiento));
    uint64_t Fase_Espectral = (Frecuencia_Final_TEMP ^ (static_cast<uint64_t>(i) * 0x94D049BBULL)) ^ (Salto_Masa ^ (Clave_Semilla_Principal << 5ULL));
    uint8_t Componente_Torsion = static_cast<uint8_t>(((Fase_Espectral >> ((i * 19ULL) & 63ULL)) ^ Clave_Semilla_Principal) & 0xFFULL);
    uint8_t Aleatoriedad_cifrado = (Componente_Torsion ^ static_cast<uint8_t>(Clave_Semilla_Principal >> 12ULL)) ^ (static_cast<uint8_t>(Frecuencia_Final_TEMP >> 20ULL));
    return ida ? (buffer + Aleatoriedad_cifrado) : (buffer - Aleatoriedad_cifrado);
}
uint8_t Desencriptacion_Dual_Esclavo_1(uint8_t buffer, uint64_t Frecuencia_Final_TEMP, int64_t i, bool ida, uint64_t Clave_CRC, uint8_t VEV)
{
    uint64_t Desplazamiento = (static_cast<uint64_t>(i) * (LAMBDA >> 20ULL)) & 63ULL;
    uint64_t Salto_Masa = (static_cast<uint64_t>(VEV) << Desplazamiento) | (static_cast<uint64_t>(VEV) >> (64ULL - Desplazamiento));
    uint64_t Fase_Espectral = (Frecuencia_Final_TEMP ^ (static_cast<uint64_t>(i) * 0x9E3779B9ULL)) ^ (Salto_Masa ^ (Clave_CRC << 1ULL));
    uint8_t Aleatoriedad_cifrado = (static_cast<uint8_t>((Fase_Espectral ^ LAMBDA) >> ((i * 13ULL) & 63ULL)) ^ (Clave_CRC >> 32ULL)) ^ (Frecuencia_Final_TEMP >> 8ULL);
    return ida ? (buffer + Aleatoriedad_cifrado) : (buffer - Aleatoriedad_cifrado);
}
uint8_t Desencriptacion_Dual_Esclavo_2(uint8_t buffer, uint64_t Frecuencia_Final_TEMP, int64_t i, bool ida, uint64_t Clave_CRC, uint8_t VEV)
{
    uint64_t Desplazamiento = (static_cast<uint64_t>(i) * ((LAMBDA >> 20ULL) + 1)) & 63ULL;
    uint64_t Salto_Masa = (static_cast<uint64_t>(VEV) << Desplazamiento) | (static_cast<uint64_t>(VEV) >> (64ULL - Desplazamiento));
    uint64_t Fase_Espectral = (Frecuencia_Final_TEMP ^ (static_cast<uint64_t>(i) * 0xBF58476DULL)) ^ (Salto_Masa ^ (Clave_CRC << 3ULL));
    uint8_t Aleatoriedad_cifrado = (static_cast<uint8_t>((Fase_Espectral ^ (LAMBDA + 1ULL)) >> ((i * 17ULL) & 63ULL)) ^ (Clave_CRC >> 24ULL)) ^ (Frecuencia_Final_TEMP >> 16ULL);
    return ida ? (buffer + Aleatoriedad_cifrado) : (buffer - Aleatoriedad_cifrado);
}
uint8_t Desencriptacion_Secundaria_Dual(uint8_t buffer, uint64_t Frecuencia_Final_TEMP, int64_t i, bool ida, uint64_t Clave_Semilla_Principal, uint8_t VEV)
{
    bool usarEsclavo2 = (VEV & 0x01);
    uint8_t Resultado = usarEsclavo2 ?
        Desencriptacion_Dual_Esclavo_2(buffer, Frecuencia_Final_TEMP, i, ida, Clave_Semilla_Principal, VEV) :
        Desencriptacion_Dual_Esclavo_1(buffer, Frecuencia_Final_TEMP, i, ida, Clave_Semilla_Principal, VEV);
    VEV ^= (Resultado ^ (i & 0xFFLL));
    VEV = (VEV << 1) | (VEV >> 7);
    return Resultado;
}

void Encriptacion_Principal(vector<uint8_t> &buffer, uint64_t Inicio, uint64_t Final, uint64_t Frecuencia_Final, uint64_t Clave_CRC, bool iva, uint64_t Frecuencia_Dispersion, uint64_t Clave_Temp, uint64_t REFERENCIA, uint64_t Semilla, bool Modo)
{
    uint64_t estado[8];
    estado[0] = Frecuencia_Dispersion ^ (Clave_CRC + LAMBDA);
    estado[1] = Clave_CRC ^ Clave_Temp;
    estado[2] = Frecuencia_Final ^ LAMBDA;
    estado[3] = LAMBDA;
    estado[4] = Clave_CRC;
    estado[5] = (LAMBDA ^ Frecuencia_Final);
    estado[6] = Frecuencia_Dispersion ^ 0x5555555555555555ULL;
    estado[7] = REFERENCIA ^ Clave_Temp;

    uint64_t SaltosDeFase = (Inicio / 1024ULL) & 63ULL;

    for (uint64_t s = 0ULL; s < SaltosDeFase; s++)
        {
            Array_Torsion(estado);
        }
    uint8_t VEV = static_cast<uint8_t>(Frecuencia_Final & 0xFFULL);

    for (uint64_t i = Inicio; i < Final; i++)
    {
        uint8_t Original = buffer[i];

        if (i < 64ULL) {
            buffer[i] = Encriptacion_Secundaria_Individual(buffer[i], Frecuencia_Final ^ Semilla, i, true, Clave_CRC, VEV);
        }
        else if (i < 2048ULL) {
            uint64_t Torsor = estado[i & 7ULL];
            buffer[i] = Encriptacion_Secundaria_Individual(buffer[i], Frecuencia_Final ^ Torsor, i, true, Clave_CRC, VEV);
        }
        else {
            uint64_t Torsor = estado[i & 7ULL];
            buffer[i] = Encriptacion_Secundaria_Dual(buffer[i], Frecuencia_Final ^ Torsor, i, true, Clave_CRC, VEV);
        }
        uint64_t Lambda_Local = LAMBDA + (estado[i & 7ULL] & (LAMBDA >> 6ULL));
        uint64_t Inyeccion = static_cast<uint64_t>(Original);
        uint64_t Desplazamiento = i & 31ULL;
        estado[i & 7ULL] ^= (Inyeccion << Desplazamiento) | (Inyeccion >> (64ULL - Desplazamiento));
        if (Modo) estado[i & 7ULL] ^= (Inyeccion >> 5ULL);
        estado[i & 7ULL] += Lambda_Local;

        VEV = Original;

        if (i > 0ULL && ((i + 1ULL) & 1023ULL) == 0ULL)
        {
            Array_Torsion(estado);
        }
    }

    uint64_t* Datos64 = reinterpret_cast<uint64_t*>(&buffer[Inicio]);
    size_t Longitud_Tramo = Final - Inicio;
    size_t Limites64 = Longitud_Tramo / sizeof(uint64_t);

    for (size_t k = 0; k < Limites64; ++k)
    {
        uint64_t Semilla_Mutante = Semilla ^ static_cast<uint64_t>(k);
        uint64_t Offset_Elemento = Inicio + (k * sizeof(uint64_t));
        Datos64[k] = Aplicar_Salto_Masa(Datos64[k], Frecuencia_Final, Offset_Elemento, Semilla_Mutante);
    }
}

void Desencriptacion_Principal(vector<uint8_t> &buf, uint64_t Inicio, uint64_t Final, uint64_t Frecuencia_Final, uint64_t Clave_CRC, bool iva, uint64_t Frecuencia_Dispersion, uint64_t Clave_Temp, uint64_t REFERENCIA, uint64_t Semilla, bool modo)
{
    uint64_t* Datos64 = reinterpret_cast<uint64_t*>(&buf[Inicio]);
    size_t Longitud_Tramo = Final - Inicio;
    size_t Limites64 = Longitud_Tramo / sizeof(uint64_t);

    for (size_t k = 0; k < Limites64; ++k)
    {
        uint64_t Semilla_Mutante = Semilla ^ static_cast<uint64_t>(k);
        uint64_t Offset_Elemento = Inicio + (k * sizeof(uint64_t));
        Datos64[k] = Aplicar_Salto_Masa(Datos64[k], Frecuencia_Final, Offset_Elemento, Semilla_Mutante);
    }

    uint64_t estado[8];
    estado[0] = Frecuencia_Dispersion ^ (Clave_CRC + LAMBDA);
    estado[1] = Clave_CRC ^ Clave_Temp;
    estado[2] = Frecuencia_Final ^ LAMBDA;
    estado[3] = LAMBDA;
    estado[4] = Clave_CRC;
    estado[5] = (LAMBDA ^ Frecuencia_Final);
    estado[6] = Frecuencia_Dispersion ^ 0x5555555555555555ULL;
    estado[7] = REFERENCIA ^ Clave_Temp;

    uint64_t SaltosDeFase = (Inicio / 1024ULL) & 63ULL;

    for (uint64_t s = 0ULL; s < SaltosDeFase; s++)
    {
        Array_Torsion(estado);
    }

    uint8_t VEV = static_cast<uint8_t>(Frecuencia_Final & 0xFFULL);

    for (uint64_t i = Inicio; i < Final; i++)
    {
        uint8_t cifrado_brana = buf[i];
        if (i < 64ULL) {
            buf[i] = Desencriptacion_Secundaria_Individual(buf[i], Frecuencia_Final ^ Semilla, i, false, Clave_CRC, VEV);
        }
        else if (i < 2048ULL) {
            uint64_t Torsor = estado[i & 7ULL];
            buf[i] = Desencriptacion_Secundaria_Individual(buf[i], Frecuencia_Final ^ Torsor, i, false, Clave_CRC, VEV);
        }
        else {
            uint64_t Torsor = estado[i & 7ULL];
            buf[i] = Desencriptacion_Secundaria_Dual(buf[i], Frecuencia_Final ^ Torsor, i, false, Clave_CRC, VEV);
        }

        uint8_t Original = buf[i];
        uint64_t LAMBDA_local = LAMBDA + (estado[i & 7ULL] & (LAMBDA >> 6ULL));
        uint64_t Inyeccion = static_cast<uint64_t>(Original);
        uint64_t Desplazamiento = i & 31ULL;
        estado[i & 7ULL] ^= (Inyeccion << Desplazamiento) | (Inyeccion >> (64ULL - Desplazamiento));
        if (modo) estado[i & 7ULL] ^= (Inyeccion >> 5ULL);
        estado[i & 7ULL] += LAMBDA_local;
        VEV = Original;

        if (i > 0ULL && ((i + 1) & 1023ULL) == 0ULL)
        {
            Array_Torsion(estado);
        }
    }
}


void Aplicar_Defensa_Activa(int64_t fd, uint64_t Fin_Header, uint64_t Fatiga_Final, uint64_t Valor_Defensa, uint64_t Semilla_Ofuscacion, uint64_t Bytes_A_Defender)
{
    uint64_t Espacio_Real = (Bytes_A_Defender > Bloque_MAX) ? Bloque_MAX : Bytes_A_Defender;
    std::vector<uint8_t> buffer(static_cast<size_t>(Espacio_Real));
    for (uint64_t n = 1ULL; n <= Valor_Defensa; n++)
    {
        _lseeki64(static_cast<int>(fd), static_cast<int64_t>(Fin_Header), SEEK_SET);
        int64_t Datos_Leidos_TMP = _read(static_cast<int>(fd), buffer.data(), static_cast<unsigned int>(Espacio_Real));
        if (Datos_Leidos_TMP <= 0LL) break;
        uint64_t Estado_TMP = Fatiga_Final ^ (n * 0x9E3779B97F4A7C15ULL) ^ LAMBDA;
        uint8_t VEV = static_cast<uint8_t>(Estado_TMP & 0xFFULL);
        for (uint64_t i = 0ULL; i < static_cast<uint64_t>(Datos_Leidos_TMP); ++i)
        {
            Actualizar_Siguiente_Estado(Estado_TMP);
            uint8_t Indice = static_cast<uint8_t>(((Estado_TMP >> 32ULL) ^ VEV) & 0xFFULL);
            uint8_t Mascara_Viscosidad = TABLA_VISCOSA[Indice];
            uint8_t Giro = static_cast<uint8_t>(((Estado_TMP >> 48ULL) & 7ULL) + 1ULL);
            buffer[i] ^= Mascara_Viscosidad;
            buffer[i] = rotl8(buffer[i], Giro);
            buffer[i] ^= VEV;
            VEV = rotl8(VEV, 3) ^ buffer[i] ^ static_cast<uint8_t>(Estado_TMP & 0xFFULL);
        }
        _lseeki64(static_cast<int>(fd), static_cast<int64_t>(Fin_Header), SEEK_SET);
        _write(static_cast<int>(fd), buffer.data(), static_cast<unsigned int>(Datos_Leidos_TMP));
    }
    _commit(static_cast<int>(fd));
}

void Restaurar_Defensa_Activa(int64_t fdIn, uint64_t InicioData, uint64_t Fatiga_Leida, uint64_t Valor_Defensa, uint64_t Semilla_Ofuscacion, uint64_t Bytes_A_Procesar)
{
    if (Valor_Defensa == 0ULL)
        return;
    uint64_t Espacio_Real = (Bytes_A_Procesar > Bloque_MAX) ? Bloque_MAX : Bytes_A_Procesar;
    std::vector<uint8_t> buffer(static_cast<size_t>(Espacio_Real));
    for (uint64_t n = Valor_Defensa; n >= 1ULL; n--)
    {
        _lseeki64(static_cast<int>(fdIn), static_cast<int64_t>(InicioData), SEEK_SET);
        int64_t BytesLeidos = _read(static_cast<int>(fdIn), buffer.data(), static_cast<unsigned int>(Espacio_Real));
        if (BytesLeidos <= 0LL) break;
        uint64_t estado = Fatiga_Leida ^ (n * 0x9E3779B97F4A7C15ULL) ^ LAMBDA;
        uint8_t VEV = static_cast<uint8_t>(estado & 0xFFULL);
        std::vector<uint8_t> mascarasViscosas(static_cast<size_t>(BytesLeidos));
        std::vector<int> GirosAsignados(static_cast<size_t>(BytesLeidos));
        std::vector<uint8_t> VEVsAplicados(static_cast<size_t>(BytesLeidos));
        for (uint64_t i = 0ULL; i < static_cast<uint64_t>(BytesLeidos); ++i)
        {
            Actualizar_Siguiente_Estado(estado);
            uint8_t Indice = static_cast<uint8_t>(((estado >> 32ULL) ^ VEV) & 0xFFULL);
            mascarasViscosas[i] = TABLA_VISCOSA[Indice];
            GirosAsignados[i] = static_cast<int>((estado >> 48ULL) & 7ULL) + 1;
            VEVsAplicados[i] = VEV;
            VEV = rotl8(VEV, 3) ^ buffer[i] ^ static_cast<uint8_t>(estado & 0xFFULL);
        }
        for (uint64_t i = 0ULL; i < static_cast<uint64_t>(BytesLeidos); ++i)
        {
            buffer[i] ^= VEVsAplicados[i];
            buffer[i] = rotr8(buffer[i], static_cast<uint8_t>(GirosAsignados[i]));
            buffer[i] ^= mascarasViscosas[i];
        }
        _lseeki64(static_cast<int>(fdIn), static_cast<int64_t>(InicioData), SEEK_SET);
        _write(static_cast<int>(fdIn), buffer.data(), static_cast<unsigned int>(BytesLeidos));
    }
    _commit(static_cast<int>(fdIn));
}

float SIGMA_YANG_MILLS = 77.92411464f;

void Procesar_Ovillo(BranaDatos *brana, uint64_t Semilla_Dual_ENC)
{
    uint32_t Clave32 = static_cast<uint32_t>(Semilla_Dual_ENC);
    const uint32_t TABLA_COOK[2] = {0x87654321u, 0x12345678u};
    uint32_t Torsion_Final = TABLA_COOK[Clave32 & 1u];
    uint32_t Ajuste_Dirac = OPERADOR_DIRAC + (Clave32 >> 2);

    for (int64_t i = 0LL; i < static_cast<int64_t>(VUELTAS_OVILLO); i++)
    {
        uint32_t flujo_Bits;
        std::memcpy(&flujo_Bits, &brana->Fase_Vorticidad[i], sizeof(float));
        uint32_t r = (flujo_Bits ^ Clave32) + static_cast<uint32_t>(SIGMA_YANG_MILLS * brana->Fase_Vorticidad[i]);
        uint32_t Espejo_Bits;
        std::memcpy(&Espejo_Bits, &brana->Espejo_Adelico[i], sizeof(float));
        uint32_t Topologia = r ^ Ajuste_Dirac ^ Espejo_Bits;
        Topologia = (Topologia << 7) | (Topologia >> 25);
        Topologia ^= Torsion_Final;
        std::memcpy(&brana->Fase_Vorticidad[i], &Topologia, sizeof(float));
    }
}

void Inicializar_Rigidez_Adelica(BranaDatos *brana, uint8_t *datos_buffer, size_t Bytes)
{
    size_t Limite = (Bytes < VUELTAS_OVILLO * 4) ? Bytes : VUELTAS_OVILLO * 4;
    size_t Elementos = Limite / 4;
    for (size_t i = 0; i < VUELTAS_OVILLO; ++i)
    {
        if (i < Elementos)
        {
            float Valor;
            std::memcpy(&Valor, &datos_buffer[i * 4], 4);
            brana->Fase_Vorticidad[i] = Valor;
            brana->Espejo_Adelico[i] = Valor;
        }
        else
        {
            brana->Fase_Vorticidad[i] = 0.0f;
            brana->Espejo_Adelico[i] = 0.0f;
        }
    }
}

bool Validar_Ciclos_Hodge(const BranaDatos *brana)
{

    if (brana == nullptr)
        return false;
    const double UMBRAL_HODGE_SESGO = 0.40;
    uint64_t neg = 0ULL;
    const uint64_t N = VUELTAS_OVILLO;
    for (uint64_t i = 0ULL; i < N; i++)
    {
        uint32_t Bits;
        std::memcpy(&Bits, &brana->Fase_Vorticidad[i], 4);
        if (Bits >> 31)
            neg++;
    }
    double frac = static_cast<double>(neg) / static_cast<double>(N);
    double sesgo = frac > 0.5 ? (frac - 0.5) : (0.5 - frac);
    return sesgo <= UMBRAL_HODGE_SESGO;
}

static const size_t CONTADOR_ENTROPIA_MAXIMA = 65536ULL;
static double TABLA_ENTROPIA[CONTADOR_ENTROPIA_MAXIMA];
static bool Tabla_Preparada = false;
static const double Viscosidad_Cinematica = 1.35e-7;

void Inicializar_TABLA_ENTROPIA()
{
    for (size_t i = 1; i < CONTADOR_ENTROPIA_MAXIMA; i++)
        TABLA_ENTROPIA[i] = static_cast<double>(i) * log2(static_cast<double>(i));
    TABLA_ENTROPIA[0] = 0.0;
    Tabla_Preparada = true;
}

double Calcular_Entropia_Shannon(const uint8_t *datos, size_t tam)
{
    if (tam == 0) return 0.0;
    if (!Tabla_Preparada) Inicializar_TABLA_ENTROPIA();
    unsigned long counts[256] = {0};
    for (size_t i = 0; i < tam; i++)
        counts[datos[i]]++;
    double suma_n_log_n = 0.0;
    double N = static_cast<double>(tam);
    for (int i = 0; i < 256; i++)
    {
        if (counts[i] > 0)
        {
            if (counts[i] < CONTADOR_ENTROPIA_MAXIMA)
                suma_n_log_n += TABLA_ENTROPIA[counts[i]];
            else
            {
                double c = static_cast<double>(counts[i]);
                suma_n_log_n += c * log2(c);
            }
        }
    }
    return log2(N) - (suma_n_log_n / N);
}

void Estabilizar_Brana(BranaDatos *brana, const uint8_t *Bloque, size_t Longitud_Bloque, float *Torsor_Actual)
{
    if (*Torsor_Actual > 1.0e6f)
        *Torsor_Actual *= static_cast<float>(1.0 - Viscosidad_Cinematica);
    double ENTROPIA = Calcular_Entropia_Shannon(Bloque, Longitud_Bloque);
    brana->Torsion_Cook *= (ENTROPIA < 0.1) ? 1.61803398875 : 1.0;
    const uint32_t MASCARA_ESTABLE = static_cast<uint32_t>(LAMBDA % 255);
    for (int64_t i = 0LL; i < 64LL; i++)
    {
        if (std::abs(brana->Fase_Vorticidad[i] - brana->Espejo_Adelico[i]) > 1e-5f)
        {
            uint32_t Bits;
            std::memcpy(&Bits, &brana->Fase_Vorticidad[i], 4);
            Bits ^= MASCARA_ESTABLE;
            std::memcpy(&brana->Fase_Vorticidad[i], &Bits, 4);
        }
    }
}

static uint64_t Brana_K_u64(const uint8_t *K, unsigned off)
{
    uint64_t x = 0;
    for (int i = 0; i < 8; ++i)
        x |= (uint64_t)K[(off + i) % 32] << (8 * i);
    return x;
}
void Brana_Expandir_Desde_KMaster(const uint8_t K[32], uint64_t CRC_Control,
    uint64_t &Clave_ENC, uint64_t &Usuario_ENC,
    uint64_t &Clave_Semilla_Principal, uint64_t &Usuario_Semilla_Principal)
{
    Clave_ENC = Brana_K_u64(K, 0) ^ Brana_K_u64(K, 16);
    Usuario_ENC = Brana_K_u64(K, 8) ^ Brana_K_u64(K, 24);
    Clave_Semilla_Principal = Brana_K_u64(K, 0) ^ (CRC_Control * 0x9E3779B97F4A7C15ULL) ^ Brana_K_u64(K, 16);
    Usuario_Semilla_Principal = Brana_K_u64(K, 8) ^ ((CRC_Control << 17) | (CRC_Control >> 3)) ^ Brana_K_u64(K, 24);
}

void Evolucionar_Ecosistema_Semillas(
    uint64_t &s_prin, uint64_t &s_alt, uint64_t &s_enc,
    uint64_t &c_prin, uint64_t &c_alt, uint64_t &c_enc)
{
    const uint64_t PHI_U64 = 0x9E3779B97F4A7C15ULL;
    const uint64_t PI_U64  = 0x243F6A8885A308D3ULL;
    const uint64_t E_U64   = 0xB7E151628AED2A6ULL;

    s_prin = rotl64(s_prin, 13) ^ s_prin;
    s_prin ^= (s_prin << 13); s_prin ^= (s_prin >> 7); s_prin ^= (s_prin << 17);
    s_prin += E_U64;
    s_alt = rotr64(s_alt, 17) ^ s_alt;
    s_alt ^= s_prin;
    s_alt += PHI_U64;
    c_prin ^= s_prin;
    c_prin = rotl64(c_prin, 7) ^ c_prin;
    c_prin ^= (c_prin << 17); c_prin ^= (c_prin >> 13); c_prin ^= (c_prin >> 5);
    c_prin += PI_U64;
    c_alt ^= s_alt;
    c_alt = rotr64(c_alt, 13) ^ c_alt;
    c_alt += E_U64;
    s_enc = rotl64(s_enc, 21);
    s_enc ^= c_prin;
    s_enc += PHI_U64;
    c_enc = rotr64(c_enc, 19);
    c_enc ^= s_alt;
    c_enc += PI_U64;
}
