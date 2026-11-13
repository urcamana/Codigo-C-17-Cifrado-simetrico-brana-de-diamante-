/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */

#ifndef BRANA_CRYPTO_H
#define BRANA_CRYPTO_H

#include <cstdint>
#include <string>
#include <vector>
#include <cstring>

extern uint64_t LAMBDA;
extern uint64_t REFERENCIA;
extern uint64_t ANCLAJE_SIGMA;
extern uint32_t OPERADOR_DIRAC;
extern uint8_t TABLA_VISCOSA[256];
extern std::string Valor_Header;
extern std::string Version;

uint64_t Actualizar_Siguiente_Estado(uint64_t &Estado);
uint64_t Generador_String(std::string k);
void Inicializar_TABLA_VISCOSA();

uint8_t rotl8(uint8_t Valor, uint8_t Bits);
uint64_t rotl64(uint64_t Valor, uint64_t Bits);
uint8_t rotr8(uint8_t Valor, uint8_t Bits);

uint8_t Encriptacion_Secundaria_Individual(uint8_t buffer, uint64_t Frecuencia_Final_TEMP, uint64_t i, bool Modo, uint64_t Clave_Semilla_Principal, uint8_t VEV);
uint8_t Encriptacion_Dual_Esclavo_1(uint8_t buffer, uint64_t Frecuencia_Final_TEMP, uint64_t i, bool Modo, uint64_t Clave_CRC, uint8_t VEV);
uint8_t Encriptacion_Dual_Esclavo_2(uint8_t buffer, uint64_t Frecuencia_Final_TEMP, uint64_t i, bool Modo, uint64_t Clave_CRC, uint8_t VEV);
uint8_t Encriptacion_Secundaria_Dual(uint8_t buffer, uint64_t Frecuencia_Final_TEMP, uint64_t i, bool Modo, uint64_t Clave_Semilla_Principal, uint8_t VEV);

uint8_t Desencriptacion_Secundaria_Individual(uint8_t buffer, uint64_t Frecuencia_Final_TEMP, int64_t i, bool ida, uint64_t Clave_Semilla_Principal, uint8_t VEV);
uint8_t Desencriptacion_Dual_Esclavo_1(uint8_t buffer, uint64_t Frecuencia_Final_TEMP, int64_t i, bool ida, uint64_t Clave_CRC, uint8_t VEV);
uint8_t Desencriptacion_Dual_Esclavo_2(uint8_t buffer, uint64_t Frecuencia_Final_TEMP, int64_t i, bool ida, uint64_t Clave_CRC, uint8_t VEV);
uint8_t Desencriptacion_Secundaria_Dual(uint8_t buffer, uint64_t Frecuencia_Final_TEMP, int64_t i, bool ida, uint64_t Clave_Semilla_Principal, uint8_t VEV);

void Aplicar_Torsion_Principal(std::vector<uint8_t> &buffer, uint64_t Total_Bytes_Brana);
void Restaurar_Torsion_Principal(std::vector<uint8_t> &buffer, uint64_t Total_Bytes_Brana);
uint64_t Aplicar_Salto_Masa(uint64_t Dato, uint64_t Semilla_Dual_ENC, uint64_t Offset_Byte, uint64_t Semilla_Mutante);
void Torsionar_Base(uint64_t estado[8], uint64_t Constante);
void Array_Torsion(uint64_t estado[8]);

void Encriptacion_Principal(std::vector<uint8_t> &buffer, uint64_t Inicio, uint64_t Final, uint64_t Frecuencia_Final, uint64_t Clave_CRC, bool iva, uint64_t Frecuencia_Dispersion, uint64_t Clave_Temp, uint64_t REFERENCIA, uint64_t Semilla, bool Modo);
void Desencriptacion_Principal(std::vector<uint8_t> &buf, uint64_t Inicio, uint64_t Final, uint64_t Frecuencia_Final, uint64_t Clave_CRC, bool iva, uint64_t Frecuencia_Dispersion, uint64_t Clave_Temp, uint64_t REFERENCIA, uint64_t Semilla, bool modo);

void Aplicar_Defensa_Activa(int64_t fd, uint64_t Fin_Header, uint64_t Fatiga_Final, uint64_t Valor_Defensa, uint64_t Semilla_Ofuscacion, uint64_t Bytes_A_Defender);
void Restaurar_Defensa_Activa(int64_t fdIn, uint64_t InicioData, uint64_t Fatiga_Leida, uint64_t Valor_Defensa, uint64_t Semilla_Ofuscacion, uint64_t Bytes_A_Procesar);


#ifndef VUELTAS_OVILLO
#define VUELTAS_OVILLO 1000001ULL
#endif
#ifndef METRICA_L
#define METRICA_L 64ULL
#endif

struct alignas(METRICA_L) BranaDatos
{
    float Fase_Vorticidad[VUELTAS_OVILLO];
    float Espejo_Adelico[VUELTAS_OVILLO];
    float Torsion_Cook;
};

extern float SIGMA_YANG_MILLS;

void Procesar_Ovillo(BranaDatos *brana, uint64_t Semilla_Dual_ENC);
void Inicializar_Rigidez_Adelica(BranaDatos *brana, uint8_t *datos_buffer, size_t Bytes);
bool Validar_Ciclos_Hodge(const BranaDatos *brana);


void Inicializar_TABLA_ENTROPIA();
double Calcular_Entropia_Shannon(const uint8_t *datos, size_t tam);
void Estabilizar_Brana(BranaDatos *brana, const uint8_t *Bloque, size_t Longitud_Bloque, float *Torsor_Actual);


void Brana_Expandir_Desde_KMaster(const uint8_t K[32], uint64_t CRC_Control,
    uint64_t &Clave_ENC, uint64_t &Usuario_ENC,
    uint64_t &Clave_Semilla_Principal, uint64_t &Usuario_Semilla_Principal);


uint64_t rotr64(uint64_t Valor, uint64_t Bits);
void Evolucionar_Ecosistema_Semillas(
    uint64_t &s_prin, uint64_t &s_alt, uint64_t &s_enc,
    uint64_t &c_prin, uint64_t &c_alt, uint64_t &c_enc);

#endif


