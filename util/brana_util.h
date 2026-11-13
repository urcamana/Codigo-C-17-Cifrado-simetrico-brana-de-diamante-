/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */

#ifndef BRANA_UTIL_H
#define BRANA_UTIL_H
#include <string>
#include <vector>
#include <cstdint>

bool Clave_Cumple_Politica(const std::string &clave, std::string &motivo);
void Mostrar_Ayuda_Encriptador();
void Mostrar_Ayuda_Desencriptador();

bool Es_Directorio(const std::string &path);
void Listar_Archivos_Recursivo(const std::string &dir, const std::string &prefijo,
    std::vector<std::string> &paths, std::vector<std::string> &nombres_rel);
bool Listar_Archivos_En_Carpeta(const std::string &dir, std::vector<std::string> &out);
std::string Nombre_Base_Carpeta(const std::string &dir);
std::string Crear_Dir_Temporal();
void Borrar_Archivo_Si_Existe(const std::string &path);
void Limpiar_Dir_Temporal();
std::string Path_En_Temp(const std::string &nombre);
std::string Solo_Nombre(const std::string &path);

extern std::string Dir_Temporal;
extern std::string path_bulk_intermedio;
extern std::string path_ov_intermedio;


size_t Verificar_Ram_Libre();
int64_t Optimizar_Hilos_CPU(uint64_t Tam_Segm_Fijo);
float Obtener_Frecuencia_Cpu();
void Optimizar_Sistema();


bool Bloquear_Archivo(int fd);
void Desbloquear_Archivo(int fd);
uint64_t Calcular_Longitud_Relleno(uint64_t Control_Semilla, uint64_t CRC_Control);

bool Wipe_Archivo(const std::string &path);

#endif


