/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */

#ifndef BRANA_CONTAINER_H
#define BRANA_CONTAINER_H
#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

double Entropia_Shannon(const std::string &path);
bool Entropia_Es_Alta(const std::string &path);
bool Comprimir_Buffer(const uint8_t *in, size_t in_len, std::vector<uint8_t> &out, int nivel = 6);
bool Descomprimir_Buffer(const uint8_t *in, size_t in_len, std::vector<uint8_t> &out, size_t expected_out = 0);
bool Crear_Archivo_OV(const std::string &path_in, const std::string &path_ov);
bool Leer_Archivo_Completo(const std::string &path, std::vector<uint8_t> &out);
bool Crear_Archivo_BULK(const std::vector<std::string> &paths,
                        const std::vector<std::string> &nombres_rel,
                        const std::string &path_bulk);
bool Crear_Archivo_BULK(const std::vector<std::string> &paths, const std::string &path_bulk);

bool Extraer_OV(const std::string &path_in, std::string &path_out_generado);
bool Extraer_BULK(const std::string &path_bulk, const std::string &carpeta_destino);
void Postproceso_Capas(std::string &path_recuperado);

#endif
