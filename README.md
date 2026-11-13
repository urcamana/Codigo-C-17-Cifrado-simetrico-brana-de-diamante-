# Codigo-C-17-Cifrado-simetrico-brana-de-diamante-
Brana de Diamante es una implementación experimental en C++17 de un cifrado simétrico basado en torsión de estado (ovillo) y un generador de keystream propio (V5_Flujo), orientado al cifrado de archivos y a modos auxiliares de campo y stream.

El diseño es propio y no se presenta como sustituto evaluado de AES, ChaCha20 u otros estándares hasta que exista revisión independiente por terceros y por la comunidad. (Agradezco ayudas, comentarios, etc...).

Alcance V6:
Encriptador y desencriptador modulares (util, container, crypto, wide, pool).
KDF con salt público y perfiles de coste (-k).
Cifrado principal del cuerpo mediante V5_Flujo (F), alineado a la lógica de Encriptacion_Principal (VEV, tabla viscosa, Array_Torsion, Salto_Masa), manteniendo el contrato stream (claro XOR keystream).
Contenedor .brana: ovillo (vueltas adaptativas), faro, defensa, inercia; doble MAC (ciphertext pre-defensa y comprobación sobre el claro recuperado).
Ancho institucional (BRANA_BITS, múltiplo de 32, mínimo 256): lo fija quien compila el encriptador; el desencriptador es universal y lee el ancho desde el contenedor.
Empaquetado .bulk, compresión .ov (miniz), wipe opcional, clave señuelo/pánico, verificación superficial (-v) sin credenciales (solo verifica archivo, no claves).
Modos -DB (campo, sobre BRANAF1 en hex) y -S (stream puro, sobre BRANAS1), solo F, sin ovillo/faro/defensa de archivo.
 

Correcciones e incorporaciones respecto a líneas anteriores

Modularización del monolito y separación del motor wide/KDF/MAC/flujo. (Necesitabamos una limpieza de todo el código).
Sustitución del stream genérico por V5_Flujo como capa principal de confidencialidad del cuerpo.
Salt en KDF; reducción de oráculos baratos de contraseña (p. ej. verificadores públicos desligados de usuario/clave).
Desencriptador universal por bits embebidos en el contenedor (sin recompilar por ancho).
Doble MAC en el flujo de archivo .brana y cuidado del orden respecto a la defensa acumulativa.
CLI de producción: perfiles, compresión, wipe, señuelo, campo y stream.


Ancho configurable (frente a techos fijos de AES / ChaCha20)
AES opera con bloque de 128 bit y clave de hasta 256 bit. ChaCha20 usa clave de 256 bit. Brana V6.0 permite fijar en compilación del encriptador un ancho de sesión BRANA_BITS (mínimo 256, múltiplo de 32; p. ej. 512, 1024, 2048, … hasta límites prácticos de memoria/CPU). Ese valor se escribe en el contenedor; el desencriptador lo lee y opera de forma universal.
Esto no sustituye una evaluación criptográfica independiente: el ancho ampliado es una propiedad de diseño e implementación, no una certificación de mayor seguridad que AES-256 o ChaCha20.

Tabla orientativa de implementación (ejemplo)

BRANA_BITS 	-	Clave / bloque F (aprox.)-	Uso orientativo 			-	Hardware orientativo:
256 (default)	-	32 B			 -	Uso general, notebooks			-	4–8 GB RAM, dual/quad core
512		-	64 B			 -	Escritorio / más margen de estado	-	8–16 GB, 4+ núcleos
1024		-	128 B			 -	Estación de trabajo			-	16 GB+, CPU moderna
2048		-	256 B			 -	Servidor / política “ancho alto”	-	16–32 GB, buen single-thread
4096–16384	-	0,5–2 KB		 -	Pruebas / políticas extremas		-	32 GB+, paciencia de CPU
65536		- 	8 KB			 -	Solo experimentación / lab		-	Mucha RAM; el I/O suele dominar

Notas: el tamaño de lectura por hilo del ovillo (Tam_Bloque_Hilo, p. ej. 1 / 2 / 4 MB) es independiente de BRANA_BITS. En equipos modestos conviene 256 + 1 MB/hilo. Subir bits aumenta trabajo de F; en discos lentos o con .ov el tiempo total puede no crecer en la misma proporción.

(Se agradece a la comunidad la realización de pruebas de rendimiento y baterías estadísticas en hardware más avanzado que el usado en el desarrollo — p. ej. estaciones con mayor número de núcleos y más memoria —, y el reporte público de resultados y anomalías.)

 

Lo que todavia falta 

Pruebas sistemáticas de esta binario V6.0 a gran escala (ENT, Dieharder, PractRand, BigCrush u otras baterías en pruebas mayores a 420GB) sobre el keystream y sobre contenedores reales; resultados de versiones previas no se reutilizan automáticamente como prueba de esta build. 
Análisis formal de seguridad, criptoanálisis y comparación rigurosa con primitivas consolidadas: pendientes y abiertos a la comunidad.
Auditoría de implementación (canales laterales, oráculos residuales, maleabilidad en -DB/-S sin MAC de producto).
Revisión de pares y uso en entornos reales solo tras evaluación externa.


Convocatoria a revisión

Se publica el código para uso personal, académico e investigación bajo la licencia indicada, con el objetivo explícito de que terceros y la comunidad revisen el diseño, la implementación y las pruebas. No se afirma equivalencia de seguridad con AES-256/ChaCha20 ni madurez de producto industrial hasta esa revisión.



Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)

Licencia
Creative Commons Atribución-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0).
Uso comercial, integración en software propietario o empleo por entidades gubernamentales/industriales requiere autorización del autor y convenio de transferencia tecnológica.

miniz.c / miniz.h — biblioteca de terceros (ver cabecera del archivo).

DOI ZENODO: https://doi.org/10.5281/zenodo.24165264