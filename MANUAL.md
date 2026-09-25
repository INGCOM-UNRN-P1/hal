# Manual de Uso y Referencia Técnica: hal

> **HAL** — Asistente forense de core dumps y análisis pedagógico post-mortem de segfaults en C
> **Versión:** `0.1.0` · **CLI principal:** `hal` · **Plugin Ripley:** `hal`

---

## 1. Arquitectura y Propósito Pedagógico

`hal` forma parte del ecosistema de herramientas de la cátedra de Programación 1 (UNRN). Su objetivo central es resolver de forma modular, determinista y automatizada las tareas asociadas a su dominio específico dentro del ciclo de desarrollo, evaluación y aprendizaje de software en C.

### Alcance Funcional (Qué cubre)
- Asistencia forense automatizada post-mortem para fallos catastróficos en programas C.
- Diagnóstico e inspección de señales fatales (`SIGSEGV`, `SIGABRT`, `SIGFPE`, `SIGILL`).
- Análisis de volcados de memoria (core dumps) y extracción automatizada de trazas de ejecución (backtraces) mediante GDB en modo batch.
- Identificación de variables locales comprometidas, punteros desreferenciados y ubicación exacta de la instrucción culpable.
- Traducción del diagnóstico técnico a explicaciones didácticas en español rioplatense.

### Límites de Responsabilidad y Delegación (Qué no cubre)
- Auditoría preventiva de seguridad en código fuente estático (delegado a `kaneda`).
- Aislamiento en sandbox de la ejecución (delegado a `nostromo`).
- Traducción de salidas de sanitizers de compilador (delegado a `tetsuo`).

### Principios de Diseño
- **Enfoque Pedagógico:** Diagnósticos y mensajes en español rioplatense orientados a facilitar la comprensión de errores conceptuales.
- **Salida Estructurada Dual:** Soporte nativo para visualización enriquecida en terminal (Rich) y salida parseable para orquestadores (`--json`).
- **Integración Contractual:** Capacidad de emitir secciones de reporte para `dredd` (`dredd-section`) y actuar como satélite orquestado por `ripley`.
- **Idempotencia y Robustez:** Validación de precondiciones y comandos de autodiagnóstico (`doctor`) para verificación del entorno.

---

## 2. Instalación y Requisitos

### Requisitos del Sistema
- **Python:** `>= 3.10` (recomendado Python 3.11 o 3.12).
- **Gestor de paquetes:** [`uv`](https://github.com/astral-sh/uv) (entorno estándar de cátedra).
- **Toolchain C (si aplica):** GCC / Clang, Make, GDB y bibliotecas estándar de desarrollo.

### Instalación en el Entorno de Usuario
Para instalar la herramienta de forma global y aislada en el sistema mediante `uv tool`:
```bash
uv tool install --editable /home/mrtin/dev/tools/hal
```

### Verificación de Instalación
Ejecutá el comando `doctor` para constatar que todas las dependencias y binarios requeridos estén presentes y operativos:
```bash
hal doctor
```

---

## 3. Guía Integral de Comandos (CLI)

| Comando | Descripción Breve |
| :--- | :--- |
| [`hal check`](#check) | Compila (si es .c), ejecuta el programa y genera un diagnóstico forense pedagógico si ocurre un crash. |
| [`hal run`](#run) | Compila (si es .c), ejecuta el programa y genera un diagnóstico forense pedagógico si ocurre un crash. |
| [`hal report`](#report) | Genera directamente la sección de reporte Markdown de HAL para Dredd o exporta a HTML/Discussions. |
| [`hal inspect`](#inspect) | Inspecciona un binario compilado ante posibles fallos de ejecución. |
| [`hal inspect-struct`](#inspectstruct) | Inspecciona y vuelca los campos de una estructura (struct) en memoria (Mejora 22). |
| [`hal struct`](#struct) | Inspecciona y vuelca los campos de una estructura (struct) en memoria (Mejora 22). |
| [`hal doctor`](#doctor) | Verifica el estado del entorno (GCC, GDB, Valgrind, addr2line). |
| [`hal generate-reproducer`](#generatereproducer) | Genera un script autónomo en Bash para reproducir exactamente el crash en cualquier máquina. |
| [`hal replay`](#replay) | Ejecuta y navega paso a paso la traza forense del crash con renderizado Rich. |
| [`hal registers`](#registers) | Muestra los valores de los registros de CPU (RAX, RSP, RIP, etc.) capturados durante el crash. |
| [`hal check-fds`](#checkfds) | Audita aperturas de archivos y descriptores huérfanos sin cerrar. |
| [`hal inspect-globals`](#inspectglobals) | Inspecciona las variables globales y estáticas (.data y .bss) en la memoria del binario. |
| [`hal resolve-addr`](#resolveaddr) | Traduce una dirección de memoria hexadecimal a archivo, línea y nombre de función. |
| [`hal parse-valgrind`](#parsevalgrind) | Parsea reportes de Valgrind Memcheck y traduce violaciones a explicaciones pedagógicas. |
| [`hal valgrind`](#valgrind) | Parsea reportes de Valgrind Memcheck y traduce violaciones a explicaciones pedagógicas. |
| [`hal advice`](#advice) | Muestra consejos pedagógicos y buenas prácticas defensivas para evitar segfaults. |

### `hal check`

Compila (si es .c), ejecuta el programa y genera un diagnóstico forense pedagógico si ocurre un crash.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `objetivo` | `Path` | Ruta al archivo C (.c) o binario a ejecutar y diagnosticar. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--args` | `Optional[List[str]]` | `None` | Argumentos a pasar al programa. |
| `--stdin`, `-i` | `Optional[str]` | `None` | Cadena de texto para enviar a la entrada estándar (stdin). |
| `--json` | `bool` | `False` | Emitir diagnóstico estructurado en formato JSON. |
| `--gdb` | `Optional[str]` | `None` | Ruta al binario de GDB. |
| `--md`, `--output-md`, `-o` | `Optional[Path]` | `None` | Generar sección de reporte en formato Markdown para fusión en Dredd. |
| `--advice` | `bool` | `False` | Mostrar consejos pedagógicos adicionales. |
| `--struct`, `-s` | `Optional[str]` | `None` | Nombre de la variable struct o puntero a struct a inspeccionar en memoria. |
| `--inject-vasquez` | `bool` | `False` | Activar inyección de fallos con Vasquez vía LD_PRELOAD. |
| `--fail-malloc-at` | `Optional[int]` | `None` | Inyectar fallo (NULL) en la N-ésima llamada a malloc. |
| `--fail-realloc-at` | `Optional[int]` | `None` | Inyectar fallo (NULL) en la N-ésima llamada a realloc. |
| `--fail-calloc-at` | `Optional[int]` | `None` | Inyectar fallo (NULL) en la N-ésima llamada a calloc. |
| `--cascade`, `--vasquez-cascade` | `bool` | `False` | Activar fallos en cascada tras el primer error. |
| `--garbage-memory`, `--vasquez-garbage` | `bool` | `False` | Envenenar bloques asignados con bytes basura. |
| `--html` | `Optional[Path]` | `None` | Ruta para exportar el reporte interactivo en HTML. |
| `--discussion-md` | `Optional[Path]` | `None` | Ruta para exportar plantilla Markdown para GitHub Discussions. |
| `--all-frames` | `bool` | `False` | Mostrar marcos de pila de libc/sistema completos. |

#### Ejemplo de Invocación
```bash
hal check <objetivo>
```

### `hal run`

Compila (si es .c), ejecuta el programa y genera un diagnóstico forense pedagógico si ocurre un crash.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `objetivo` | `Path` | Ruta al archivo C (.c) o binario a ejecutar y diagnosticar. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--args` | `Optional[List[str]]` | `None` | Argumentos a pasar al programa. |
| `--stdin`, `-i` | `Optional[str]` | `None` | Cadena de texto para enviar a la entrada estándar (stdin). |
| `--json` | `bool` | `False` | Emitir diagnóstico estructurado en formato JSON. |
| `--gdb` | `Optional[str]` | `None` | Ruta al binario de GDB. |
| `--md`, `--output-md`, `-o` | `Optional[Path]` | `None` | Generar sección de reporte en formato Markdown para fusión en Dredd. |
| `--advice` | `bool` | `False` | Mostrar consejos pedagógicos adicionales. |
| `--struct`, `-s` | `Optional[str]` | `None` | Nombre de la variable struct o puntero a struct a inspeccionar en memoria. |
| `--inject-vasquez` | `bool` | `False` | Activar inyección de fallos con Vasquez vía LD_PRELOAD. |
| `--fail-malloc-at` | `Optional[int]` | `None` | Inyectar fallo (NULL) en la N-ésima llamada a malloc. |
| `--fail-realloc-at` | `Optional[int]` | `None` | Inyectar fallo (NULL) en la N-ésima llamada a realloc. |
| `--fail-calloc-at` | `Optional[int]` | `None` | Inyectar fallo (NULL) en la N-ésima llamada a calloc. |
| `--cascade`, `--vasquez-cascade` | `bool` | `False` | Activar fallos en cascada tras el primer error. |
| `--garbage-memory`, `--vasquez-garbage` | `bool` | `False` | Envenenar bloques asignados con bytes basura. |
| `--html` | `Optional[Path]` | `None` | Ruta para exportar el reporte interactivo en HTML. |
| `--discussion-md` | `Optional[Path]` | `None` | Ruta para exportar plantilla Markdown para GitHub Discussions. |
| `--all-frames` | `bool` | `False` | Mostrar marcos de pila de libc/sistema completos. |

#### Ejemplo de Invocación
```bash
hal run <objetivo>
```

### `hal report`

Genera directamente la sección de reporte Markdown de HAL para Dredd o exporta a HTML/Discussions.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `objetivo` | `Path` | Ruta al archivo C (.c) o binario a diagnosticar. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--output`, `-o` | `Optional[Path]` | `None` | Ruta de destino del archivo Markdown. |
| `--stdin`, `-i` | `Optional[str]` | `None` | Entrada estándar. |
| `--html` | `Optional[Path]` | `None` | Ruta para exportar el reporte interactivo en HTML. |
| `--discussion-md` | `Optional[Path]` | `None` | Ruta para exportar plantilla Markdown para GitHub Discussions. |
| `--json` | `bool` | `False` | Emitir diagnóstico en formato JSON. |

#### Ejemplo de Invocación
```bash
hal report <objetivo>
```

### `hal inspect`

Inspecciona un binario compilado ante posibles fallos de ejecución.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `binario` | `Path` | Binario ejecutable a inspeccionar. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--json` | `bool` | `False` | Emitir diagnóstico en formato JSON. |
| `--gdb` | `Optional[str]` | `None` | Ruta a GDB. |
| `--md`, `--output-md` | `Optional[Path]` | `None` | Generar sección de reporte en Markdown. |
| `--struct`, `-s` | `Optional[str]` | `None` | Nombre de la variable struct o puntero a struct a inspeccionar. |
| `--inject-vasquez` | `bool` | `False` | Activar inyección de fallos con Vasquez vía LD_PRELOAD. |
| `--fail-malloc-at` | `Optional[int]` | `None` | Inyectar fallo en la N-ésima llamada a malloc. |
| `--fail-realloc-at` | `Optional[int]` | `None` | Inyectar fallo en la N-ésima llamada a realloc. |
| `--fail-calloc-at` | `Optional[int]` | `None` | Inyectar fallo en la N-ésima llamada a calloc. |
| `--cascade`, `--vasquez-cascade` | `bool` | `False` | Activar fallos en cascada. |
| `--garbage-memory`, `--vasquez-garbage` | `bool` | `False` | Envenenar memoria asignada. |

#### Ejemplo de Invocación
```bash
hal inspect <binario>
```

### `hal inspect-struct`

Inspecciona y vuelca los campos de una estructura (struct) en memoria (Mejora 22).

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `objetivo` | `Path` | Archivo .c o binario a ejecutar e inspeccionar. |
| `struct_nombre` | `str` | Nombre de la variable struct o puntero a struct. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--stdin`, `-i` | `Optional[str]` | `None` | Entrada estándar. |
| `--json` | `bool` | `False` | Emitir salida en formato JSON. |
| `--gdb` | `Optional[str]` | `None` | Ruta a GDB. |

#### Ejemplo de Invocación
```bash
hal inspect-struct <objetivo> <struct_nombre>
```

### `hal struct`

Inspecciona y vuelca los campos de una estructura (struct) en memoria (Mejora 22).

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `objetivo` | `Path` | Archivo .c o binario a ejecutar e inspeccionar. |
| `struct_nombre` | `str` | Nombre de la variable struct o puntero a struct. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--stdin`, `-i` | `Optional[str]` | `None` | Entrada estándar. |
| `--json` | `bool` | `False` | Emitir salida en formato JSON. |
| `--gdb` | `Optional[str]` | `None` | Ruta a GDB. |

#### Ejemplo de Invocación
```bash
hal struct <objetivo> <struct_nombre>
```

### `hal doctor`

Verifica el estado del entorno (GCC, GDB, Valgrind, addr2line).

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--json` | `bool` | `False` | Emitir diagnóstico del entorno en formato JSON. |

#### Ejemplo de Invocación
```bash
hal doctor
```

### `hal generate-reproducer`

Genera un script autónomo en Bash para reproducir exactamente el crash en cualquier máquina.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `objetivo` | `Path` | Archivo .c o binario que produce el crash. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--output`, `-o` | `Path` | `reproducer.sh` | Ruta de destino del script bash. |
| `--stdin`, `-i` | `Optional[str]` | `None` | Datos de entrada estándar. |
| `--args`, `-a` | `Optional[str]` | `None` | Argumentos de línea de comando. |
| `--json` | `bool` | `False` | Emitir metadatos del script reproductor en JSON. |

#### Ejemplo de Invocación
```bash
hal generate-reproducer <objetivo>
```

### `hal replay`

Ejecuta y navega paso a paso la traza forense del crash con renderizado Rich.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `objetivo` | `Path` | Archivo .c o binario a re-ejecutar en modo diagnóstico. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--stdin`, `-i` | `Optional[str]` | `None` | Datos de entrada estándar. |
| `--json` | `bool` | `False` | Emitir resultado del replay en formato JSON. |

#### Ejemplo de Invocación
```bash
hal replay <objetivo>
```

### `hal registers`

Muestra los valores de los registros de CPU (RAX, RSP, RIP, etc.) capturados durante el crash.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `objetivo` | `Path` | Archivo .c o binario a inspeccionar. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--stdin`, `-i` | `Optional[str]` | `None` | Entrada estándar. |
| `--json` | `bool` | `False` | Emitir registros en JSON. |

#### Ejemplo de Invocación
```bash
hal registers <objetivo>
```

### `hal check-fds`

Audita aperturas de archivos y descriptores huérfanos sin cerrar.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `fuente` | `Path` | Archivo fuente C a auditar. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--json` | `bool` | `False` | Salida en JSON. |

#### Ejemplo de Invocación
```bash
hal check-fds <fuente>
```

### `hal inspect-globals`

Inspecciona las variables globales y estáticas (.data y .bss) en la memoria del binario.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `binario` | `Path` | Binario a inspeccionar. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--json` | `bool` | `False` | Salida en JSON. |

#### Ejemplo de Invocación
```bash
hal inspect-globals <binario>
```

### `hal resolve-addr`

Traduce una dirección de memoria hexadecimal a archivo, línea y nombre de función.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `binario` | `Path` | Binario ejecutable con símbolos. |
| `direccion` | `str` | Dirección hexadecimal a desofuscar (ej: 0x555555555169). |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--json` | `bool` | `False` | Salida en JSON. |

#### Ejemplo de Invocación
```bash
hal resolve-addr <binario> <direccion>
```

### `hal parse-valgrind`

Parsea reportes de Valgrind Memcheck y traduce violaciones a explicaciones pedagógicas.

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--log-file` | `Optional[Path]` | `None` | Archivo de log de Valgrind o leer desde stdin. |
| `--json` | `bool` | `False` | Salida en JSON. |

#### Ejemplo de Invocación
```bash
hal parse-valgrind
```

### `hal valgrind`

Parsea reportes de Valgrind Memcheck y traduce violaciones a explicaciones pedagógicas.

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--log-file` | `Optional[Path]` | `None` | Archivo de log de Valgrind o leer desde stdin. |
| `--json` | `bool` | `False` | Salida en JSON. |

#### Ejemplo de Invocación
```bash
hal valgrind
```

### `hal advice`

Muestra consejos pedagógicos y buenas prácticas defensivas para evitar segfaults.

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--json` | `bool` | `False` | Emitir consejos pedagógicos en formato JSON. |

#### Ejemplo de Invocación
```bash
hal advice
```

---

## 4. Formatos de Salida e Integración con el Ecosistema

### Modo Interactivo / Terminal (Rich)
Por defecto, la herramienta renderiza paneles, árboles y tablas estilizadas para facilitar la lectura del estudiante y docente en terminales modernas con soporte ANSI.

### Modo Estructurado JSON (`--json`)
Para integración con pipelines de CI/CD, scripts de automatización u orquestadores externos, la opción `--json` emite un documento JSON estricto por la salida estándar (`stdout`), dirigiendo cualquier mensaje de logging a `stderr`:
```bash
hal check --json
```

### Integración con Dredd (`dredd-section`)
Cuando la herramienta genera reportes de evaluación para entregas de alumnos, produce una sección Markdown estandarizada conforme al contrato de integración de Dredd (v1.0.0):
```markdown
<!-- dredd-section: hal, tool=hal, version=0.1.0, status=ok -->
```
Este encabezado garantiza la agregación determinista de los hallazgos en la rúbrica docente.

### Integración con Ripley
`hal` está registrada en el catálogo de plugins satélites de Ripley (`SATELLITE_CATALOG`). Puede invocarse directamente a través del motor de evaluación de Ripley configurando el análisis en `ripley.toml`.

---

## 5. Diagnóstico y Códigos de Salida

### Códigos de Retorno (`exit code`)
| Código | Significado |
| :---: | :--- |
| `0` | Ejecución exitosa sin hallazgos críticos ni errores de sintaxis. |
| `1` | Hallazgos pedagógicos detectados, infracción de reglas o advertencias activas. |
| `2` | Error de sintaxis en argumentos CLI o archivo fuente no encontrado. |
| `>2` | Error no recuperable del sistema, fallo de memoria o excepción interna. |

### Diagnóstico del Entorno (`doctor`)
Ante comportamientos inesperados, verificá el estado operativo con:
```bash
hal doctor
```
Comprueba la presencia de las dependencias requeridas y la integridad de los componentes del paquete.