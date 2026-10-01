# 🤖 HAL — Asistente Forense de Core Dumps y Segfaults en C

> 📖 **Manual de Usuario:** Para una guía exhaustiva de comandos, banderas, arquitectura y ejemplos, consultá el [Manual de Uso](MANUAL.md).

HAL es una herramienta standalone diseñada para diagnosticar fallos en tiempo de ejecución (`SIGSEGV`, `SIGABRT`, `SIGFPE`, `SIGILL`) en programas C estudiantiles, traduciendo volcados crudos y backtraces de GDB a explicaciones pedagógicas claras en español rioplatense con ubicación exacta de la falla y acciones correctivas concretas.

---

## 🎯 Alcance

### Qué cubre
- Asistencia forense automatizada post-mortem para fallos catastróficos en programas C.
- Diagnóstico e inspección de señales fatales (`SIGSEGV`, `SIGABRT`, `SIGFPE`, `SIGILL`).
- Análisis de volcados de memoria (core dumps) y extracción automatizada de trazas de ejecución (backtraces) mediante GDB en modo batch.
- Identificación de variables locales comprometidas, punteros desreferenciados y ubicación exacta de la instrucción culpable.
- Traducción del diagnóstico técnico a explicaciones didácticas en español rioplatense.
- Modo pista para evaluaciones (`check --pista` o `P1_PISTA=1`, que ripley exporta con `[general] pistas = true`): la señal, la causa y la función donde ocurrió, sin la línea, la variable culpable, los valores de la pila ni la corrección.

### Qué no cubre (Límites y Delegación)
- Auditoría preventiva de seguridad en código fuente estático (delegado a `kaneda`).
- Aislamiento en sandbox de la ejecución (delegado a `nostromo`).
- Traducción de salidas de sanitizers de compilador (delegado a `tetsuo`).

---

## 📋 Requisitos

### Requisitos de Sistema y Entorno
- Linux (nativo o WSL). Python >= 3.10.

### Dependencias Externas y Binarios
- `gdb`, `gcc` (con símbolos de depuración `-g`).

### Integración en el Ecosistema y Frontera R-B6
- **Responsabilidad Canónica:** `R-B6` — Análisis forense post-mortem de caídas por señales (`SIGSEGV`, `SIGABRT`, `SIGFPE`, `SIGILL`, `SIGBUS`) y diagnóstico explicativo pedagógico.
- **Contrato Estructurado:** CLI emite JSON versión 1.0.0 (`schema_version: "1.0.0"`) conteniendo diagnóstico estructurado (`tipo_senal`, `causa_raiz_titulo`, `explicacion`, `accion_correctiva`, `archivo_falla`/`archivo`, `linea_falla`/`linea`, `frames`, etc.).
- **Consumidores:**
  - `spunkmeyer`: consume `archivo` y `linea` para correlacionar caídas de ejecución con antipatrones estáticos detectados (`spunkmeyer correlate-hal`).
  - `nostromo`: consume `hal.core.inspector:inspeccionar_fuente_o_binario` ante fallos catastróficos por señales (`SEGFAULT`, `ABORT`, `FPE`) en suites de testcases.
  - `dredd`: consume `hal run --md` / `hal report` (sección `hal.md` en reportes de corrección docente).
  - `ripley`: orquestador microkernel. Los diagnósticos de crash pueden ser consumidos vía subprocess `hal run <archivo> --json` o inspección directa en Python.
- **Delegaciones Formales:**
  - Compilación cátedra: delegada en daedalus (`daedalus compile`).
  - Inyección deliberada en runtime: delegada en vasquez (`LD_PRELOAD` de `libvasquez_inject.so`).
  - Sandboxing de ejecución: delegado en nostromo.
  - Análisis de sanitizers: delegado en tetsuo.

---

## Instalación

```bash
uv tool install --editable .
```

## Uso Rápido

```bash
# 1. Compilar, ejecutar y diagnosticar un archivo fuente C
hal run programa_con_fallo.c

# 2. Diagnosticar con salida estructurada JSON para bots y CI
hal run programa_con_fallo.c --json

# 3. Pasar argumentos y datos por stdin
hal run programa.c arg1 arg2 --stdin "10\n20\n"

# 4. Inspeccionar un binario precompilado
hal inspect ./binario_compilado

# 5. Comprobar salud del entorno (GCC, GDB, Valgrind, addr2line)
hal doctor
hal doctor --json
```

## Capacidades Avanzadas e Integración con Vasquez

### 6. Auditoría de Resiliencia e Inyección de Fallos en Runtime (Vasquez)
HAL permite evaluar la robustez del programa frente a fallos del entorno (memoria agotada, punteros nulos forzados) integrándose con `vasquez` vía `LD_PRELOAD`:

```bash
# Inyectar fallo en la 1° llamada a malloc
hal run programa.c --inject-vasquez --fail-malloc-at 1

# Inyectar fallo en la 2° llamada a realloc o calloc
hal run programa.c --inject-vasquez --fail-realloc-at 2
hal run programa.c --inject-vasquez --fail-calloc-at 1

# Cascada de fallos: fallar todas las reservas posteriores al primer fallo
hal run programa.c --inject-vasquez --fail-malloc-at 1 --cascade

# Rellenar memoria asignada con bytes basura no nulos (0xAA)
hal run programa.c --inject-vasquez --garbage-memory
```

### 7. Repetición Forense y Generación de Reproductores Autónomos
```bash
# Re-ejecutar interactivamente paso a paso la traza forense del crash
hal replay programa.c

# Generar script de reproducción autocontenido en Bash para compartir
hal generate-reproducer programa.c -o reproductor.sh
```

### 8. Inspección de Estructuras, Registros y Descriptores
```bash
# Inspeccionar variables y campos de struct en el punto de quiebre
hal inspect-struct programa.c mi_nodo

# Volcar registros de CPU (RAX, RSP, RIP) en formato estructurado
hal registers programa.c --json

# Auditar balance de descriptores de archivo (FILE* y fd)
hal check-fds programa.c

# Desofuscar una dirección de memoria DWARF a archivo y línea
hal resolve-addr ./binario 0x555555555169

# Parsear reporte de Valgrind Memcheck a explicaciones en lenguaje natural
hal parse-valgrind valgrind.log

# Consultar consejos pedagógicos didácticos
hal advice --json
```

<!-- p1:referencia:inicio — generado por p1-tools/scripts/readme_generado.py: no editar a mano -->

## Referencia rápida

### Requisitos

- Python ≥ 3.11 y [uv](https://docs.astral.sh/uv/getting-started/installation/).
- Programas del sistema: `gcc`, `gdb`, `valgrind`.

| Sistema | `gcc` | `gdb` | `valgrind` |
|:--|:--|:--|:--|
| Debian / Ubuntu | `sudo apt install gcc` | `sudo apt install gdb` | `sudo apt install valgrind` |
| Fedora | `sudo dnf install gcc` | `sudo dnf install gdb` | `sudo dnf install valgrind` |
| Windows | incluido en el entorno de la cátedra (MSYS2 UCRT64) | incluido en el entorno de la cátedra (MSYS2 UCRT64) | no existe: usar WSL |
| macOS | `xcode-select --install` (clang como `gcc`) | `brew install gdb` (en Apple Silicon no está: usar `lldb`) | no existe en Apple Silicon |

### Comandos

| Comando | Descripción |
|:--|:--|
| `hal check`, `hal run` | Compila (si es .c), ejecuta el programa y genera un diagnóstico forense pedagógico si ocurre un crash. |
| `hal report` | Genera directamente la sección de reporte Markdown de HAL para Dredd o exporta a HTML/Discussions. |
| `hal inspect` | Inspecciona un binario compilado ante posibles fallos de ejecución. |
| `hal inspect-struct`, `hal struct` | Inspecciona y vuelca los campos de una estructura (struct) en memoria (Mejora 22). |
| `hal doctor` | Verifica el estado del entorno (GCC, GDB, Valgrind, addr2line). |
| `hal generate-reproducer` | Genera un script autónomo en Bash para reproducir exactamente el crash en cualquier máquina. |
| `hal replay` | Ejecuta y navega paso a paso la traza forense del crash con renderizado Rich. |
| `hal registers` | Muestra los valores de los registros de CPU (RAX, RSP, RIP, etc.) capturados durante el crash. |
| `hal check-fds` | Audita aperturas de archivos y descriptores huérfanos sin cerrar. |
| `hal inspect-globals` | Inspecciona las variables globales y estáticas (.data y .bss) en la memoria del binario. |
| `hal resolve-addr` | Traduce una dirección de memoria hexadecimal a archivo, línea y nombre de función. |
| `hal parse-valgrind`, `hal valgrind` | Parsea reportes de Valgrind Memcheck y traduce violaciones a explicaciones pedagógicas. |
| `hal advice` | Muestra consejos pedagógicos y buenas prácticas defensivas para evitar segfaults. |

Ayuda de cada comando: `hal <comando> -h`.

<!-- p1:referencia:fin -->
