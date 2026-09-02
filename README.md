# 🤖 HAL — Asistente Forense de Core Dumps y Segfaults en C

HAL es una herramienta standalone diseñada para diagnosticar fallos en tiempo de ejecución (`SIGSEGV`, `SIGABRT`, `SIGFPE`, `SIGILL`) en programas C estudiantiles, traduciendo volcados crudos y backtraces de GDB a explicaciones pedagógicas claras en español rioplatense con ubicación exacta de la falla y acciones correctivas concretas.

---

## 🎯 Alcance

### Qué cubre
- Asistencia forense automatizada post-mortem para fallos catastróficos en programas C.
- Diagnóstico e inspección de señales fatales (`SIGSEGV`, `SIGABRT`, `SIGFPE`, `SIGILL`).
- Análisis de volcados de memoria (core dumps) y extracción automatizada de trazas de ejecución (backtraces) mediante GDB en modo batch.
- Identificación de variables locales comprometidas, punteros desreferenciados y ubicación exacta de la instrucción culpable.
- Traducción del diagnóstico técnico a explicaciones didácticas en español rioplatense.

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

### Integración en el Ecosistema
- CLI `hal`. Subcomando `hal doctor`. Integración con `dredd` para diagnóstico de fallos en entregas.

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

# 5. Comprobar salud del entorno (GCC, GDB, Valgrind)
hal doctor
```
