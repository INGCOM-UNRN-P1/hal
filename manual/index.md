---
title: "Manual de Referencia: hal"
subtitle: "Hal — Asistente Forense de Core Dumps y Análisis Post-Mortem de Segfaults en C"
author: "Cátedra de Algoritmos y Programación"
date: "2026-08-31"
---

(manual-hal)=
# Hal — Asistente Forense de Core Dumps y Análisis Post-Mortem de Segfaults en C

````{abstract}
**Rol en el ecosistema:** Diagnóstico forense automático de caídas fatales (SIGSEGV, SIGABRT, SIGFPE), inspección de core dumps, extracción de stack traces con GDB y explicación didáctica en español rioplatense.
````

---

(manual-hal-proposito)=
## 1. Propósito y Filosofía Pedagógica

La herramienta **`hal`** forma parte del ecosistema oficial de software de la cátedra. Su diseño sigue principios pedagógicos rigurosos:

1. **Evidencia Técnica Directa**: Todo diagnóstico se fundamenta en la norma ISO C (C11/C23), en el modelo de memoria del sistema o en convenciones arquitectónicas formales.
2. **Acción Correctiva Concreta**: Cada advertencia incluye la prescripción técnica inmediata para resolver el defecto sin recurrir a conjeturas.
3. **Autonomía del Estudiante**: Facilita la autoevaluación local antes de la entrega final del trabajo práctico.
4. **Objetividad Docente**: Estandariza la corrección automática eliminando discrepancias subjetivas en la evaluación.

---

(manual-hal-instalacion)=
## 2. Instalación y Diagnóstico del Entorno

````{important}
Asegurate de contar con el compilador GCC/Clang y las librerías del sistema instaladas antes de ejecutar `hal`.
````

Para comprobar el estado de salud de tu entorno de trabajo y las dependencias auxiliares:

````{code-block} bash
# Comprobación de dependencias del sistema
hal doctor
````

Si se detecta la falta de alguna utilidad (como `gdb`, `valgrind`, `clang-format` o `typst`), el comando indicará el paquete exacto a instalar según tu distribución GNU/Linux o entorno MSYS2.

---

(manual-hal-comandos)=
## 3. Referencia Completa de Comandos CLI

A continuación se detallan los subcomandos principales disponibles en `hal`:

| Sintaxis del Comando | Descripción y Efecto |
| :--- | :--- |
| `hal inspect ./bin/programa [args]` | Ejecuta el binario, captura el crash y genera el diagnóstico. |
| `hal core ./bin/programa core.dump` | Analiza post-mortem un archivo core dump generado por el kernel. |
| `hal valgrind ./bin/programa` | Ejecuta Valgrind y traduce las fugas y accesos inválidos. |
| `hal doctor` | Verifica la configuración de límites de core dump (`ulimit -c`) y GDB. |

````{tip}
Podés agregar el flag `--json` a la mayoría de los comandos para exportar resultados en formato estructurado o `--md` para generar reportes Markdown para el informe de entrega.
````

---

(manual-hal-tutorial)=
## 4. Tutorial Paso a Paso con Ejemplos Reales

### Caso de Estudio

Considerá el siguiente fragmento de código representativo:

````{code-block} c
:linenos:
#include <stdio.h>

typedef struct {
    int id;
    char *nombre;
} t_usuario;

void imprimir_usuario(t_usuario *u) {
    printf("Usuario: %s (ID: %d)\n", u->nombre, u->id); // Crash si u es NULL o nombre es NULL
}

int main(void) {
    t_usuario *u = NULL;
    imprimir_usuario(u);
    return 0;
}
````

### Ejecución de la Herramienta

Ejecutá el análisis desde tu terminal:

````{code-block} bash
hal inspect ./bin/programa [args]
````

### Salida Obtenida en Consola

````{code-block} text
💥 SEÑAL FATAL DETECTADA: SIGSEGV (Violación de Segmento)
Ubicación: src/main.c:9 en función 'imprimir_usuario()'
Dirección de memoria inválida: 0x0000000000000004 (SEGV_MAPERR)

📋 STACK TRACE FORENSE:
  #0  imprimir_usuario (u=0x0) at src/main.c:9
  #1  main () at src/main.c:14

💡 DIAGNÓSTICO PEDAGÓGICO DE HAL:
  Intentaste acceder al campo 'u->id' a través de un puntero NULO (u == NULL).
  El procesador intentó leer la dirección 0x4 (desplazamiento del campo dentro del struct) que no pertenece al espacio de memoria de tu programa.

🔧 ACCIÓN RECOMENDADA:
  Agregá una verificación defensiva al inicio de 'imprimir_usuario':
  if (u == NULL || u->nombre == NULL) { return; }
````

````{note}
Prestá atención a la explicación pedagógica generada: la herramienta no solo señala la línea del problema, sino que explica la causa raíz y el impacto en memoria o arquitectura.
````

---

(manual-hal-ejercicios)=
## 5. Ejercicios Prácticos y Desafíos

Practicá el uso avanzado de **`hal`** resolviendo los siguientes ejercicios:

````{exercise} Desafío 1: Diagnóstico de Puntero Nulo
Ejecutar un binario con crash por NULL y revisar el stack trace pedagógico.

**Instrucción de ejecución:**
```bash
hal inspect ./bin/crash_null
```
````

````{solution} Desafío 1
```bash
hal inspect ./bin/crash_null
# Verificá que la operación concluya exitosamente con código de salida 0.
```
````

````{exercise} Desafío 2: Análisis de Core Dump Post-Mortem
Inspeccionar un core dump generado en un servidor sin volver a compilar.

**Instrucción de ejecución:**
```bash
hal core ./bin/servidor /var/cores/core.1234
```
````

````{solution} Desafío 2
```bash
hal core ./bin/servidor /var/cores/core.1234
# Revisá el archivo generado o el informe en terminal para confirmar la resolución del problema.
```
````

````{exercise} Desafío 3: Traducción de Acceso Fuera de Límites (Buffer Overflow)
Diagnosticar un segfault provocado por escribir en `vec[1000000]`.

**Instrucción de ejecución:**
```bash
hal inspect ./bin/crash_bounds
```
````

````{solution} Desafío 3
```bash
hal inspect ./bin/crash_bounds
# Comprobá que la salida confirme la ausencia de advertencias o errores pendientes.
```
````

---

(manual-hal-makefile)=
## 6. Integración en el Flujo de Trabajo y Makefile

Para incorporar `hal` de forma automática a tu flujo de desarrollo, agregá la siguiente regla en el `Makefile` de tu proyecto:

````{code-block} makefile
check-hal:
	@echo "=== Ejecutando verificación con hal ==="
	hal check src/ include/

.PHONY: check-hal
````

Ejecutá `make check-hal` antes de cada commit para asegurar que tu código conserve el estado de aprobación.
