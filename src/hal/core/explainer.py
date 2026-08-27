"""Motor de diagnóstico pedagógico y síntesis en lenguaje natural en HAL."""

from __future__ import annotations

import re
from typing import List, Optional, Tuple
from hal.core.models import DiagnosticoCrash, StackFrame


def diagnosticar_crash(
    senal: str,
    codigo_senal: Optional[str],
    direccion_memoria: Optional[str],
    frames: List[StackFrame],
    gdb_output: str = "",
    salida_prog: str = "",
) -> DiagnosticoCrash:
    """Genera un diagnóstico pedagógico completo a partir de los datos crudos del fallo."""
    # Extraer frame culpable (primer frame con archivo/línea conocidos)
    frame_falla = None
    for f in frames:
        if f.archivo and not f.archivo.startswith("/usr/") and not f.archivo.startswith("??"):
            frame_falla = f
            break
    if not frame_falla and frames:
        frame_falla = frames[0]

    archivo = frame_falla.archivo if frame_falla else None
    linea = frame_falla.linea if frame_falla else None
    funcion = frame_falla.funcion if frame_falla else None

    # Detectar variable culpable inspeccionando argumentos y variables locales con valor de puntero nulo
    var_culpable = None
    nil_values = ("0x0", "(nil)", "0x00000000", "0x0000000000000000", "NULL")
    if frame_falla:
        # Primero buscar en argumentos (muy común pasar puntero NULL a función)
        for arg, val in frame_falla.argumentos.items():
            if val in nil_values:
                var_culpable = arg
                break
        # Si no, buscar en variables locales
        if not var_culpable:
            for var, val in frame_falla.variables_locales.items():
                if val in nil_values:
                    var_culpable = var
                    break

    # 1. Caso: SIGSEGV (Segmentation Fault)
    if "SEGV" in senal or "SEGMENTATION" in senal.upper() or "SEGMENTATION" in (codigo_senal or "").upper():
        # Analizar si es desreferencia de NULL
        es_null = (
            direccion_memoria in nil_values
            or (direccion_memoria and direccion_memoria.startswith("0x") and int(direccion_memoria, 16) < 0x1000)
            or var_culpable is not None
            or "SEGV_MAPERR" in (codigo_senal or "")
        )

        # Detectar si es stack overflow (recursión infinita)
        if len(frames) > 30 and len(set(f.funcion for f in frames)) <= 3:
            titulo = "Desbordamiento de Pila (Stack Overflow por Recursión Infinita)"
            fn_name = frames[0].funcion if frames else "recursiva"
            explicacion = (
                f"Tu programa agotó el espacio de memoria reservado para la pila de ejecución (Stack).\n"
                f"Se detectaron más de {len(frames)} llamadas recursivas anidadas a la función '{fn_name}'.\n"
                f"Esto ocurre cuando el caso base de la recursión falta, no se cumple nunca, o los parámetros no se acercan al caso base."
            )
            accion = (
                f"1. Verificá que la función '{fn_name}' tenga una condición de corte explícita (caso base).\n"
                f"2. Asegurate de que en cada llamada recursiva los argumentos modifiquen su valor hacia el caso base.\n"
                f"3. Si la recursión es muy profunda por diseño, considerá reescribir el algoritmo de forma iterativa."
            )
            return DiagnosticoCrash(
                tipo_senal="SIGSEGV",
                codigo_senal="STACK_OVERFLOW",
                direccion_memoria=direccion_memoria,
                causa_raiz_titulo=titulo,
                explicacion=explicacion,
                accion_correctiva=accion,
                archivo_falla=archivo,
                linea_falla=linea,
                funcion_falla=funcion,
                variable_culpable=var_culpable,
                frames=frames,
                salida_programa=salida_prog,
            )

        if es_null:
            titulo = "Desreferencia de Puntero Nulo (NULL Pointer Dereference)"
            var_texto = f" de la variable o puntero '{var_culpable}'" if var_culpable else ""
            explicacion = (
                f"El programa intentó leer o escribir en la dirección de memoria {direccion_memoria or '0x0'}{var_texto}.\n"
                f"En la línea {linea or '?'}, se desreferenció un puntero que apuntaba a NULL.\n"
                f"Causas comunes: `malloc()` retornó NULL por falta de memoria o tamaño cero, un puntero no fue inicializado, o se intentó acceder a un elemento fuera de una estructura enlazada."
            )
            accion = (
                f"1. Verificá que el puntero no sea NULL antes de acceder a sus miembros o desreferenciarlo:\n"
                f"   if ({var_culpable or 'ptr'} == NULL) {{ /* manejar error o retornar */ }}\n"
                f"2. Chequeá siempre el valor de retorno de funciones de asignación como `malloc()` o `fopen()`."
            )
        else:
            # Dirección fuera de rango o buffer overflow
            titulo = "Acceso a Dirección de Memoria Inválida o Fuera de Rango"
            explicacion = (
                f"El programa intentó acceder a la dirección {direccion_memoria or 'desconocida'}.\n"
                f"Esta dirección no pertenece a ningún segmento de memoria mapeado para tu proceso.\n"
                f"Causas comunes: Lectura/escritura fuera de los límites de un arreglo (buffer overflow), uso de un puntero liberado (Use-After-Free) o puntero con valor basura no inicializado."
            )
            accion = (
                f"1. Revisá los índices de los bucles: recordá que en C los arreglos de tamaño N van desde 0 hasta N-1.\n"
                f"2. Verificá que todas las variables de tipo puntero sean inicializadas con una dirección válida o con NULL.\n"
                f"3. Si usaste `free(p)`, asignale inmediatamente `p = NULL;` para evitar accesos colgantes."
            )

        return DiagnosticoCrash(
            tipo_senal="SIGSEGV",
            codigo_senal=codigo_senal or ("SEGV_MAPERR" if es_null else "SEGV_ACCERR"),
            direccion_memoria=direccion_memoria,
            causa_raiz_titulo=titulo,
            explicacion=explicacion,
            accion_correctiva=accion,
            archivo_falla=archivo,
            linea_falla=linea,
            funcion_falla=funcion,
            variable_culpable=var_culpable,
            frames=frames,
            salida_programa=salida_prog,
        )

    # 2. Caso: SIGABRT (Aborted / Assertion Failed / Double Free)
    elif "ABRT" in senal:
        if "free(): double free" in gdb_output or "double free" in salida_prog:
            titulo = "Liberación Doble de Memoria (Double Free)"
            explicacion = (
                f"El gestor de memoria (glibc allocator) abortó la ejecución porque se intentó invocar `free()` sobre un puntero que ya había sido liberado previamente."
            )
            accion = (
                f"1. Asegurate de llamar a `free()` exactamente una vez por cada bloque solicitado con `malloc()`.\n"
                f"2. Tras liberar un puntero, setealo en NULL: `free(p); p = NULL;` (invocar `free(NULL)` es seguro e inocuo en C)."
            )
        elif "corrupted size vs. prev_size" in gdb_output or "heap-buffer-overflow" in gdb_output:
            titulo = "Corrupción de la Cabecera del Heap (Heap Buffer Overflow)"
            explicacion = (
                f"El programa escribió más bytes de los reservados en un bloque de memoria dinámica, pisando los metadatos internos del Heap."
            )
            accion = (
                f"1. Revisá los tamaños pasados a `malloc(n * sizeof(tipo))` y las funciones de copia como `strcpy` / `memcpy`.\n"
                f"2. Corré el programa con `valgrind` o AddressSanitizer (`-fsanitize=address`) para ubicar la escritura fuera de rango."
            )
        elif "assert" in gdb_output.lower() or "assertion" in salida_prog.lower():
            titulo = "Aserción Fallida (`assert()` macro)"
            explicacion = (
                f"Una condición obligatoria definida con `assert(...)` evaluó a falso en tiempo de ejecución, provocando la terminación inmediata del programa."
            )
            accion = (
                f"1. Revisá las precondiciones de la función '{funcion or 'actual'}' y los valores pasados como argumentos."
            )
        else:
            titulo = "Terminación Anormal Solicitada (Abort)"
            explicacion = f"El programa invocó explícitamente `abort()` o una librería del sistema detectó una inconsistencia irrecuperable."
            accion = f"1. Revisá los últimos mensajes emitidos por el programa antes del fallo."

        return DiagnosticoCrash(
            tipo_senal="SIGABRT",
            codigo_senal="ABRT",
            direccion_memoria=direccion_memoria,
            causa_raiz_titulo=titulo,
            explicacion=explicacion,
            accion_correctiva=accion,
            archivo_falla=archivo,
            linea_falla=linea,
            funcion_falla=funcion,
            variable_culpable=var_culpable,
            frames=frames,
            salida_programa=salida_prog,
        )

    # 3. Caso: SIGFPE (Floating Point Exception / División por Cero)
    elif "FPE" in senal:
        titulo = "Excepción Aritmética (División Entera por Cero o Módulo Cero)"
        explicacion = (
            f"El procesador generó una interrupción por una operación matemática ilegal (generalmente una división por cero `x / 0` o resto de módulo `x % 0`)."
        )
        accion = (
            f"1. En la línea {linea or '?'}, verificá que el divisor no sea 0 antes de efectuar la división:\n"
            f"   if (divisor == 0) {{ /* manejar error */ }} else {{ res = dividendo / divisor; }}"
        )
        return DiagnosticoCrash(
            tipo_senal="SIGFPE",
            codigo_senal="FPE_INTDIV",
            direccion_memoria=direccion_memoria,
            causa_raiz_titulo=titulo,
            explicacion=explicacion,
            accion_correctiva=accion,
            archivo_falla=archivo,
            linea_falla=linea,
            funcion_falla=funcion,
            variable_culpable=var_culpable,
            frames=frames,
            salida_programa=salida_prog,
        )

    # 4. Caso genérico / Otros fallos
    titulo = f"Fallo por Señal Fatal ({senal})"
    explicacion = f"El programa fue terminado abruptamente por el sistema operativo al recibir la señal {senal}."
    accion = f"1. Inspeccioná la traza de llamadas (stack trace) para ubicar el último punto de ejecución válido."
    return DiagnosticoCrash(
        tipo_senal=senal,
        codigo_senal=codigo_senal,
        direccion_memoria=direccion_memoria,
        causa_raiz_titulo=titulo,
        explicacion=explicacion,
        accion_correctiva=accion,
        archivo_falla=archivo,
        linea_falla=linea,
        funcion_falla=funcion,
        variable_culpable=var_culpable,
        frames=frames,
        salida_programa=salida_prog,
    )
