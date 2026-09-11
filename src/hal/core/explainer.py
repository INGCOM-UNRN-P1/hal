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
    vasquez_injected: bool = False,
) -> DiagnosticoCrash:
    """Genera un diagnóstico pedagógico completo a partir de los datos crudos del fallo."""
    # Extraer frame culpable (primer frame con archivo/línea conocidos, evitando libc)
    frame_falla = None
    for f in frames:
        if f.archivo and not f.archivo.startswith("/usr/") and not f.archivo.startswith("??") and not f.archivo.startswith("/lib"):
            frame_falla = f
            break
    if not frame_falla and frames:
        for f in frames:
            if f.funcion and not f.funcion.startswith("__") and f.funcion not in (
                "raise", "abort", "malloc_printerr", "malloc_printerr_tail", "__pthread_kill_implementation"
            ):
                frame_falla = f
                break
        if not frame_falla:
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

    texto_combinado = (gdb_output + "\n" + salida_prog).lower()

    # Detección de Inyección de Fallos por Vasquez
    vasquez_detectada = (
        vasquez_injected
        or "[vasquez]" in texto_combinado
        or "vasquez" in texto_combinado
    )
    vasquez_info: Optional[dict] = None
    if vasquez_detectada:
        matches = re.findall(r"\[vasquez\]\s*([^\n\r]+)", gdb_output + "\n" + salida_prog, re.IGNORECASE)
        detalle_v = "; ".join(m.strip() for m in matches) if matches else "Inyección deliberada de fallos en runtime vía LD_PRELOAD"
        vasquez_info = {"inyectado": True, "detalle": detalle_v}

    # Mejora 16: Use-After-Free (UAF)
    is_uaf = (
        "heap-use-after-free" in texto_combinado
        or "use-after-free" in texto_combinado
        or "use after free" in texto_combinado
        or "freed by thread" in texto_combinado
        or "recently free'd" in texto_combinado
        or "was free'd" in texto_combinado
        or "was freed" in texto_combinado
    )
    if is_uaf:
        titulo = "Acceso a Memoria Ya Liberada (Use-After-Free)"
        explicacion = (
            f"El programa intentó acceder a la dirección {direccion_memoria or 'de memoria previa'}, la cual ya había sido devuelta al sistema mediante `free()`.\n"
            f"Cuando liberás un bloque dinámico con `free(p)`, el sistema operativo o el gestor del Heap recicla ese espacio o lo desmapea. "
            f"Si tu código conserva el puntero (puntero colgante o dangling pointer) y realiza lecturas o escrituras sobre él, "
            f"se produce corrupción silenciosa de datos o una caída inmediata por violación de segmento."
        )
        accion = (
            f"1. Seteá el puntero en NULL inmediatamente después de liberarlo: `free(p); p = NULL;`.\n"
            f"2. Verificá que ninguna otra variable o estructura mantenga una copia huérfana de la dirección liberada.\n"
            f"3. No intentes leer ni modificar campos de un struct tras invocar su función de destrucción o liberación."
        )
        diag = DiagnosticoCrash(
            tipo_senal=senal if senal != "NINGUNA" else "SIGSEGV",
            codigo_senal="USE_AFTER_FREE",
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
            es_use_after_free=True,
            vasquez_inyeccion_detectada=vasquez_info,
        )
        _enriquecer_con_vasquez(diag)
        return diag

    # Mejora 23: Auditor de paso de puntero inválido a free() (Invalid Pointer Free)
    is_invalid_free = (
        "free(): invalid pointer" in texto_combinado
        or "munmap_chunk(): invalid pointer" in texto_combinado
        or "free(): invalid next size" in texto_combinado
        or "free called on unallocated object" in texto_combinado
        or "attempting free on address which was not malloc" in texto_combinado
        or ("invalid pointer" in texto_combinado and "free" in texto_combinado)
    )
    if is_invalid_free:
        titulo = "Puntero Inválido Pasado a free() (Invalid Pointer Free)"
        explicacion = (
            f"El gestor de memoria dinámica de la biblioteca estándar (glibc) abortó la ejecución porque se intentó invocar `free()` "
            f"sobre una dirección de memoria que no corresponde al inicio exacto de un bloque devuelto por `malloc()`, `calloc()` o `realloc()`.\n"
            f"Causas comunes:\n"
            f"1. Intentar liberar una variable de la pila (Stack) o memoria estática (ej: `int x; free(&x);` o `char arr[32]; free(arr);`).\n"
            f"2. Puntero interior o desplazado: haber modificado el puntero base mediante aritmética de punteros (ej: `char *p = malloc(10); p++; free(p);`).\n"
            f"3. Puntero no inicializado conteniendo valores basura del marco de pila."
        )
        accion = (
            f"1. Pasá a `free()` únicamente el puntero exacto retornado por las funciones de reserva dinámica (`malloc`, `calloc`, `realloc`).\n"
            f"2. Nunca invoques `free()` sobre variables locales automáticas ni arreglos declarados en la pila (`&variable`).\n"
            f"3. Si avanzaste un puntero para iterar (`p++`), conservá siempre el puntero inicial retornado por malloc para efectuar la liberación."
        )
        diag = DiagnosticoCrash(
            tipo_senal="SIGABRT",
            codigo_senal="INVALID_POINTER_FREE",
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
            es_invalid_free=True,
            vasquez_inyeccion_detectada=vasquez_info,
        )
        _enriquecer_con_vasquez(diag)
        return diag

    # Mejora 18: Explicador de señales de aborto por agotamiento de memoria (ENOMEM / OOM Killer)
    is_oom = (
        "cannot allocate memory" in texto_combinado
        or "enomem" in texto_combinado
        or "out of memory" in texto_combinado
        or "oom-killer" in texto_combinado
        or "exceeds maximum object size" in texto_combinado
        or any("18446744073709551615" in str(f.variables_locales) or "18446744073709551615" in str(f.argumentos) for f in frames)
    )
    if is_oom:
        titulo = "Agotamiento de Memoria del Proceso (ENOMEM / Out-Of-Memory)"
        explicacion = (
            f"El sistema operativo o el gestor de memoria no pudo satisfacer la solicitud de asignación de memoria (retornando NULL o abortando).\n"
            f"Causas comunes:\n"
            f"1. Solicitud de un tamaño desproporcionado (gigabytes o exabytes), generalmente por pasar un entero con signo negativo a `malloc(size)` "
            f"que se interpreta como un valor `size_t` (unsigned) exorbitante (ej: `(size_t)-1` = 18446744073709551615 bytes).\n"
            f"2. Desbordamiento aritmético (integer overflow) al multiplicar `cantidad * sizeof(tipo)`.\n"
            f"3. Fuga masiva y continua de memoria (Memory Leak) acumulada en un ciclo infinito."
        )
        accion = (
            f"1. Verificá los argumentos pasados a `malloc()`, `calloc()` o `realloc()` asegurándote de que la cantidad sea positiva y razonable.\n"
            f"2. Chequeá que la multiplicación para el tamaño total no sufra integer overflow antes de reservar.\n"
            f"3. Validá siempre que el puntero devuelto no sea NULL antes de utilizarlo defensivamente."
        )
        diag = DiagnosticoCrash(
            tipo_senal=senal if senal != "NINGUNA" else "SIGABRT",
            codigo_senal="ENOMEM_OOM",
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
            es_oom_enomem=True,
            vasquez_inyeccion_detectada=vasquez_info,
        )
        _enriquecer_con_vasquez(diag)
        return diag

    # Mejora: Detección de Buffer Overflow pisando dirección de retorno ($rip/$eip)
    is_ret_overflow = (
        "cannot access memory at address" in texto_combinado
        or "previous frame inner to this frame" in texto_combinado
        or "corrupted stack frame" in texto_combinado
        or (direccion_memoria and any(direccion_memoria.lower().startswith(p) for p in ("0x41414141", "0x61616161", "0x78787878")))
    )
    if is_ret_overflow:
        titulo = "Desbordamiento de Búfer sobre Dirección de Retorno ($rip/$eip Overflow)"
        explicacion = (
            f"Una escritura fuera de los límites en un búfer local de la pila (Stack Buffer Overflow) "
            f"sobrescribió los metadatos del marco de activación, pisando la dirección de retorno ($rip o $eip).\n"
            f"Al intentar retornar de la función mediante la instrucción `ret`, el procesador intentó saltar a la dirección "
            f"corrupta ({direccion_memoria or 'inválida'}), generando un fallo inmediato por violación de memoria."
        )
        accion = (
            f"1. Verificá los tamaños de los arreglos locales y los límites de escritura.\n"
            f"2. Descartá el uso de funciones no seguras como `gets()`, `strcpy()` o `sprintf()`.\n"
            f"3. Utilizá alternativas acotadas como `fgets()`, `strncpy()` o `snprintf()` especificando el tamaño máximo del búfer de destino."
        )
        diag = DiagnosticoCrash(
            tipo_senal=senal if senal != "NINGUNA" else "SIGSEGV",
            codigo_senal="RET_ADDR_CORRUPTED",
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
            es_buffer_overflow_ret=True,
            vasquez_inyeccion_detectada=vasquez_info,
        )
        _enriquecer_con_vasquez(diag)
        return diag

    # 1. Caso: SIGBUS (Bus Error / Desalineación de memoria)
    if "BUS" in senal or "BUS_ADRALN" in (codigo_senal or ""):
        titulo = "Error de Bus / Desalineación de Memoria (SIGBUS / Alignment Fault)"
        explicacion = (
            f"El procesador detuvo el programa al intentar acceder a la dirección {direccion_memoria or 'no alineada'}.\n"
            f"En muchas arquitecturas (ARM, SPARC, RISC-V), los tipos de datos deben residir en direcciones múltiplos de su tamaño "
            f"(ej: `int` o `float` en múltiplos de 4 bytes, `double` o punteros en múltiplos de 8 bytes).\n"
            f"Causas comunes: Casteo de punteros incompatibles (ej: `char*` a `int*` en offset impar), uso indebido de `#pragma pack`, "
            f"o mapeo de archivos con `mmap()` cuyo offset no respeta los límites de página."
        )
        accion = (
            f"1. Verificá que los punteros apunten a direcciones con alineación adecuada (`alignof` o `sizeof(tipo)`).\n"
            f"2. Evitá castear punteros de tipos pequeños a tipos mayores arbitrariamente (`(int*)(buffer + 1)`).\n"
            f"3. Si necesitás empaquetar datos, usá `memcpy()` para copiar bytes a una variable local alineada."
        )
        diag = DiagnosticoCrash(
            tipo_senal="SIGBUS",
            codigo_senal=codigo_senal or "BUS_ADRALN",
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
            vasquez_inyeccion_detectada=vasquez_info,
        )
        _enriquecer_con_vasquez(diag)
        return diag

    # 2. Caso: SIGSEGV (Segmentation Fault)
    if "SEGV" in senal or "SEGMENTATION" in senal.upper() or "SEGMENTATION" in (codigo_senal or "").upper():
        # Analizar si es desreferencia de NULL
        es_null = (
            direccion_memoria in nil_values
            or (direccion_memoria and direccion_memoria.startswith("0x") and int(direccion_memoria, 16) < 0x1000)
            or var_culpable is not None
            or ("SEGV_MAPERR" in (codigo_senal or "") and (not direccion_memoria or int(direccion_memoria, 16) < 0x1000))
        )

        # Detectar puntero salvaje / no inicializado
        patrones_basura = ("0xbaad", "0xcccc", "0xdead", "0xfeee", "0xcdcd", "0xabab", "0x555555555555", "0xaaaaaaaa")
        es_wild = False
        if direccion_memoria and direccion_memoria not in nil_values:
            try:
                val_int = int(direccion_memoria, 16)
                if val_int >= 0x1000:
                    addr_lower = direccion_memoria.lower()
                    if any(p in addr_lower for p in patrones_basura) or "wild pointer" in texto_combinado or "uninitialized" in texto_combinado or ("SEGV_MAPERR" in (codigo_senal or "") and not es_null):
                        es_wild = True
            except ValueError:
                pass

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
            diag = DiagnosticoCrash(
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
                vasquez_inyeccion_detectada=vasquez_info,
            )
            _enriquecer_con_vasquez(diag)
            return diag

        if es_wild:
            titulo = f"Desreferencia de Puntero Salvaje o No Inicializado (Wild Pointer: {direccion_memoria})"
            explicacion = (
                f"El programa intentó acceder a la dirección inaccesible {direccion_memoria}.\n"
                f"En la línea {linea or '?'}, se desreferenció un puntero no inicializado que contenía basura del stack.\n"
                f"En C, las variables automáticas no se inicializan por defecto. Utilizar un puntero sin asignarle previamente una dirección válida o NULL desata fallos impredecibles."
            )
            accion = (
                f"1. Inicializá siempre los punteros en NULL o con una dirección válida al declararlos:\n"
                f"   tipo *ptr = NULL;\n"
                f"2. Verificá que todas las ramas de ejecución asignen el puntero antes de desreferenciarlo."
            )
            diag = DiagnosticoCrash(
                tipo_senal="SIGSEGV",
                codigo_senal="WILD_POINTER",
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
                es_wild_pointer=True,
                vasquez_inyeccion_detectada=vasquez_info,
            )
            _enriquecer_con_vasquez(diag)
            return diag

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
                f"1. Revisá los índices de los lazos: recordá que en C los arreglos de tamaño N van desde 0 hasta N-1.\n"
                f"2. Verificá que todas las variables de tipo puntero sean inicializadas con una dirección válida o con NULL.\n"
                f"3. Si usaste `free(p)`, asignale inmediatamente `p = NULL;` para evitar accesos colgantes."
            )

        diag = DiagnosticoCrash(
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
            vasquez_inyeccion_detectada=vasquez_info,
        )
        _enriquecer_con_vasquez(diag)
        return diag

    # 3. Caso: SIGABRT (Aborted / Assertion Failed / Double Free)
    elif "ABRT" in senal:
        es_assert = False
        expr_assert = None
        m_assert = re.search(r"(?:assertion|Assertion)\s+[`'\"]([^`'\"]+)[`'\"]\s+failed", gdb_output + "\n" + salida_prog, re.IGNORECASE)
        if not m_assert:
            m_assert = re.search(r"assert\s*\((.*?)\)", gdb_output + "\n" + salida_prog, re.IGNORECASE)

        if m_assert or "assert" in gdb_output.lower() or "assertion" in salida_prog.lower():
            es_assert = True
            expr_assert = m_assert.group(1).strip() if m_assert else "condición"

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
        elif es_assert:
            titulo = f"Aserción Fallida: assert({expr_assert or 'condición'})"
            explicacion = (
                f"La condición obligatoria '{expr_assert or 'condición'}' evaluó a falso (cero) en tiempo de ejecución en la línea {linea or '?'}.\n"
                f"El macro `assert()` abortó el proceso para salvaguardar la integridad de los datos."
            )
            accion = (
                f"1. Revisá los valores de las variables intervinientes en el marco de la función '{funcion or 'actual'}'.\n"
                f"2. Comprobá las precondiciones antes de invocar la aserción."
            )
        else:
            titulo = "Terminación Anormal Solicitada (Abort)"
            explicacion = f"El programa invocó explícitamente `abort()` o una librería del sistema detectó una inconsistencia irrecuperable."
            accion = f"1. Revisá los últimos mensajes emitidos por el programa antes del fallo."

        diag = DiagnosticoCrash(
            tipo_senal="SIGABRT",
            codigo_senal="ASSERT_FAILED" if es_assert else "ABRT",
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
            es_assert_fallido=es_assert,
            expresion_assert=expr_assert,
            vasquez_inyeccion_detectada=vasquez_info,
        )
        _enriquecer_con_vasquez(diag)
        return diag

    # 4. Caso: SIGFPE (Floating Point Exception / División por Cero)
    elif "FPE" in senal:
        # Detectar variable con valor 0 en el marco
        div_var = None
        if frame_falla:
            for k, v in {**frame_falla.argumentos, **frame_falla.variables_locales}.items():
                if str(v).strip() in ("0", "0x0", "+0", "-0"):
                    div_var = k
                    break
        if div_var:
            var_culpable = div_var
            titulo = f"Excepción Aritmética: División por Cero (divisor '{div_var}' = 0)"
            explicacion = (
                f"El procesador detuvo el programa en la línea {linea or '?'} al intentar realizar una división entera o módulo donde el divisor '{div_var}' vale 0."
            )
        else:
            titulo = "Excepción Aritmética (División Entera por Cero o Módulo Cero)"
            explicacion = (
                f"El procesador detuvo el programa en la línea {linea or '?'} por una operación matemática ilegal (división `/ 0` o resto `% 0`)."
            )

        accion = (
            f"1. En la línea {linea or '?'}, verificá que el divisor no sea 0 antes de efectuar la operación:\n"
            f"   if ({div_var or 'divisor'} == 0) {{ /* manejar error */ }} else {{ res = dividendo / {div_var or 'divisor'}; }}"
        )
        diag = DiagnosticoCrash(
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
            vasquez_inyeccion_detectada=vasquez_info,
        )
        _enriquecer_con_vasquez(diag)
        return diag

    # 5. Caso genérico / Otros fallos
    titulo = f"Fallo por Señal Fatal ({senal})"
    explicacion = f"El programa fue terminado abruptamente por el sistema operativo al recibir la señal {senal}."
    accion = f"1. Inspeccioná la traza de llamadas (stack trace) para ubicar el último punto de ejecución válido."
    diag = DiagnosticoCrash(
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
        vasquez_inyeccion_detectada=vasquez_info,
    )
    _enriquecer_con_vasquez(diag)
    return diag


def _enriquecer_con_vasquez(diag: DiagnosticoCrash) -> None:
    """Enriquece la explicación diagnóstica si se detectó una inyección deliberada de fallos de Vasquez."""
    if not diag.vasquez_inyeccion_detectada:
        return
    detalle = diag.vasquez_inyeccion_detectada.get("detalle", "Inyección de fallos en runtime")
    nota = (
        f"\n\n⚠️ INYECCIÓN DE FALLOS POR VASQUEZ: Este crash se produjo bajo la inyección activa de Vasquez "
        f"para auditar la programación defensiva ({detalle}). "
        f"El retorno forzado de NULL o error de llamada al sistema no fue controlado adecuadamente por tu código antes de acceder a la memoria."
    )
    if "VASQUEZ" not in diag.explicacion:
        diag.explicacion += nota
