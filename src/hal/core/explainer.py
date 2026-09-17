"""Motor de diagnóstico pedagógico y síntesis en lenguaje natural en HAL."""

from __future__ import annotations

import re
from typing import List, Optional, Tuple
from hal.core.models import DiagnosticoCrash, StackFrame


NIL_VALUES = ("0x0", "(nil)", "0x00000000", "0x0000000000000000", "NULL")
PATRONES_BASURA = ("0xbaad", "0xcccc", "0xdead", "0xfeee", "0xcdcd", "0xabab", "0x555555555555", "0xaaaaaaaa")


def _extraer_frame_y_variable_culpable(
    frames: List[StackFrame],
) -> Tuple[Optional[str], Optional[int], Optional[str], Optional[str], Optional[StackFrame]]:
    """Extrae archivo, línea, función, variable y frame culpable evitando bibliotecas del sistema."""
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

    var_culpable = None
    if frame_falla:
        for arg, val in frame_falla.argumentos.items():
            if val in NIL_VALUES:
                var_culpable = arg
                break
        if not var_culpable:
            for var, val in frame_falla.variables_locales.items():
                if val in NIL_VALUES:
                    var_culpable = var
                    break

    return archivo, linea, funcion, var_culpable, frame_falla


def _detectar_inyeccion_vasquez(
    vasquez_injected: bool,
    gdb_output: str,
    salida_prog: str,
    texto_combinado: str,
) -> Optional[dict]:
    """Detecta y extrae metadatos de inyección de Vasquez."""
    if not (vasquez_injected or "[vasquez]" in texto_combinado or "vasquez" in texto_combinado):
        return None
    matches = re.findall(r"\[vasquez\]\s*([^\n\r]+)", gdb_output + "\n" + salida_prog, re.IGNORECASE)
    detalle_v = "; ".join(m.strip() for m in matches) if matches else "Inyección deliberada de fallos en runtime vía LD_PRELOAD"
    return {"inyectado": True, "detalle": detalle_v}


def _diagnosticar_uaf(
    senal: str,
    direccion: Optional[str],
    archivo: Optional[str],
    linea: Optional[int],
    funcion: Optional[str],
    var: Optional[str],
    frames: List[StackFrame],
    salida_prog: str,
    vasquez_info: Optional[dict],
) -> DiagnosticoCrash:
    return DiagnosticoCrash(
        tipo_senal=senal if senal != "NINGUNA" else "SIGSEGV",
        codigo_senal="USE_AFTER_FREE",
        direccion_memoria=direccion,
        causa_raiz_titulo="Acceso a Memoria Ya Liberada (Use-After-Free)",
        explicacion=(
            f"El programa intentó acceder a la dirección {direccion or 'de memoria previa'}, la cual ya había sido devuelta al sistema mediante `free()`.\n"
            f"Cuando liberás un bloque dinámico con `free(p)`, el sistema operativo o el gestor del Heap recicla ese espacio o lo desmapea. "
            f"Si tu código conserva el puntero (puntero colgante o dangling pointer) y realiza lecturas o escrituras sobre él, "
            f"se produce corrupción silenciosa de datos o una caída inmediata por violación de segmento."
        ),
        accion_correctiva=(
            f"1. Seteá el puntero en NULL inmediatamente después de liberarlo: `free(p); p = NULL;`.\n"
            f"2. Verificá que ninguna otra variable o estructura mantenga una copia huérfana de la dirección liberada.\n"
            f"3. No intentes leer ni modificar campos de un struct tras invocar su función de destrucción o liberación."
        ),
        archivo_falla=archivo,
        linea_falla=linea,
        funcion_falla=funcion,
        variable_culpable=var,
        frames=frames,
        salida_programa=salida_prog,
        es_use_after_free=True,
        vasquez_inyeccion_detectada=vasquez_info,
    )


def _diagnosticar_invalid_free(
    direccion: Optional[str],
    archivo: Optional[str],
    linea: Optional[int],
    funcion: Optional[str],
    var: Optional[str],
    frames: List[StackFrame],
    salida_prog: str,
    vasquez_info: Optional[dict],
) -> DiagnosticoCrash:
    return DiagnosticoCrash(
        tipo_senal="SIGABRT",
        codigo_senal="INVALID_POINTER_FREE",
        direccion_memoria=direccion,
        causa_raiz_titulo="Puntero Inválido Pasado a free() (Invalid Pointer Free)",
        explicacion=(
            f"El gestor de memoria dinámica de la biblioteca estándar (glibc) abortó la ejecución porque se intentó invocar `free()` "
            f"sobre una dirección de memoria que no corresponde al inicio exacto de un bloque devuelto por `malloc()`, `calloc()` o `realloc()`.\n"
            f"Causas comunes:\n"
            f"1. Intentar liberar una variable de la pila (Stack) o memoria estática (ej: `int x; free(&x);` o `char arr[32]; free(arr);`).\n"
            f"2. Puntero interior o desplazado: haber modificado el puntero base mediante aritmética de punteros (ej: `char *p = malloc(10); p++; free(p);`).\n"
            f"3. Puntero no inicializado conteniendo valores basura del marco de pila."
        ),
        accion_correctiva=(
            f"1. Pasá a `free()` únicamente el puntero exacto retornado por las funciones de reserva dinámica (`malloc`, `calloc`, `realloc`).\n"
            f"2. Nunca invoques `free()` sobre variables locales automáticas ni arreglos declarados en la pila (`&variable`).\n"
            f"3. Si avanzaste un puntero para iterar (`p++`), conservá siempre el puntero inicial retornado por malloc para efectuar la liberación."
        ),
        archivo_falla=archivo,
        linea_falla=linea,
        funcion_falla=funcion,
        variable_culpable=var,
        frames=frames,
        salida_programa=salida_prog,
        es_invalid_free=True,
        vasquez_inyeccion_detectada=vasquez_info,
    )


def _diagnosticar_oom(
    senal: str,
    direccion: Optional[str],
    archivo: Optional[str],
    linea: Optional[int],
    funcion: Optional[str],
    var: Optional[str],
    frames: List[StackFrame],
    salida_prog: str,
    vasquez_info: Optional[dict],
) -> DiagnosticoCrash:
    return DiagnosticoCrash(
        tipo_senal=senal if senal != "NINGUNA" else "SIGABRT",
        codigo_senal="ENOMEM_OOM",
        direccion_memoria=direccion,
        causa_raiz_titulo="Agotamiento de Memoria del Proceso (ENOMEM / Out-Of-Memory)",
        explicacion=(
            f"El sistema operativo o el gestor de memoria no pudo satisfacer la solicitud de asignación de memoria (retornando NULL o abortando).\n"
            f"Causas comunes:\n"
            f"1. Solicitud de un tamaño desproporcionado (gigabytes o exabytes), generalmente por pasar un entero con signo negativo a `malloc(size)` "
            f"que se interpreta como un valor `size_t` (unsigned) exorbitante (ej: `(size_t)-1` = 18446744073709551615 bytes).\n"
            f"2. Desbordamiento aritmético (integer overflow) al multiplicar `cantidad * sizeof(tipo)`.\n"
            f"3. Fuga masiva y continua de memoria (Memory Leak) acumulada en un ciclo infinito."
        ),
        accion_correctiva=(
            f"1. Verificá los argumentos pasados a `malloc()`, `calloc()` o `realloc()` asegurándote de que la cantidad sea positiva y razonable.\n"
            f"2. Chequeá que la multiplicación para el tamaño total no sufra integer overflow antes de reservar.\n"
            f"3. Validá siempre que el puntero devuelto no sea NULL antes de utilizarlo defensivamente."
        ),
        archivo_falla=archivo,
        linea_falla=linea,
        funcion_falla=funcion,
        variable_culpable=var,
        frames=frames,
        salida_programa=salida_prog,
        es_oom_enomem=True,
        vasquez_inyeccion_detectada=vasquez_info,
    )


def _diagnosticar_ret_overflow(
    senal: str,
    direccion: Optional[str],
    archivo: Optional[str],
    linea: Optional[int],
    funcion: Optional[str],
    var: Optional[str],
    frames: List[StackFrame],
    salida_prog: str,
    vasquez_info: Optional[dict],
) -> DiagnosticoCrash:
    return DiagnosticoCrash(
        tipo_senal=senal if senal != "NINGUNA" else "SIGSEGV",
        codigo_senal="RET_ADDR_CORRUPTED",
        direccion_memoria=direccion,
        causa_raiz_titulo="Desbordamiento de Búfer sobre Dirección de Retorno ($rip/$eip Overflow)",
        explicacion=(
            f"Una escritura fuera de los límites en un búfer local de la pila (Stack Buffer Overflow) "
            f"sobrescribió los metadatos del marco de activación, pisando la dirección de retorno ($rip o $eip).\n"
            f"Al intentar retornar de la función mediante la instrucción `ret`, el procesador intentó saltar a la dirección "
            f"corrupta ({direccion or 'inválida'}), generando un fallo inmediato por violación de memoria."
        ),
        accion_correctiva=(
            f"1. Verificá los tamaños de los arreglos locales y los límites de escritura.\n"
            f"2. Descartá el uso de funciones no seguras como `gets()`, `strcpy()` o `sprintf()`.\n"
            f"3. Utilizá alternativas acotadas como `fgets()`, `strncpy()` o `snprintf()` especificando el tamaño máximo del búfer de destino."
        ),
        archivo_falla=archivo,
        linea_falla=linea,
        funcion_falla=funcion,
        variable_culpable=var,
        frames=frames,
        salida_programa=salida_prog,
        es_buffer_overflow_ret=True,
        vasquez_inyeccion_detectada=vasquez_info,
    )


def _diagnosticar_sigbus(
    codigo_senal: Optional[str],
    direccion: Optional[str],
    archivo: Optional[str],
    linea: Optional[int],
    funcion: Optional[str],
    var: Optional[str],
    frames: List[StackFrame],
    salida_prog: str,
    vasquez_info: Optional[dict],
) -> DiagnosticoCrash:
    return DiagnosticoCrash(
        tipo_senal="SIGBUS",
        codigo_senal=codigo_senal or "BUS_ADRALN",
        direccion_memoria=direccion,
        causa_raiz_titulo="Error de Bus / Desalineación de Memoria (SIGBUS / Alignment Fault)",
        explicacion=(
            f"El procesador detuvo el programa al intentar acceder a la dirección {direccion or 'no alineada'}.\n"
            f"En muchas arquitecturas (ARM, SPARC, RISC-V), los tipos de datos deben residir en direcciones múltiplos de su tamaño "
            f"(ej: `int` o `float` en múltiplos de 4 bytes, `double` o punteros en múltiplos de 8 bytes).\n"
            f"Causas comunes: Casteo de punteros incompatibles (ej: `char*` a `int*` en offset impar), uso indebido de `#pragma pack`, "
            f"o mapeo de archivos con `mmap()` cuyo offset no respeta los límites de página."
        ),
        accion_correctiva=(
            f"1. Verificá que los punteros apunten a direcciones con alineación adecuada (`alignof` o `sizeof(tipo)`).\n"
            f"2. Evitá castear punteros de tipos pequeños a tipos mayores arbitrariamente (`(int*)(buffer + 1)`).\n"
            f"3. Si necesitás empaquetar datos, usá `memcpy()` para copiar bytes a una variable local alineada."
        ),
        archivo_falla=archivo,
        linea_falla=linea,
        funcion_falla=funcion,
        variable_culpable=var,
        frames=frames,
        salida_programa=salida_prog,
        vasquez_inyeccion_detectada=vasquez_info,
    )


def _diagnosticar_sigsegv(
    codigo_senal: Optional[str],
    direccion: Optional[str],
    archivo: Optional[str],
    linea: Optional[int],
    funcion: Optional[str],
    var: Optional[str],
    frames: List[StackFrame],
    salida_prog: str,
    texto_combinado: str,
    vasquez_info: Optional[dict],
) -> DiagnosticoCrash:
    es_null = (
        direccion in NIL_VALUES
        or (direccion and direccion.startswith("0x") and int(direccion, 16) < 0x1000)
        or var is not None
        or ("SEGV_MAPERR" in (codigo_senal or "") and (not direccion or int(direccion, 16) < 0x1000))
    )

    es_wild = False
    if direccion and direccion not in NIL_VALUES:
        try:
            val_int = int(direccion, 16)
            if val_int >= 0x1000:
                addr_lower = direccion.lower()
                if any(p in addr_lower for p in PATRONES_BASURA) or "wild pointer" in texto_combinado or "uninitialized" in texto_combinado or ("SEGV_MAPERR" in (codigo_senal or "") and not es_null):
                    es_wild = True
        except ValueError:
            pass

    if len(frames) > 30 and len(set(f.funcion for f in frames)) <= 3:
        fn_name = frames[0].funcion if frames else "recursiva"
        return DiagnosticoCrash(
            tipo_senal="SIGSEGV",
            codigo_senal="STACK_OVERFLOW",
            direccion_memoria=direccion,
            causa_raiz_titulo="Desbordamiento de Pila (Stack Overflow por Recursión Infinita)",
            explicacion=(
                f"Tu programa agotó el espacio de memoria reservado para la pila de ejecución (Stack).\n"
                f"Se detectaron más de {len(frames)} llamadas recursivas anidadas a la función '{fn_name}'.\n"
                f"Esto ocurre cuando el caso base de la recursión falta, no se cumple nunca, o los parámetros no se acercan al caso base."
            ),
            accion_correctiva=(
                f"1. Verificá que la función '{fn_name}' tenga una condición de corte explícita (caso base).\n"
                f"2. Asegurate de que en cada llamada recursiva los argumentos modifiquen su valor hacia el caso base.\n"
                f"3. Si la recursión es muy profunda por diseño, considerá reescribir el algoritmo de forma iterativa."
            ),
            archivo_falla=archivo,
            linea_falla=linea,
            funcion_falla=funcion,
            variable_culpable=var,
            frames=frames,
            salida_programa=salida_prog,
            vasquez_inyeccion_detectada=vasquez_info,
        )

    if es_wild:
        return DiagnosticoCrash(
            tipo_senal="SIGSEGV",
            codigo_senal="WILD_POINTER",
            direccion_memoria=direccion,
            causa_raiz_titulo=f"Desreferencia de Puntero Salvaje o No Inicializado (Wild Pointer: {direccion})",
            explicacion=(
                f"El programa intentó acceder a la dirección inaccesible {direccion}.\n"
                f"En la línea {linea or '?'}, se desreferenció un puntero no inicializado que contenía basura del stack.\n"
                f"En C, las variables automáticas no se inicializan por defecto. Utilizar un puntero sin asignarle previamente una dirección válida o NULL desata fallos impredecibles."
            ),
            accion_correctiva=(
                f"1. Inicializá siempre los punteros en NULL o con una dirección válida al declararlos:\n"
                f"   tipo *ptr = NULL;\n"
                f"2. Verificá que todas las ramas de ejecución asignen el puntero antes de desreferenciarlo."
            ),
            archivo_falla=archivo,
            linea_falla=linea,
            funcion_falla=funcion,
            variable_culpable=var,
            frames=frames,
            salida_programa=salida_prog,
            es_wild_pointer=True,
            vasquez_inyeccion_detectada=vasquez_info,
        )

    if es_null:
        var_texto = f" de la variable o puntero '{var}'" if var else ""
        titulo = "Desreferencia de Puntero Nulo (NULL Pointer Dereference)"
        explicacion = (
            f"El programa intentó leer o escribir en la dirección de memoria {direccion or '0x0'}{var_texto}.\n"
            f"En la línea {linea or '?'}, se desreferenció un puntero que apuntaba a NULL.\n"
            f"Causas comunes: `malloc()` retornó NULL por falta de memoria o tamaño cero, un puntero no fue inicializado, o se intentó acceder a un elemento fuera de una estructura enlazada."
        )
        accion = (
            f"1. Verificá que el puntero no sea NULL antes de acceder a sus miembros o desreferenciarlo:\n"
            f"   if ({var or 'ptr'} == NULL) {{ /* manejar error o retornar */ }}\n"
            f"2. Chequeá siempre el valor de retorno de funciones de asignación como `malloc()` o `fopen()`."
        )
    else:
        titulo = "Acceso a Dirección de Memoria Inválida o Fuera de Rango"
        explicacion = (
            f"El programa intentó acceder a la dirección {direccion or 'desconocida'}.\n"
            f"Esta dirección no pertenece a ningún segmento de memoria mapeado para tu proceso.\n"
            f"Causas comunes: Lectura/escritura fuera de los límites de un arreglo (buffer overflow), uso de un puntero liberado (Use-After-Free) o puntero con valor basura no inicializado."
        )
        accion = (
            f"1. Revisá los índices de los lazos: recordá que en C los arreglos de tamaño N van desde 0 hasta N-1.\n"
            f"2. Verificá que todas las variables de tipo puntero sean inicializadas con una dirección válida o con NULL.\n"
            f"3. Si usaste `free(p)`, asignale inmediatamente `p = NULL;` para evitar accesos colgantes."
        )

    return DiagnosticoCrash(
        tipo_senal="SIGSEGV",
        codigo_senal=codigo_senal or ("SEGV_MAPERR" if es_null else "SEGV_ACCERR"),
        direccion_memoria=direccion,
        causa_raiz_titulo=titulo,
        explicacion=explicacion,
        accion_correctiva=accion,
        archivo_falla=archivo,
        linea_falla=linea,
        funcion_falla=funcion,
        variable_culpable=var,
        frames=frames,
        salida_programa=salida_prog,
        vasquez_inyeccion_detectada=vasquez_info,
    )


def _diagnosticar_sigabrt(
    direccion: Optional[str],
    archivo: Optional[str],
    linea: Optional[int],
    funcion: Optional[str],
    var: Optional[str],
    frames: List[StackFrame],
    gdb_output: str,
    salida_prog: str,
    vasquez_info: Optional[dict],
) -> DiagnosticoCrash:
    texto = gdb_output + "\n" + salida_prog
    m_assert = re.search(r"(?:assertion|Assertion)\s+[`'\"]([^`'\"]+)[`'\"]\s+failed", texto, re.IGNORECASE)
    if not m_assert:
        m_assert = re.search(r"assert\s*\((.*?)\)", texto, re.IGNORECASE)

    es_assert = bool(m_assert or "assert" in gdb_output.lower() or "assertion" in salida_prog.lower())
    expr_assert = m_assert.group(1).strip() if m_assert else ("condición" if es_assert else None)

    if "free(): double free" in gdb_output or "double free" in salida_prog:
        titulo = "Liberación Doble de Memoria (Double Free)"
        explicacion = "El gestor de memoria (glibc allocator) abortó la ejecución porque se intentó invocar `free()` sobre un puntero que ya había sido liberado previamente."
        accion = (
            "1. Asegurate de llamar a `free()` exactamente una vez por cada bloque solicitado con `malloc()`.\n"
            "2. Tras liberar un puntero, setealo en NULL: `free(p); p = NULL;` (invocar `free(NULL)` es seguro e inocuo en C)."
        )
    elif "corrupted size vs. prev_size" in gdb_output or "heap-buffer-overflow" in gdb_output:
        titulo = "Corrupción de la Cabecera del Heap (Heap Buffer Overflow)"
        explicacion = "El programa escribió más bytes de los reservados en un bloque de memoria dinámica, pisando los metadatos internos del Heap."
        accion = (
            "1. Revisá los tamaños pasados a `malloc(n * sizeof(tipo))` y las funciones de copia como `strcpy` / `memcpy`.\n"
            "2. Corré el programa con `valgrind` o AddressSanitizer (`-fsanitize=address`) para ubicar la escritura fuera de rango."
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
        explicacion = "El programa invocó explícitamente `abort()` o una librería del sistema detectó una inconsistencia irrecuperable."
        accion = "1. Revisá los últimos mensajes emitidos por el programa antes del fallo."

    return DiagnosticoCrash(
        tipo_senal="SIGABRT",
        codigo_senal="ASSERT_FAILED" if es_assert else "ABRT",
        direccion_memoria=direccion,
        causa_raiz_titulo=titulo,
        explicacion=explicacion,
        accion_correctiva=accion,
        archivo_falla=archivo,
        linea_falla=linea,
        funcion_falla=funcion,
        variable_culpable=var,
        frames=frames,
        salida_programa=salida_prog,
        es_assert_fallido=es_assert,
        expresion_assert=expr_assert,
        vasquez_inyeccion_detectada=vasquez_info,
    )


def _diagnosticar_sigfpe(
    direccion: Optional[str],
    archivo: Optional[str],
    linea: Optional[int],
    funcion: Optional[str],
    var: Optional[str],
    frame_falla: Optional[StackFrame],
    frames: List[StackFrame],
    salida_prog: str,
    vasquez_info: Optional[dict],
) -> DiagnosticoCrash:
    div_var = None
    if frame_falla:
        for k, v in {**frame_falla.argumentos, **frame_falla.variables_locales}.items():
            if str(v).strip() in ("0", "0x0", "+0", "-0"):
                div_var = k
                break

    culpable = div_var or var
    if div_var:
        titulo = f"Excepción Aritmética: División por Cero (divisor '{div_var}' = 0)"
        explicacion = f"El procesador detuvo el programa en la línea {linea or '?'} al intentar realizar una división entera o módulo donde el divisor '{div_var}' vale 0."
    else:
        titulo = "Excepción Aritmética (División Entera por Cero o Módulo Cero)"
        explicacion = f"El procesador detuvo el programa en la línea {linea or '?'} por una operación matemática ilegal (división `/ 0` o resto `% 0`)."

    accion = (
        f"1. En la línea {linea or '?'}, verificá que el divisor no sea 0 antes de efectuar la operación:\n"
        f"   if ({div_var or 'divisor'} == 0) {{ /* manejar error */ }} else {{ res = dividendo / {div_var or 'divisor'}; }}"
    )

    return DiagnosticoCrash(
        tipo_senal="SIGFPE",
        codigo_senal="FPE_INTDIV",
        direccion_memoria=direccion,
        causa_raiz_titulo=titulo,
        explicacion=explicacion,
        accion_correctiva=accion,
        archivo_falla=archivo,
        linea_falla=linea,
        funcion_falla=funcion,
        variable_culpable=culpable,
        frames=frames,
        salida_programa=salida_prog,
        vasquez_inyeccion_detectada=vasquez_info,
    )


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
    archivo, linea, funcion, var_culpable, frame_falla = _extraer_frame_y_variable_culpable(frames)
    texto_combinado = (gdb_output + "\n" + salida_prog).lower()
    vasquez_info = _detectar_inyeccion_vasquez(vasquez_injected, gdb_output, salida_prog, texto_combinado)

    # 1. Use-After-Free (UAF)
    is_uaf = any(s in texto_combinado for s in (
        "heap-use-after-free", "use-after-free", "use after free",
        "freed by thread", "recently free'd", "was free'd", "was freed"
    ))
    if is_uaf:
        diag = _diagnosticar_uaf(senal, direccion_memoria, archivo, linea, funcion, var_culpable, frames, salida_prog, vasquez_info)
        _enriquecer_con_vasquez(diag)
        return diag

    # 2. Invalid Pointer Free
    is_invalid_free = (
        any(s in texto_combinado for s in (
            "free(): invalid pointer", "munmap_chunk(): invalid pointer",
            "free(): invalid next size", "free called on unallocated object",
            "attempting free on address which was not malloc"
        ))
        or ("invalid pointer" in texto_combinado and "free" in texto_combinado)
    )
    if is_invalid_free:
        diag = _diagnosticar_invalid_free(direccion_memoria, archivo, linea, funcion, var_culpable, frames, salida_prog, vasquez_info)
        _enriquecer_con_vasquez(diag)
        return diag

    # 3. ENOMEM / OOM Killer
    is_oom = (
        any(s in texto_combinado for s in ("cannot allocate memory", "enomem", "out of memory", "oom-killer", "exceeds maximum object size"))
        or any("18446744073709551615" in str(f.variables_locales) or "18446744073709551615" in str(f.argumentos) for f in frames)
    )
    if is_oom:
        diag = _diagnosticar_oom(senal, direccion_memoria, archivo, linea, funcion, var_culpable, frames, salida_prog, vasquez_info)
        _enriquecer_con_vasquez(diag)
        return diag

    # 4. Ret Addr Buffer Overflow
    is_ret_overflow = (
        any(s in texto_combinado for s in ("cannot access memory at address", "previous frame inner to this frame", "corrupted stack frame"))
        or (direccion_memoria and any(direccion_memoria.lower().startswith(p) for p in ("0x41414141", "0x61616161", "0x78787878")))
    )
    if is_ret_overflow:
        diag = _diagnosticar_ret_overflow(senal, direccion_memoria, archivo, linea, funcion, var_culpable, frames, salida_prog, vasquez_info)
        _enriquecer_con_vasquez(diag)
        return diag

    # 5. SIGBUS
    if "BUS" in senal or "BUS_ADRALN" in (codigo_senal or ""):
        diag = _diagnosticar_sigbus(codigo_senal, direccion_memoria, archivo, linea, funcion, var_culpable, frames, salida_prog, vasquez_info)
        _enriquecer_con_vasquez(diag)
        return diag

    # 6. SIGSEGV
    if "SEGV" in senal or "SEGMENTATION" in senal.upper() or "SEGMENTATION" in (codigo_senal or "").upper():
        diag = _diagnosticar_sigsegv(codigo_senal, direccion_memoria, archivo, linea, funcion, var_culpable, frames, salida_prog, texto_combinado, vasquez_info)
        _enriquecer_con_vasquez(diag)
        return diag

    # 7. SIGABRT
    if "ABRT" in senal:
        diag = _diagnosticar_sigabrt(direccion_memoria, archivo, linea, funcion, var_culpable, frames, gdb_output, salida_prog, vasquez_info)
        _enriquecer_con_vasquez(diag)
        return diag

    # 8. SIGFPE
    if "FPE" in senal:
        diag = _diagnosticar_sigfpe(direccion_memoria, archivo, linea, funcion, var_culpable, frame_falla, frames, salida_prog, vasquez_info)
        _enriquecer_con_vasquez(diag)
        return diag

    # 9. Fallo genérico
    diag = DiagnosticoCrash(
        tipo_senal=senal,
        codigo_senal=codigo_senal,
        direccion_memoria=direccion_memoria,
        causa_raiz_titulo=f"Fallo por Señal Fatal ({senal})",
        explicacion=f"El programa fue terminado abruptamente por el sistema operativo al recibir la señal {senal}.",
        accion_correctiva="1. Inspeccioná la traza de llamadas (stack trace) para ubicar el último punto de ejecución válido.",
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
