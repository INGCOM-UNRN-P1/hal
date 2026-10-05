"""Motor de diagnóstico pedagógico y síntesis en lenguaje natural en HAL."""

from __future__ import annotations

import re
from typing import List, Optional
from hal.core.models import DiagnosticoCrash, StackFrame


# Los diagnósticos de cada señal están en senales.py; se reexportan para quien los importaba de acá.
from hal.core.senales import (  # noqa: F401
    NIL_VALUES,
    PATRONES_BASURA,
    _extraer_frame_y_variable_culpable,
    _detectar_inyeccion_vasquez,
    _diagnosticar_uaf,
    _diagnosticar_invalid_free,
    _diagnosticar_oom,
    _diagnosticar_ret_overflow,
    _diagnosticar_sigbus,
    _diagnosticar_sigsegv,
    _diagnosticar_sigabrt,
    _diagnosticar_sigfpe,
)




def diagnosticar_crash(
    senal: str,
    codigo_senal: Optional[str],
    direccion_memoria: Optional[str],
    frames: List[StackFrame],
    gdb_output: str = "",
    salida_prog: str = "",
    vasquez_injected: bool = False,
    profundidad_pila: Optional[int] = None,
) -> DiagnosticoCrash:
    """Genera un diagnóstico pedagógico completo a partir de los datos crudos del fallo."""
    archivo, linea, funcion, var_culpable, frame_falla = _extraer_frame_y_variable_culpable(frames)
    texto_combinado = (gdb_output + "\n" + salida_prog).lower()
    vasquez_info = _detectar_inyeccion_vasquez(vasquez_injected, gdb_output, salida_prog, texto_combinado)

    # 0. Recursión sin caso base: con miles de marcos la pila se desborda y gdb además informa
    # «cannot access memory», que se confundía con un desborde de la dirección de retorno (QoL #474).
    if (profundidad_pila or 0) >= 1000 and "SEGV" in senal:
        diag = _diagnosticar_sigsegv(codigo_senal, direccion_memoria, archivo, linea, funcion, var_culpable, frames,
                                     salida_prog, texto_combinado, vasquez_info, profundidad_pila)
        _enriquecer_con_vasquez(diag)
        return diag

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
        diag = _diagnosticar_sigsegv(codigo_senal, direccion_memoria, archivo, linea, funcion, var_culpable, frames, salida_prog, texto_combinado, vasquez_info, profundidad_pila)
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


_RE_RETORNO_LOCAL = re.compile(
    r"In function [‘'`](?P<fn>\w+)[’'`].*?(?P<lin>\d+):\d+: warning: function returns address of local variable",
    re.DOTALL,
)


def diagnosticar_puntero_a_local(diag: DiagnosticoCrash, advertencias: str) -> DiagnosticoCrash:
    """Si el compilador avisó que una función devuelve la dirección de una variable local, el crash
    casi seguro viene de ahí: esa variable dejó de existir al terminar la función (QoL #472). Sin
    esta pista el estudiante veía un «acceso a una dirección inválida» genérico."""
    if "returns address of local variable" not in (advertencias or ""):
        return diag
    m = _RE_RETORNO_LOCAL.search(advertencias)
    fn = m.group("fn") if m else "la función"
    linea_ret = f" (línea {m.group('lin')})" if m else ""
    diag.codigo_senal = "DANGLING_STACK"
    diag.causa_raiz_titulo = "Puntero a una variable local que ya no existe (dangling pointer)"
    diag.explicacion = (
        f"La función '{fn}' devuelve la dirección de una de sus variables locales{linea_ret}.\n"
        "Las variables locales viven en el marco de pila de la función y desaparecen cuando la función "
        "termina: el puntero devuelto apunta a memoria que ya no le pertenece al programa (el compilador "
        "lo avisó con -Wreturn-local-addr). Usarlo después es comportamiento indefinido y acá terminó en "
        f"{diag.tipo_senal}."
    )
    diag.accion_correctiva = (
        "1. No devuelvas la dirección de una variable local.\n"
        "2. Si el valor tiene que sobrevivir a la función, devolvelo por valor, recibí un puntero del "
        "llamador donde escribirlo, o reservá memoria con malloc (y liberala después).\n"
        "3. Compilá con -Wall y no ignores las advertencias: esta la detectaba el compilador."
    )
    return diag


def diagnosticar_sin_terminar() -> DiagnosticoCrash:
    """El programa no terminó en el tiempo límite: no es un crash, pero tampoco hay traza."""
    return DiagnosticoCrash(
        tipo_senal="TIMEOUT",
        codigo_senal="SIN_TERMINAR",
        direccion_memoria=None,
        causa_raiz_titulo="El programa no terminó a tiempo (¿bucle infinito o espera de entrada?)",
        explicacion=(
            "El programa siguió corriendo hasta el tiempo límite sin recibir ninguna señal de error.\n"
            "Las causas típicas son un lazo cuya condición nunca se vuelve falsa o un scanf/fgets que "
            "espera datos por la entrada estándar."
        ),
        accion_correctiva=(
            "1. Revisá que la variable de control de cada lazo cambie en cada vuelta.\n"
            "2. Si el programa lee datos, pasáselos con --stdin o redirigiendo un archivo."
        ),
        es_crash=False,
    )
