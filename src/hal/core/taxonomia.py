"""El diagnóstico de un crash en la taxonomía común del ecosistema (yutani.hallazgos)."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from yutani.hallazgos import hallazgo

from hal.core.models import DiagnosticoCrash

# código de hal (codigo_senal o tipo_senal) → (código estable, categoría)
_POR_CODIGO: Dict[str, Tuple[str, str]] = {
    "STACK_OVERFLOW": ("recursion-sin-caso-base", "recursion"),
    "DANGLING_STACK": ("puntero-a-local", "punteros"),
    "WILD_POINTER": ("puntero-sin-inicializar", "punteros"),
    "SEGV_MAPERR": ("acceso-invalido", "punteros"),
    "SEGV_ACCERR": ("acceso-sin-permiso", "punteros"),
    "RET_ADDR_CORRUPTED": ("desborde-de-buffer", "arreglos"),
    "SIN_TERMINAR": ("sin-terminar", "control"),
}
_POR_SENAL: Dict[str, Tuple[str, str]] = {
    "SIGFPE": ("division-por-cero", "numeros"),
    "SIGABRT": ("abort", "memoria"),
    "SIGBUS": ("acceso-desalineado", "punteros"),
    "SIGSEGV": ("acceso-invalido", "punteros"),
}


def clasificar(diag: DiagnosticoCrash) -> Tuple[str, str]:
    if diag.es_use_after_free:
        return "uso-despues-de-free", "memoria"
    if diag.es_invalid_free:
        return "free-invalido", "memoria"
    if diag.es_oom_enomem:
        return "sin-memoria", "memoria"
    if diag.es_assert_fallido:
        return "assert-fallido", "pruebas"
    if diag.es_buffer_overflow_ret:
        return "desborde-de-buffer", "arreglos"
    if diag.codigo_senal in _POR_CODIGO:
        return _POR_CODIGO[diag.codigo_senal]
    return _POR_SENAL.get(diag.tipo_senal, ("senal-" + diag.tipo_senal.lower(), "punteros"))


def hallazgos(diag: DiagnosticoCrash) -> List[Dict[str, Any]]:
    """Un hallazgo si hubo un crash o el programa no terminó; ninguno si terminó bien."""
    if not diag.es_crash and diag.codigo_senal != "SIN_TERMINAR":
        return []
    codigo, categoria = clasificar(diag)
    return [hallazgo("hal", codigo, categoria, "error", diag.causa_raiz_titulo,
                     archivo=diag.archivo_falla, linea=diag.linea_falla,
                     sugerencia=diag.accion_correctiva or None)]
