"""El diagnóstico de un crash en la taxonomía común del ecosistema (yutani.hallazgos)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
    "STACK_FRAME_TOO_LARGE": ("arreglo-local-demasiado-grande", "arreglos"),
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
    if diag.pila and diag.pila.get("causa") == "caso-base-inalcanzable":
        return "caso-base-inalcanzable", "recursion"
    if diag.codigo_senal in _POR_CODIGO:
        return _POR_CODIGO[diag.codigo_senal]
    return _POR_SENAL.get(diag.tipo_senal, ("senal-" + diag.tipo_senal.lower(), "punteros"))


def hallazgos(diag: DiagnosticoCrash) -> List[Dict[str, Any]]:
    """Un hallazgo si hubo un crash o el programa no terminó; ninguno si terminó bien."""
    if not diag.es_crash and diag.codigo_senal != "SIN_TERMINAR":
        return []
    codigo, categoria = clasificar(diag)
    h = hallazgo("hal", codigo, categoria, "error", diag.causa_raiz_titulo,
                 archivo=ruta_relativa(diag.archivo_falla), linea=diag.linea_falla or None,
                 sugerencia=diag.accion_correctiva or None)
    # El porqué en español (lo que jonesy muestra con F1), clave opcional de la forma común.
    if diag.explicacion:
        h["explicacion"] = diag.explicacion
    return [h]


def ruta_relativa(ruta: Optional[str]) -> Optional[str]:
    """El archivo como lo esperan jonesy y los demás clientes (yutani.hallazgos.ruta_archivo):
    relativo al directorio de trabajo, con / y sin ./; afuera de él, absoluto. gdb informa la ruta
    con la que se compiló (absoluta, casi siempre)."""
    if not ruta:
        return None
    p = Path(ruta.replace("\\", "/") if not ruta.startswith("/") else ruta)
    if p.is_absolute():
        try:
            relativa = os.path.relpath(p, Path.cwd())
        except ValueError:  # otra unidad en Windows
            return p.as_posix()
        if relativa == os.pardir or relativa.startswith(os.pardir + os.sep):
            return p.as_posix()
        p = Path(relativa)
    return Path(os.path.normpath(p)).as_posix()
