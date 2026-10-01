"""Modo pista (`--pista` o `P1_PISTA=1`): qué falla hubo y en qué función, sin la línea ni la corrección.

Revisión 05 §3: en una evaluación, hal mostraba siempre la línea culpable, la variable responsable, los
valores de la pila y la acción correctiva. En modo pista el diagnóstico conserva la señal, la causa
(título y explicación), la función donde ocurrió y la cadena de llamadas por nombre, y oculta la línea,
la variable culpable, los argumentos y variables de cada frame, los registros, el volcado del struct y
la corrección. La misma variable activa el modo en daedalus y tetsuo, y ripley la exporta a los
satélites cuando la práctica lo pide (`[general] pistas = true` en ripley.toml).
"""

from __future__ import annotations

import os
import re
from dataclasses import replace
from typing import Optional

from hal.core.models import DiagnosticoCrash

VARIABLE_PISTA = "P1_PISTA"


def pista_activa(bandera: bool = False) -> bool:
    return bandera or os.environ.get(VARIABLE_PISTA, "").strip().lower() in ("1", "true", "si", "sí", "yes")


def explicacion_sin_ubicacion(texto: str, variable: Optional[str]) -> str:
    """La explicación sin las oraciones que dicen la línea («En la línea 5, …») o nombran la variable culpable."""
    oraciones = re.split(r"(?<=[.!?])\s+|\n+", texto)
    ocultar = [re.compile(r"\bl[ií]neas?\s+\d+", re.IGNORECASE)]
    if variable:
        ocultar.append(re.compile(rf"['`\"]{re.escape(variable)}['`\"]"))
    return " ".join(o for o in oraciones if o.strip() and not any(r.search(o) for r in ocultar))


def diagnostico_en_pista(diag: DiagnosticoCrash) -> DiagnosticoCrash:
    if not diag.es_crash:
        return diag  # una ejecución sin falla, o un error al ejecutar: no hay nada que ocultar
    frames = [replace(f, linea=None, argumentos={}, variables_locales={}, instruccion=None) for f in diag.frames]
    return replace(diag, linea_falla=None, variable_culpable=None, accion_correctiva="", frames=frames,
                   registros={}, campos_struct=None, pista=True,
                   explicacion=explicacion_sin_ubicacion(diag.explicacion, diag.variable_culpable))
