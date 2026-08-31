"""Modelos de datos para el análisis forense de crashes en HAL."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class StackFrame:
    """Representa un frame individual en el call stack del crash."""
    nivel: int
    funcion: str
    archivo: Optional[str] = None
    linea: Optional[int] = None
    argumentos: Dict[str, str] = field(default_factory=dict)
    variables_locales: Dict[str, str] = field(default_factory=dict)
    instruccion: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nivel": self.nivel,
            "funcion": self.funcion,
            "archivo": self.archivo,
            "linea": self.linea,
            "argumentos": self.argumentos,
            "variables_locales": self.variables_locales,
            "instruccion": self.instruccion,
        }


@dataclass
class DiagnosticoCrash:
    """Diagnóstico pedagógico estructurado de un fallo en tiempo de ejecución."""
    tipo_senal: str               # SIGSEGV, SIGABRT, SIGFPE, SIGILL, SIGBUS
    codigo_senal: Optional[str]   # SEGV_MAPERR, SEGV_ACCERR, FPE_INTDIV, BUS_ADRALN, etc.
    direccion_memoria: Optional[str]
    causa_raiz_titulo: str
    explicacion: str
    accion_correctiva: str
    archivo_falla: Optional[str] = None
    linea_falla: Optional[int] = None
    funcion_falla: Optional[str] = None
    variable_culpable: Optional[str] = None
    frames: List[StackFrame] = field(default_factory=list)
    registros: Dict[str, str] = field(default_factory=dict)
    descriptores_abiertos: List[str] = field(default_factory=list)
    salida_programa: str = ""
    es_crash: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "es_crash": self.es_crash,
            "tipo_senal": self.tipo_senal,
            "codigo_senal": self.codigo_senal,
            "direccion_memoria": self.direccion_memoria,
            "causa_raiz_titulo": self.causa_raiz_titulo,
            "explicacion": self.explicacion,
            "accion_correctiva": self.accion_correctiva,
            "archivo_falla": self.archivo_falla,
            "linea_falla": self.linea_falla,
            "funcion_falla": self.funcion_falla,
            "variable_culpable": self.variable_culpable,
            "frames": [f.to_dict() for f in self.frames],
            "registros": self.registros,
            "descriptores_abiertos": self.descriptores_abiertos,
            "salida_programa": self.salida_programa,
        }
