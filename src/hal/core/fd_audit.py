"""Módulo de auditoría de descriptores de archivo huérfanos en HAL."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional


def auditar_descriptores_archivo(fuente: Path) -> Dict[str, Any]:
    """Audita aperturas de archivo (fopen, open, socket) vs cierres (fclose, close) en código C."""
    fuente = Path(fuente)
    if not fuente.is_file():
        return {"error": f"Archivo '{fuente}' no encontrado."}

    contenido = fuente.read_text(encoding="utf-8", errors="ignore")
    lineas = contenido.splitlines()

    aperturas: List[Dict[str, Any]] = []
    cierres: List[Dict[str, Any]] = []

    re_fopen = re.compile(r'(\b[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\bfopen\s*\(([^,]+),\s*([^)]+)\)')
    re_open = re.compile(r'(\b[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(?:\bopen|\bsocket)\s*\(')
    re_fclose = re.compile(r'\bfclose\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)')
    re_close = re.compile(r'\bclose\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)')

    for idx, l in enumerate(lineas, 1):
        m_f = re_fopen.search(l)
        if m_f:
            aperturas.append({
                "variable": m_f.group(1),
                "tipo": "fopen",
                "recurso": m_f.group(2).strip(),
                "linea": idx,
            })
        m_o = re_open.search(l)
        if m_o:
            aperturas.append({
                "variable": m_o.group(1),
                "tipo": "open/socket",
                "recurso": "descriptor",
                "linea": idx,
            })
        m_fc = re_fclose.search(l)
        if m_fc:
            cierres.append({
                "variable": m_fc.group(1),
                "linea": idx,
            })
        m_c = re_close.search(l)
        if m_c:
            cierres.append({
                "variable": m_c.group(1),
                "linea": idx,
            })

    variables_cerradas = {c["variable"] for c in cierres}
    huerfanos = [a for a in aperturas if a["variable"] not in variables_cerradas]

    return {
        "total_aperturas": len(aperturas),
        "total_cierres": len(cierres),
        "total_huerfanos": len(huerfanos),
        "huerfanos": huerfanos,
        "aperturas": aperturas,
        "cierres": cierres,
        "balance_correcto": len(huerfanos) == 0,
    }
