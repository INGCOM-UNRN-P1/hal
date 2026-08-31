"""Módulo de parsing y traducción didáctica de reportes de Valgrind Memcheck en HAL."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional


def parsear_log_valgrind(texto_log: str) -> Dict[str, Any]:
    """Parsea la salida de Valgrind Memcheck y traduce violaciones de memoria a español rioplatense."""
    lineas = texto_log.splitlines()
    errores: List[Dict[str, Any]] = []

    patrones = [
        (r"Invalid read of size (\d+)", "Lectura de memoria inválida (Invalid Read)", "El programa intentó leer {0} bytes en una dirección no asignada o ya liberada."),
        (r"Invalid write of size (\d+)", "Escritura de memoria inválida (Invalid Write)", "El programa intentó escribir {0} bytes fuera de los límites de un bloque de memoria (Buffer Overflow)."),
        (r"Conditional jump or move depends on uninitialised value\(s\)", "Salto condicional sobre variable no inicializada", "Se evaluó un `if`, `while` o `for` usando una variable que contiene basura de la memoria."),
        (r"Use of uninitialised value of size (\d+)", "Uso de valor no inicializado", "Se utilizó una variable o struct de {0} bytes sin haberle asignado un valor inicial previo."),
        (r"definitely lost: ([0-9,]+) bytes in (\d+) blocks", "Fuga definitiva de memoria (Memory Leak)", "Se perdieron {0} bytes en {1} bloques asignados con malloc que nunca fueron liberados con `free()`."),
        (r"indirectly lost: ([0-9,]+) bytes in (\d+) blocks", "Fuga indirecta de memoria", "Se perdieron {0} bytes contenidos dentro de estructuras dinámicas cuyos punteros raíz fueron extraviados."),
    ]

    for l in lineas:
        line_clean = re.sub(r"^==\d+==\s*", "", l).strip()
        for pat, tit, desc in patrones:
            m = re.search(pat, line_clean)
            if m:
                args = m.groups()
                desc_formateada = desc.format(*args) if args else desc
                errores.append({
                    "titulo": tit,
                    "descripcion": desc_formateada,
                    "linea_cruda": line_clean,
                })

    # Resumen de memoria
    fugas_totales = 0
    m_leak = re.search(r"definitely lost:\s*([0-9,]+)\s*bytes", texto_log)
    if m_leak:
        fugas_totales = int(m_leak.group(1).replace(",", ""))

    return {
        "total_errores": len(errores),
        "fugas_bytes": fugas_totales,
        "sin_errores": len(errores) == 0,
        "errores": errores,
    }
