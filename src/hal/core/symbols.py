"""Módulo de desofuscación de direcciones de memoria e inspección de símbolos en HAL."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


def desofuscar_direccion(
    binario: Path,
    direccion_hex: str,
) -> Dict[str, Any]:
    """Traduce una dirección de memoria hexadecimal a archivo, línea y nombre de función mediante addr2line o GDB."""
    binario = Path(binario)
    if not binario.is_file():
        return {"error": f"El binario '{binario}' no existe."}

    addr2line = shutil.which("addr2line")
    if addr2line:
        cmd = [addr2line, "-e", str(binario.resolve()), "-f", "-C", direccion_hex]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                lineas = res.stdout.strip().splitlines()
                func = lineas[0] if len(lineas) > 0 else "??"
                loc = lineas[1] if len(lineas) > 1 else "??"
                return {
                    "direccion": direccion_hex,
                    "funcion": func,
                    "ubicacion": loc,
                    "desofuscado": func != "??" and loc != "??:0",
                }
        except Exception:
            pass

    # Fallback con nm
    nm = shutil.which("nm")
    if nm:
        cmd_nm = [nm, "-C", str(binario.resolve())]
        try:
            res_nm = subprocess.run(cmd_nm, capture_output=True, text=True, timeout=5)
            for linea in res_nm.stdout.splitlines():
                partes = linea.split()
                if len(partes) >= 3 and direccion_hex.lower().endswith(partes[0].lower()):
                    return {
                        "direccion": direccion_hex,
                        "funcion": partes[2],
                        "ubicacion": "tabla de símbolos",
                        "desofuscado": True,
                    }
        except Exception:
            pass

    return {
        "direccion": direccion_hex,
        "funcion": "símbolo desconocido",
        "ubicacion": "no disponible",
        "desofuscado": False,
    }


def inspeccionar_variables_globales(binario: Path) -> List[Dict[str, str]]:
    """Extrae las variables globales y estáticas (.data y .bss) de la tabla de símbolos del binario."""
    binario = Path(binario)
    if not binario.is_file():
        return []

    nm = shutil.which("nm")
    if not nm:
        return []

    cmd = [nm, "-C", "-B", str(binario.resolve())]
    variables: List[Dict[str, str]] = []
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        for linea in res.stdout.splitlines():
            partes = linea.split()
            if len(partes) >= 3:
                addr, tipo, nombre = partes[0], partes[1], " ".join(partes[2:])
                # Tipos de símbolos: B/b (BSS/no inicializada), D/d (Data/inicializada), R/r (Read-only)
                if tipo in ("B", "b", "D", "d", "G", "g", "S", "s"):
                    seccion = "BSS (No inicializada)" if tipo.upper() == "B" else "DATA (Inicializada)"
                    variables.append({
                        "nombre": nombre,
                        "direccion": f"0x{addr}",
                        "tipo": tipo,
                        "seccion": seccion,
                    })
    except Exception:
        pass

    return variables
