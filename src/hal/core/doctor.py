"""Diagnóstico del entorno y dependencias externas de HAL."""

from __future__ import annotations

import shutil
import subprocess
from typing import Any, Dict, Optional

from rich.console import Console
from rich.table import Table


def gdb_tiene_python(gdb: Optional[str]) -> bool:
    """Si `gdb` trae Python: sin él hal no puede leer la traza de la falla."""
    if not gdb:
        return False
    try:
        res = subprocess.run([gdb, "-nx", "-batch", "-ex", "python print('hal-ok')"], capture_output=True, text=True,
                             timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return "hal-ok" in res.stdout


def obtener_estado_doctor() -> Dict[str, Any]:
    """Obtiene el estado de las herramientas del entorno en una estructura serializable."""
    gcc = shutil.which("gcc")
    gdb = shutil.which("gdb")
    con_python = gdb_tiene_python(gdb)
    valgrind = shutil.which("valgrind")
    addr2line = shutil.which("addr2line")

    from hal import __version__

    herramientas = {
        "gcc": {"presente": gcc is not None, "ruta": gcc, "requerido": True},
        "gdb": {"presente": gdb is not None, "ruta": gdb, "requerido": False},
        "gdb (Python)": {"presente": con_python, "ruta": "La traza de la falla se lee con la API Python de gdb" if con_python
                         else None, "requerido": False},
        "valgrind": {"presente": valgrind is not None, "ruta": valgrind, "requerido": False},
        "addr2line": {"presente": addr2line is not None, "ruta": addr2line, "requerido": False},
    }
    return {
        # Sobre común de `doctor --json` (N-ECO-04); "herramientas" se conserva
        # por compatibilidad con quien ya lo consumía.
        "schema_version": "1.0.0",
        "herramienta": "hal",
        "version": __version__,
        "ok": gcc is not None,
        "chequeos": [
            {"nombre": nombre, "requerido": info["requerido"], "ok": info["presente"],
             "detalle": info["ruta"] or ("Sin traza de la falla: instalá un gdb con soporte de Python"
                                         if nombre == "gdb (Python)" else "No encontrado en $PATH")}
            for nombre, info in herramientas.items()
        ],
        "herramientas": herramientas,
    }


def ejecutar_diagnostico_doctor(console: Optional[Console] = None) -> bool:
    """Verifica disponibilidad de herramientas del entorno para HAL (GCC, GDB, Valgrind, Addr2line)."""
    c = console or Console()
    estado = obtener_estado_doctor()
    herramientas = estado["herramientas"]

    tabla = Table(title="Diagnóstico del Entorno HAL")
    tabla.add_column("Componente", style="bold cyan")
    tabla.add_column("Estado", justify="center")
    tabla.add_column("Detalle")

    # GCC
    gcc_info = herramientas["gcc"]
    tabla.add_row("Compilador GCC", "[green]✓ Presente[/green]" if gcc_info["presente"] else "[red]✗ Faltante[/red]", gcc_info["ruta"] or "Obligatorio para compilar con -g -O0")

    # GDB
    gdb_info = herramientas["gdb"]
    tabla.add_row("Depurador GDB", "[green]✓ Presente[/green]" if gdb_info["presente"] else "[yellow]⚠️ Faltante[/yellow]", gdb_info["ruta"] or "Recomendado para trazas de llamadas completas (sudo apt install gdb)")

    py_info = herramientas["gdb (Python)"]
    tabla.add_row("GDB con Python", "[green]✓ Presente[/green]" if py_info["presente"] else "[yellow]⚠️ Faltante[/yellow]",
                  py_info["ruta"] or "Sin esto no hay traza de la falla: instalá un gdb con soporte de Python")

    # Valgrind
    val_info = herramientas["valgrind"]
    tabla.add_row("Valgrind", "[green]✓ Presente[/green]" if val_info["presente"] else "[dim]— Opcional[/dim]", val_info["ruta"] or "Opcional para análisis dinámico de memoria")

    # Addr2line
    addr_info = herramientas["addr2line"]
    tabla.add_row("Binutil addr2line", "[green]✓ Presente[/green]" if addr_info["presente"] else "[dim]— Opcional[/dim]", addr_info["ruta"] or "Para traducción de direcciones de memoria")

    c.print(tabla)

    # Requisito crítico: GCC
    return bool(estado["ok"])
