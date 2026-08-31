"""Diagnóstico del entorno y dependencias externas de HAL."""

from __future__ import annotations

import shutil
from typing import Any, Dict, Optional

from rich.console import Console
from rich.table import Table


def ejecutar_diagnostico_doctor(console: Optional[Console] = None) -> bool:
    """Verifica disponibilidad de herramientas del entorno para HAL (GCC, GDB, Valgrind, Addr2line)."""
    c = console or Console()

    tabla = Table(title="Diagnóstico del Entorno HAL")
    tabla.add_column("Componente", style="bold cyan")
    tabla.add_column("Estado", justify="center")
    tabla.add_column("Detalle")

    # GCC
    gcc = shutil.which("gcc")
    tabla.add_row("Compilador GCC", "[green]✓ Presente[/green]" if gcc else "[red]✗ Faltante[/red]", gcc or "Obligatorio para compilar con -g -O0")

    # GDB
    gdb = shutil.which("gdb")
    tabla.add_row("Depurador GDB", "[green]✓ Presente[/green]" if gdb else "[yellow]⚠️ Faltante[/yellow]", gdb or "Recomendado para backtraces completos (sudo apt install gdb)")

    # Valgrind
    valgrind = shutil.which("valgrind")
    tabla.add_row("Valgrind", "[green]✓ Presente[/green]" if valgrind else "[dim]— Opcional[/dim]", valgrind or "Opcional para análisis dinámico de memoria")

    # Addr2line
    addr2line = shutil.which("addr2line")
    tabla.add_row("Binutil addr2line", "[green]✓ Presente[/green]" if addr2line else "[dim]— Opcional[/dim]", addr2line or "Para traducción de direcciones de memoria")

    c.print(tabla)

    # Requisito crítico: GCC
    return gcc is not None
