"""CLI de HAL — Asistente forense de core dumps y análisis post-mortem de segfaults."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from hal import __version__
from hal.core.inspector import inspeccionar_fuente_o_binario
from hal.core.models import DiagnosticoCrash

console = Console()
err_console = Console(stderr=True)

app = typer.Typer(
    name="hal",
    help="🤖 HAL — Asistente forense de core dumps y análisis pedagógico post-mortem de segfaults en C.",
    add_completion=True,
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold cyan]HAL[/bold cyan] versión [bold]{__version__}[/bold]")
        raise typer.Exit(code=0)


@app.callback()
def main_callback(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Muestra la versión de HAL.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    pass


def _renderizar_diagnostico_rich(diag: DiagnosticoCrash, ruta_fuente: Optional[Path] = None) -> None:
    """Renderiza el diagnóstico pedagógico con formato Rich en terminal."""
    if not diag.es_crash:
        if diag.tipo_senal == "ERROR":
            err_console.print(Panel(
                f"[bold red]❌ {diag.causa_raiz_titulo}[/bold red]\n\n{diag.explicacion}\n\n[dim]{diag.accion_correctiva}[/dim]",
                title="Error en HAL",
                border_style="red",
            ))
        else:
            console.print(Panel(
                f"[bold green]✓ {diag.causa_raiz_titulo}[/bold green]\n\n{diag.explicacion}",
                title="Ejecución Exitosa",
                border_style="green",
            ))
        return

    # Panel de Señal y Causa Raíz
    header = (
        f"[bold red]💥 SEÑAL FATAL DETECTADA: {diag.tipo_senal}[/bold red]"
        + (f" ({diag.codigo_senal})" if diag.codigo_senal else "")
        + (f" en dirección [bold cyan]{diag.direccion_memoria}[/bold cyan]" if diag.direccion_memoria else "")
    )
    if diag.archivo_falla and diag.linea_falla:
        header += f"\n📍 [bold]Ubicación:[/bold] [yellow]{diag.archivo_falla}:{diag.linea_falla}[/yellow] (en función [cyan]{diag.funcion_falla or 'main'}[/cyan])"

    console.print(Panel(header, title="🚨 Diagnóstico Forense de HAL", border_style="red"))

    # Explicación Pedagógica
    console.print(Panel(
        f"[bold yellow]🔍 Causa Raíz:[/bold yellow] [bold]{diag.causa_raiz_titulo}[/bold]\n\n{diag.explicacion}",
        title="📘 Explicación Pedagógica",
        border_style="yellow",
    ))

    # Snippet de código fuente si el archivo existe
    if diag.archivo_falla and diag.linea_falla and Path(diag.archivo_falla).is_file():
        try:
            contenido = Path(diag.archivo_falla).read_text(encoding="utf-8")
            lineas = contenido.splitlines()
            start_l = max(1, diag.linea_falla - 4)
            end_l = min(len(lineas), diag.linea_falla + 4)
            codigo_recortado = "\n".join(lineas[start_l - 1:end_l])

            console.print(Panel(
                Syntax(
                    codigo_recortado,
                    "c",
                    line_numbers=True,
                    start_line=start_l,
                    highlight_lines={diag.linea_falla},
                    theme="monokai",
                ),
                title=f"📄 Contexto del Código ({Path(diag.archivo_falla).name}:{diag.linea_falla})",
                border_style="blue",
            ))
        except Exception:
            pass

    # Call Stack / Backtrace Table
    if diag.frames:
        tabla_bt = Table(title="🥞 Pila de Llamadas (Call Stack Backtrace)")
        tabla_bt.add_column("#", justify="right", style="bold")
        tabla_bt.add_column("Función", style="cyan")
        tabla_bt.add_column("Argumentos", style="dim")
        tabla_bt.add_column("Ubicación", style="yellow")
        tabla_bt.add_column("Variables Locales", style="green")

        for f in diag.frames:
            ubicacion = f"{Path(f.archivo).name}:{f.linea}" if f.archivo and f.linea else (f.archivo or "—")
            args_str = ", ".join(f"{k}={v}" for k, v in f.argumentos.items()) if f.argumentos else "—"
            locals_str = ", ".join(f"{k}={v}" for k, v in f.variables_locales.items()) if f.variables_locales else "—"
            tabla_bt.add_row(str(f.nivel), f.funcion, args_str, ubicacion, locals_str)

        console.print(tabla_bt)

    # Acción Correctiva
    console.print(Panel(
        f"[bold green]💡 ¿Cómo solucionarlo?[/bold green]\n\n{diag.accion_correctiva}",
        title="🛠️ Acción Correctiva Sugerida",
        border_style="green",
    ))


@app.command("run")
def run_cmd(
    objetivo: Path = typer.Argument(..., help="Ruta al archivo C (.c) o binario a ejecutar y diagnosticar."),
    args: Optional[List[str]] = typer.Argument(None, help="Argumentos a pasar al programa."),
    stdin: Optional[str] = typer.Option(None, "--stdin", "-i", help="Cadena de texto para enviar a la entrada estándar (stdin)."),
    json_output: bool = typer.Option(False, "--json", help="Emitir diagnóstico estructurado en formato JSON."),
    gdb_path: Optional[str] = typer.Option(None, "--gdb", help="Ruta al binario de GDB."),
) -> None:
    """Compila (si es .c), ejecuta el programa y genera un diagnóstico forense pedagógico si ocurre un crash."""
    diag = inspeccionar_fuente_o_binario(
        ruta_objetivo=objetivo,
        args=args or [],
        stdin_data=stdin or "",
        gdb_path=gdb_path,
    )

    if json_output:
        print(json.dumps(diag.to_dict(), indent=2, ensure_ascii=False))
        raise typer.Exit(code=1 if diag.es_crash else 0)

    _renderizar_diagnostico_rich(diag, ruta_fuente=objetivo if objetivo.suffix == ".c" else None)
    raise typer.Exit(code=1 if diag.es_crash else 0)


@app.command("inspect")
def inspect_cmd(
    binario: Path = typer.Argument(..., help="Binario ejecutable a inspeccionar."),
    json_output: bool = typer.Option(False, "--json", help="Emitir diagnóstico en formato JSON."),
    gdb_path: Optional[str] = typer.Option(None, "--gdb", help="Ruta a GDB."),
) -> None:
    """Inspecciona un binario compilado ante posibles fallos de ejecución."""
    diag = inspeccionar_fuente_o_binario(
        ruta_objetivo=binario,
        gdb_path=gdb_path,
    )

    if json_output:
        print(json.dumps(diag.to_dict(), indent=2, ensure_ascii=False))
        raise typer.Exit(code=1 if diag.es_crash else 0)

    _renderizar_diagnostico_rich(diag)
    raise typer.Exit(code=1 if diag.es_crash else 0)


@app.command("doctor")
def doctor_cmd() -> None:
    """Verifica el estado del entorno (GCC, GDB, configuración de core dumps y límites de sistema)."""
    tabla = Table(title="Diagnóstico del Entorno HAL")
    tabla.add_column("Componente", style="bold cyan")
    tabla.add_column("Estado", justify="center")
    tabla.add_column("Detalle")

    # GCC
    gcc = shutil.which("gcc")
    tabla.add_row("Compilador GCC", "[green]✓ Presente[/green]" if gcc else "[red]✗ Faltante[/red]", gcc or "No encontrado en PATH")

    # GDB
    gdb = shutil.which("gdb")
    tabla.add_row("Depurador GDB", "[green]✓ Presente[/green]" if gdb else "[yellow]⚠️ Faltante[/yellow]", gdb or "Instalar gdb para backtraces completos (sudo apt install gdb)")

    # Valgrind
    valgrind = shutil.which("valgrind")
    tabla.add_row("Valgrind", "[green]✓ Presente[/green]" if valgrind else "[dim]— Opcional[/dim]", valgrind or "No instalado")

    console.print(tabla)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
