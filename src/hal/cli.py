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


def generar_seccion_markdown(diag: DiagnosticoCrash) -> str:
    """Genera sección de análisis forense y crash para Dredd."""
    lines = ["## Diagnóstico Forense de Crash y Señales (Hal)\n"]
    if not diag.es_crash:
        lines.append("- **Estado:** ✓ Ejecución Exitosa (Sin caídas ni violaciones de memoria)\n")
        lines.append("> [!TIP]\n> **Proceso Estable:** El programa finalizó correctamente sin arrojar señales fatales ni desbordamiento de pila.\n")
    else:
        lines.append(f"- **Señal Fatal:** `{diag.tipo_senal}` ({diag.codigo_senal or 'CRASH'})\n")
        if diag.archivo_falla and diag.linea_falla:
            lines.append(f"- **Ubicación:** `{Path(diag.archivo_falla).name}:{diag.linea_falla}` (en `{diag.funcion_falla or 'main'}`)")
        if diag.direccion_memoria:
            lines.append(f"- **Dirección de Memoria Inválida:** `{diag.direccion_memoria}`")
        lines.append(f"- **Causa Raíz:** {diag.causa_raiz_titulo}\n")
        lines.append(f"> [!CAUTION]\n> **Fallo Fatal:** {diag.explicacion}\n")
        lines.append(f"**Sugerencia de corrección:** {diag.accion_correctiva}\n")
        if diag.frames:
            lines.append("### Pila de Ejecución (Stack Frames)")
            lines.append("| Frame # | Función | Ubicación |")
            lines.append("| :---: | :--- | :--- |")
            for f in diag.frames:
                loc = f"`{Path(f.archivo).name}:{f.linea}`" if f.archivo and f.linea else (f.archivo or "—")
                lines.append(f"| {f.nivel} | `{f.funcion}()` | {loc} |")
            lines.append("")
    return "\n".join(lines)


@app.command("run")
@app.command("check")
def run_cmd(
    objetivo: Path = typer.Argument(..., help="Ruta al archivo C (.c) o binario a ejecutar y diagnosticar."),
    args: Optional[List[str]] = typer.Argument(None, help="Argumentos a pasar al programa."),
    stdin: Optional[str] = typer.Option(None, "--stdin", "-i", help="Cadena de texto para enviar a la entrada estándar (stdin)."),
    json_output: bool = typer.Option(False, "--json", help="Emitir diagnóstico estructurado en formato JSON."),
    gdb_path: Optional[str] = typer.Option(None, "--gdb", help="Ruta al binario de GDB."),
    output_md: Optional[Path] = typer.Option(None, "--md", "--output-md", "-o", help="Generar sección de reporte en formato Markdown para fusión en Dredd."),
) -> None:
    """Compila (si es .c), ejecuta el programa y genera un diagnóstico forense pedagógico si ocurre un crash."""
    diag = inspeccionar_fuente_o_binario(
        ruta_objetivo=objetivo,
        args=args or [],
        stdin_data=stdin or "",
        gdb_path=gdb_path,
    )

    if output_md:
        md_text = generar_seccion_markdown(diag)
        output_md.parent.mkdir(parents=True, exist_ok=True)
        output_md.write_text(md_text, encoding="utf-8")
        console.print(f"[green]✓ Sección Markdown generada en:[/green] [cyan]{output_md}[/cyan]")
        raise typer.Exit(code=1 if diag.es_crash else 0)

    if json_output:
        print(json.dumps(diag.to_dict(), indent=2, ensure_ascii=False))
        raise typer.Exit(code=1 if diag.es_crash else 0)

    _renderizar_diagnostico_rich(diag, ruta_fuente=objetivo if objetivo.suffix == ".c" else None)
    raise typer.Exit(code=1 if diag.es_crash else 0)


@app.command("report")
def report_cmd(
    objetivo: Path = typer.Argument(..., help="Ruta al archivo C (.c) o binario a diagnosticar."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Ruta de destino del archivo Markdown."),
    stdin: Optional[str] = typer.Option(None, "--stdin", "-i", help="Entrada estándar."),
) -> None:
    """Genera directamente la sección de reporte Markdown de HAL para Dredd."""
    diag = inspeccionar_fuente_o_binario(
        ruta_objetivo=objetivo,
        args=[],
        stdin_data=stdin or "",
    )
    md_content = generar_seccion_markdown(diag)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(md_content, encoding="utf-8")
        console.print(f"[green]✓ Reporte Markdown generado en:[/green] [cyan]{output}[/cyan]")
    else:
        print(md_content)


@app.command("inspect")
def inspect_cmd(
    binario: Path = typer.Argument(..., help="Binario ejecutable a inspeccionar."),
    json_output: bool = typer.Option(False, "--json", help="Emitir diagnóstico en formato JSON."),
    gdb_path: Optional[str] = typer.Option(None, "--gdb", help="Ruta a GDB."),
    output_md: Optional[Path] = typer.Option(None, "--md", "--output-md", help="Generar sección de reporte en Markdown."),
) -> None:
    """Inspecciona un binario compilado ante posibles fallos de ejecución."""
    diag = inspeccionar_fuente_o_binario(
        ruta_objetivo=binario,
        gdb_path=gdb_path,
    )

    if output_md:
        md_text = generar_seccion_markdown(diag)
        output_md.parent.mkdir(parents=True, exist_ok=True)
        output_md.write_text(md_text, encoding="utf-8")
        console.print(f"[green]✓ Sección Markdown generada en:[/green] [cyan]{output_md}[/cyan]")
        raise typer.Exit(code=1 if diag.es_crash else 0)

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


@app.command("generate-reproducer")
def generate_reproducer_cmd(
    objetivo: Path = typer.Argument(..., help="Archivo .c o binario que produce el crash."),
    output: Path = typer.Option(Path("reproducer.sh"), "--output", "-o", help="Ruta de destino del script bash."),
    stdin: Optional[str] = typer.Option(None, "--stdin", "-i", help="Datos de entrada estándar."),
    args: Optional[str] = typer.Option(None, "--args", "-a", help="Argumentos de línea de comando."),
) -> None:
    """Genera un script autónomo en Bash para reproducir exactamente el crash en cualquier máquina."""
    is_c = objetivo.suffix == ".c"
    arg_str = args or ""
    stdin_str = f"echo '{stdin}' | " if stdin else ""

    if is_c:
        script = f"""#!/usr/bin/env bash
# Script autónomo de reproducción generado por HAL
set -euo pipefail
echo "Compilando {objetivo.name} con símbolos de depuración y AddressSanitizer..."
gcc -std=c11 -Wall -Wextra -g -O0 -fsanitize=address,undefined "{objetivo.resolve()}" -o /tmp/crash_app
echo "Ejecutando binario..."
{stdin_str}/tmp/crash_app {arg_str}
"""
    else:
        script = f"""#!/usr/bin/env bash
# Script autónomo de reproducción generado por HAL
set -euo pipefail
echo "Ejecutando binario {objetivo.name}..."
{stdin_str}"{objetivo.resolve()}" {arg_str}
"""

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(script, encoding="utf-8")
    output.chmod(0o755)
    console.print(f"[bold green]✓ Script de reproducción generado exitosamente en:[/bold green] [cyan]{output}[/cyan]")


@app.command("replay")
def replay_cmd(
    objetivo: Path = typer.Argument(..., help="Archivo .c o binario a re-ejecutar en modo diagnóstico."),
    stdin: Optional[str] = typer.Option(None, "--stdin", "-i", help="Datos de entrada estándar."),
) -> None:
    """Ejecuta y navega paso a paso la traza forense del crash con renderizado Rich."""
    console.print(f"[bold cyan]🎬 Replay forense interactivo de HAL sobre:[/bold cyan] [yellow]{objetivo.name}[/yellow]...")
    diag = inspeccionar_fuente_o_binario(
        ruta_objetivo=objetivo,
        args=[],
        stdin_data=stdin or "",
    )
    _renderizar_diagnostico_rich(diag)
    raise typer.Exit(code=1 if diag.es_crash else 0)


def main() -> None:
    app()


if __name__ == "__main__":
    main()

