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
from hal.core.advice import obtener_consejos
from hal.core.doctor import ejecutar_diagnostico_doctor
from hal.core.fd_audit import auditar_descriptores_archivo
from hal.core.inspector import inspeccionar_fuente_o_binario
from hal.core.models import DiagnosticoCrash
from hal.core.symbols import desofuscar_direccion, inspeccionar_variables_globales
from hal.core.valgrind_parser import parsear_log_valgrind

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


def _renderizar_diagnostico_rich(diag: DiagnosticoCrash, ruta_fuente: Optional[Path] = None, mostrar_consejos: bool = False) -> None:
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

    if mostrar_consejos:
        console.print("\n[bold cyan]🎓 Consejos Didácticos de Programación Defensiva:[/bold cyan]")
        for c in obtener_consejos()[:2]:
            console.print(Panel(f"[bold]{c['regla']}[/bold]\n\n{c['explicacion']}\n\n[green]{c['ejemplo_correcto']}[/green]", title=c['tema'], border_style="cyan"))


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
    advice: bool = typer.Option(False, "--advice", help="Mostrar consejos pedagógicos adicionales."),
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

    _renderizar_diagnostico_rich(diag, ruta_fuente=objetivo if objetivo.suffix == ".c" else None, mostrar_consejos=advice)
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
    """Verifica el estado del entorno (GCC, GDB, Valgrind, addr2line)."""
    ok = ejecutar_diagnostico_doctor(console=console)
    if not ok:
        raise typer.Exit(code=1)


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


@app.command("registers")
def registers_cmd(
    objetivo: Path = typer.Argument(..., help="Archivo .c o binario a inspeccionar."),
    stdin: Optional[str] = typer.Option(None, "--stdin", "-i", help="Entrada estándar."),
    json_output: bool = typer.Option(False, "--json", help="Emitir registros en JSON."),
) -> None:
    """Muestra los valores de los registros de CPU (RAX, RSP, RIP, etc.) capturados durante el crash."""
    diag = inspeccionar_fuente_o_binario(ruta_objetivo=objetivo, stdin_data=stdin or "")

    if json_output:
        print(json.dumps(diag.registros, indent=2, ensure_ascii=False))
        raise typer.Exit(code=0)

    if not diag.registros:
        console.print("[yellow]No se capturaron registros de CPU (se requiere GDB).[/yellow]")
        raise typer.Exit(code=0)

    tabla = Table(title="🖥️ Registros de CPU en el Momento del Crash")
    tabla.add_column("Registro", style="bold cyan")
    tabla.add_column("Valor Hex / Dirección", style="green")

    for reg, val in sorted(diag.registros.items()):
        tabla.add_row(reg, val)

    console.print(tabla)


@app.command("check-fds")
def check_fds_cmd(
    fuente: Path = typer.Argument(..., help="Archivo fuente C a auditar."),
    json_output: bool = typer.Option(False, "--json", help="Salida en JSON."),
) -> None:
    """Audita aperturas de archivos y descriptores huérfanos sin cerrar."""
    res = auditar_descriptores_archivo(fuente)

    if json_output:
        print(json.dumps(res, indent=2, ensure_ascii=False))
        raise typer.Exit(code=0 if res.get("balance_correcto") else 1)

    if res.get("balance_correcto"):
        console.print(f"[bold green]✓ Todos los archivos abiertos ({res['total_aperturas']}) fueron cerrados adecuadamente con fclose()/close().[/bold green]")
        raise typer.Exit(code=0)

    console.print(f"[bold red]❌ Se detectaron {res['total_huerfanos']} descriptores de archivo huérfanos (sin fclose):[/bold red]\n")
    tabla = Table(title="Descriptores No Cerrados")
    tabla.add_column("Variable", style="bold yellow")
    tabla.add_column("Tipo", style="cyan")
    tabla.add_column("Línea", justify="right", style="green")
    tabla.add_column("Recurso", style="dim")

    for h in res.get("huerfanos", []):
        tabla.add_row(h["variable"], h["tipo"], str(h["linea"]), h.get("recurso", ""))

    console.print(tabla)
    raise typer.Exit(code=1)


@app.command("inspect-globals")
def inspect_globals_cmd(
    binario: Path = typer.Argument(..., help="Binario a inspeccionar."),
    json_output: bool = typer.Option(False, "--json", help="Salida en JSON."),
) -> None:
    """Inspecciona las variables globales y estáticas (.data y .bss) en la memoria del binario."""
    vars_list = inspeccionar_variables_globales(binario)

    if json_output:
        print(json.dumps(vars_list, indent=2, ensure_ascii=False))
        raise typer.Exit(code=0)

    if not vars_list:
        console.print("[dim]No se detectaron variables globales o estáticas exportadas en la tabla de símbolos.[/dim]")
        raise typer.Exit(code=0)

    tabla = Table(title=f"🌐 Variables Globales y Estáticas ({binario.name})")
    tabla.add_column("Nombre", style="bold cyan")
    tabla.add_column("Dirección", style="green")
    tabla.add_column("Sección", style="yellow")

    for v in vars_list:
        tabla.add_row(v["nombre"], v["direccion"], v["seccion"])

    console.print(tabla)


@app.command("resolve-addr")
def resolve_addr_cmd(
    binario: Path = typer.Argument(..., help="Binario ejecutable con símbolos."),
    direccion: str = typer.Argument(..., help="Dirección hexadecimal a desofuscar (ej: 0x555555555169)."),
    json_output: bool = typer.Option(False, "--json", help="Salida en JSON."),
) -> None:
    """Traduce una dirección de memoria hexadecimal a archivo, línea y nombre de función."""
    res = desofuscar_direccion(binario, direccion)

    if json_output:
        print(json.dumps(res, indent=2, ensure_ascii=False))
        raise typer.Exit(code=0)

    console.print(Panel(
        f"Dirección: [bold cyan]{res['direccion']}[/bold cyan]\n"
        f"Función: [bold green]{res['funcion']}[/bold green]\n"
        f"Ubicación: [bold yellow]{res['ubicacion']}[/bold yellow]",
        title="🔍 Desofuscación de Dirección DWARF",
        border_style="cyan",
    ))


@app.command("valgrind")
@app.command("parse-valgrind")
def valgrind_cmd(
    log_file: Optional[Path] = typer.Argument(None, help="Archivo de log de Valgrind o leer desde stdin."),
    json_output: bool = typer.Option(False, "--json", help="Salida en JSON."),
) -> None:
    """Parsea reportes de Valgrind Memcheck y traduce violaciones a explicaciones pedagógicas."""
    if log_file and log_file.is_file():
        texto = log_file.read_text(encoding="utf-8", errors="ignore")
    else:
        texto = sys.stdin.read()

    res = parsear_log_valgrind(texto)

    if json_output:
        print(json.dumps(res, indent=2, ensure_ascii=False))
        raise typer.Exit(code=0 if res["sin_errores"] else 1)

    if res["sin_errores"]:
        console.print("[bold green]✓ Reporte de Valgrind Limpio: Cero fugas de memoria y cero accesos inválidos.[/bold green]")
        raise typer.Exit(code=0)

    console.print(f"[bold red]❌ Se detectaron {res['total_errores']} anomalías de memoria en el log de Valgrind:[/bold red]\n")
    for err in res["errores"]:
        console.print(Panel(
            f"[bold red]{err['titulo']}[/bold red]\n\n{err['descripcion']}\n\n[dim]{err['linea_cruda']}[/dim]",
            title="⚠️ Violación de Memoria (Memcheck)",
            border_style="red",
        ))

    if res["fugas_bytes"] > 0:
        console.print(f"[bold yellow]💧 Fugas de memoria detectadas: {res['fugas_bytes']} bytes sin liberar.[/bold yellow]")

    raise typer.Exit(code=1)


@app.command("advice")
def advice_cmd() -> None:
    """Muestra consejos pedagógicos y buenas prácticas defensivas para evitar segfaults."""
    consejos = obtener_consejos()
    console.print("[bold cyan]🎓 Consejos Didácticos de Programación Defensiva en C (HAL)[/bold cyan]\n")

    for idx, c in enumerate(consejos, 1):
        console.print(Panel(
            f"🎯 [bold]{c['regla']}[/bold]\n\n"
            f"🔍 {c['explicacion']}\n\n"
            f"[bold green]✓ Correcto:[/bold green]\n{c['ejemplo_correcto']}\n\n"
            f"[bold red]✗ Incorrecto:[/bold red]\n{c['ejemplo_incorrecto']}",
            title=f"Consejo #{idx}: {c['tema']}",
            border_style="cyan",
        ))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
