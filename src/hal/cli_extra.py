"""Comandos secundarios de HAL (reproductor, registros, descriptores, globales, valgrind, esquema y
consejos): salieron de `cli.py` (746 líneas, revisión 07) y se registran en la misma app.
"""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table

from hal.core.advice import obtener_consejos
from hal.core.fd_audit import auditar_descriptores_archivo
from hal.core.inspector import inspeccionar_fuente_o_binario
from hal.core.symbols import desofuscar_direccion, inspeccionar_variables_globales
from hal.core.valgrind_parser import parsear_log_valgrind

from hal.cli import _existente, app, console
from hal.presentacion import _codigo_salida, _renderizar_diagnostico_rich


def script_reproductor(objetivo: Path, stdin: Optional[str] = None, args: Optional[str] = None) -> str:
    """Script Bash que reproduce el crash (N-HAL-02).

    El binario se compila en un directorio propio creado con mktemp (no en una ruta fija
    de /tmp que otro usuario podría ocupar) y se borra al salir; la ruta, la entrada y los
    argumentos van citados para el shell.
    """
    argumentos = " ".join(shlex.quote(a) for a in shlex.split(args or ""))
    entrada = f"printf '%s\\n' {shlex.quote(stdin)} | " if stdin else ""
    ruta = shlex.quote(str(objetivo.resolve()))
    encabezado = "#!/usr/bin/env bash\n# Script autónomo de reproducción generado por HAL\nset -euo pipefail\n"
    if objetivo.suffix == ".c":
        return (
            encabezado
            + 'DIR="$(mktemp -d)"\n'
            + "trap 'rm -rf \"$DIR\"' EXIT\n"
            + f"echo {shlex.quote(f'Compilando {objetivo.name} con símbolos de depuración y AddressSanitizer...')}\n"
            + f'gcc -std=c11 -Wall -Wextra -g -O0 -fsanitize=address,undefined {ruta} -o "$DIR/crash_app"\n'
            + 'echo "Ejecutando binario..."\n'
            + f'{entrada}"$DIR/crash_app" {argumentos}\n'
        )
    return (
        encabezado
        + f"echo {shlex.quote(f'Ejecutando binario {objetivo.name}...')}\n"
        + f"{entrada}{ruta} {argumentos}\n"
    )


@app.command("generate-reproducer")
def generate_reproducer_cmd(
    objetivo: Path = typer.Argument(..., callback=_existente, help="Archivo .c o binario que produce el crash."),
    output: Path = typer.Option(Path("reproducer.sh"), "--output", "-o", help="Ruta de destino del script bash."),
    stdin: Optional[str] = typer.Option(None, "--stdin", "-i", help="Datos de entrada estándar."),
    args: Optional[str] = typer.Option(None, "--args", "-a", help="Argumentos de línea de comando."),
    json_output: bool = typer.Option(False, "--json", help="Emitir metadatos del script reproductor en JSON."),
) -> None:
    """Genera un script autónomo en Bash para reproducir exactamente el crash en cualquier máquina."""
    is_c = objetivo.suffix == ".c"
    try:
        script = script_reproductor(objetivo, stdin, args)
    except ValueError as error:
        raise typer.BadParameter(f"--args mal formado: {error}.", param_hint="--args") from None

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(script, encoding="utf-8")
    output.chmod(0o755)

    if json_output:
        res = {
            "ok": True,
            "script_path": str(output),
            "objetivo": objetivo.name,
            "es_fuente_c": is_c,
            "tamano_bytes": len(script.encode("utf-8")),
        }
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return

    console.print(f"[bold green]✓ Script de reproducción generado exitosamente en:[/bold green] [cyan]{output}[/cyan]")


@app.command("replay")
def replay_cmd(
    objetivo: Path = typer.Argument(..., callback=_existente, help="Archivo .c o binario a re-ejecutar en modo diagnóstico."),
    stdin: Optional[str] = typer.Option(None, "--stdin", "-i", help="Datos de entrada estándar."),
    json_output: bool = typer.Option(False, "--json", help="Emitir resultado del replay en formato JSON."),
) -> None:
    """Ejecuta y navega paso a paso la traza forense del crash con renderizado Rich."""
    diag = inspeccionar_fuente_o_binario(
        ruta_objetivo=objetivo,
        args=[],
        stdin_data=stdin or "",
    )
    if json_output:
        print(json.dumps(diag.to_dict(), indent=2, ensure_ascii=False))
        raise typer.Exit(code=_codigo_salida(diag))

    console.print(f"[bold cyan]🎬 Replay forense interactivo de HAL sobre:[/bold cyan] [yellow]{objetivo.name}[/yellow]...")
    _renderizar_diagnostico_rich(diag)
    raise typer.Exit(code=_codigo_salida(diag))


@app.command("registers")
def registers_cmd(
    objetivo: Path = typer.Argument(..., callback=_existente, help="Archivo .c o binario a inspeccionar."),
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
    fuente: Path = typer.Argument(..., exists=True, help="Archivo fuente C a auditar."),
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
    binario: Path = typer.Argument(..., callback=_existente, help="Binario a inspeccionar."),
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
    binario: Path = typer.Argument(..., callback=_existente, help="Binario ejecutable con símbolos."),
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
    log_file: Optional[Path] = typer.Argument(None, exists=True, help="Archivo de log de Valgrind o leer desde stdin."),
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


@app.command("schema")
def schema_cmd() -> None:
    """Imprime el JSON Schema de la salida `--json` de check (crash v1)."""
    from importlib.resources import files
    print((files("hal") / "esquemas" / "crash-v1.schema.json").read_text(encoding="utf-8"))


@app.command("advice")
def advice_cmd(
    json_output: bool = typer.Option(False, "--json", help="Emitir consejos pedagógicos en formato JSON."),
) -> None:
    """Muestra consejos pedagógicos y buenas prácticas defensivas para evitar segfaults."""
    consejos = obtener_consejos()
    if json_output:
        print(json.dumps(consejos, indent=2, ensure_ascii=False))
        raise typer.Exit(code=0)

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
