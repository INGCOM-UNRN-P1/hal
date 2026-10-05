"""CLI de HAL — Asistente forense de core dumps y análisis post-mortem de segfaults."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import typer
from yutani.cli import crear_app
from rich.console import Console
from rich.table import Table

from hal import __version__
from hal.core.doctor import ejecutar_diagnostico_doctor, obtener_estado_doctor
from hal.core.exporter import exportar_discussion_markdown, exportar_html
from hal.core.inspector import inspeccionar_fuente_o_binario, resolver_binario
from hal.core.pista import diagnostico_en_pista, pista_activa
# La presentación (Rich y Markdown) está en presentacion.py; se reexporta para quien la importaba de acá.
from hal.presentacion import _codigo_salida, _renderizar_diagnostico_rich, generar_seccion_markdown  # noqa: F401

console = Console()


def _existente(valor: Optional[Path]) -> Optional[Path]:
    """Como exists=True, pero en Windows acepta `prog` cuando existe `prog.exe` (N-ECO-10)."""
    if valor is None:
        return valor
    valor = resolver_binario(valor)
    if not valor.exists():
        raise typer.BadParameter(f"No existe '{valor}'.")
    return valor
err_console = Console(stderr=True)

# Contrato de línea de comandos del ecosistema (-h/--help, --version/-v, errores de datos como
# mensajes) y textos de Typer en español, desde yutani (N-ECO-14).
app: typer.Typer = crear_app(
    "hal",
    __version__,
    "🤖 HAL — Asistente forense de core dumps y análisis pedagógico post-mortem de segfaults en C.",
    add_completion=True,
)




@app.command("run")
@app.command("check")
def run_cmd(
    objetivo: Path = typer.Argument(..., callback=_existente, help="Ruta al archivo C (.c) o binario a ejecutar y diagnosticar."),
    args: Optional[List[str]] = typer.Argument(None, help="Argumentos a pasar al programa."),
    stdin: Optional[str] = typer.Option(None, "--stdin", "-i", help="Cadena de texto para enviar a la entrada estándar (stdin)."),
    json_output: bool = typer.Option(False, "--json", help="Emitir diagnóstico estructurado en formato JSON."),
    gdb_path: Optional[str] = typer.Option(None, "--gdb", help="Ruta al binario de GDB."),
    output_md: Optional[Path] = typer.Option(None, "--md", "--output-md", "-o", help="Generar sección de reporte en formato Markdown para fusión en Dredd."),
    advice: bool = typer.Option(False, "--advice", help="Mostrar consejos pedagógicos adicionales."),
    struct_var: Optional[str] = typer.Option(None, "--struct", "-s", help="Nombre de la variable struct o puntero a struct a inspeccionar en memoria."),
    inject_vasquez: bool = typer.Option(False, "--inject-vasquez", help="Activar inyección de fallos con Vasquez vía LD_PRELOAD."),
    fail_malloc_at: Optional[int] = typer.Option(None, "--fail-malloc-at", help="Inyectar fallo (NULL) en la N-ésima llamada a malloc."),
    fail_realloc_at: Optional[int] = typer.Option(None, "--fail-realloc-at", help="Inyectar fallo (NULL) en la N-ésima llamada a realloc."),
    fail_calloc_at: Optional[int] = typer.Option(None, "--fail-calloc-at", help="Inyectar fallo (NULL) en la N-ésima llamada a calloc."),
    vasquez_cascade: bool = typer.Option(False, "--cascade", "--vasquez-cascade", help="Activar fallos en cascada tras el primer error."),
    vasquez_garbage: bool = typer.Option(False, "--garbage-memory", "--vasquez-garbage", help="Envenenar bloques asignados con bytes basura."),
    html_output: Optional[Path] = typer.Option(None, "--html", help="Ruta para exportar el reporte interactivo en HTML."),
    discussion_md: Optional[Path] = typer.Option(None, "--discussion-md", help="Ruta para exportar plantilla Markdown para GitHub Discussions."),
    all_frames: bool = typer.Option(False, "--all-frames", help="Mostrar marcos de pila de libc/sistema completos."),
    pista: bool = typer.Option(False, "--pista", help="Modo pista (o P1_PISTA=1): la falla y la función, sin la línea, los valores ni la corrección."),
    gdb_script: Optional[Path] = typer.Option(None, "--gdb-script", help="Escribir un script de gdb que se detiene donde ocurrió el crash, para seguir depurando."),
) -> None:
    """Compila (si es .c), ejecuta el programa y genera un diagnóstico forense pedagógico si ocurre un crash."""
    diag = inspeccionar_fuente_o_binario(
        ruta_objetivo=objetivo,
        args=args or [],
        stdin_data=stdin or "",
        gdb_path=gdb_path,
        struct_nombre=struct_var,
        inyectar_vasquez=inject_vasquez,
        vasquez_fail_malloc_at=fail_malloc_at,
        vasquez_fail_realloc_at=fail_realloc_at,
        vasquez_fail_calloc_at=fail_calloc_at,
        vasquez_cascade=vasquez_cascade,
        vasquez_garbage_memory=vasquez_garbage,
    )
    if pista_activa(pista):
        diag = diagnostico_en_pista(diag)

    if gdb_script:
        from hal.core.gdb_script import generar_script_gdb
        gdb_script.parent.mkdir(parents=True, exist_ok=True)
        gdb_script.write_text(generar_script_gdb(diag, objetivo, args or []), encoding="utf-8")
        err_console.print(f"[green]✓ Script de gdb en:[/green] [cyan]{gdb_script}[/cyan]")

    if html_output:
        html_code = exportar_html(diag)
        html_output.parent.mkdir(parents=True, exist_ok=True)
        html_output.write_text(html_code, encoding="utf-8")
        console.print(f"[green]✓ Reporte HTML interactivo generado en:[/green] [cyan]{html_output}[/cyan]")
        raise typer.Exit(code=_codigo_salida(diag))

    if discussion_md:
        disc_text = exportar_discussion_markdown(diag)
        discussion_md.parent.mkdir(parents=True, exist_ok=True)
        discussion_md.write_text(disc_text, encoding="utf-8")
        console.print(f"[green]✓ Plantilla para GitHub Discussions generada en:[/green] [cyan]{discussion_md}[/cyan]")
        raise typer.Exit(code=_codigo_salida(diag))

    if output_md:
        md_text = generar_seccion_markdown(diag)
        output_md.parent.mkdir(parents=True, exist_ok=True)
        output_md.write_text(md_text, encoding="utf-8")
        console.print(f"[green]✓ Sección Markdown generada en:[/green] [cyan]{output_md}[/cyan]")
        raise typer.Exit(code=_codigo_salida(diag))

    if json_output:
        print(json.dumps(diag.to_dict(), indent=2, ensure_ascii=False))
        raise typer.Exit(code=_codigo_salida(diag))

    _renderizar_diagnostico_rich(
        diag,
        ruta_fuente=objetivo if objetivo.suffix == ".c" else None,
        mostrar_consejos=advice,
        mostrar_todos_frames=all_frames,
    )
    raise typer.Exit(code=_codigo_salida(diag))


@app.command("report")
def report_cmd(
    objetivo: Path = typer.Argument(..., callback=_existente, help="Ruta al archivo C (.c) o binario a diagnosticar."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Ruta de destino del archivo Markdown."),
    stdin: Optional[str] = typer.Option(None, "--stdin", "-i", help="Entrada estándar."),
    html_output: Optional[Path] = typer.Option(None, "--html", help="Ruta para exportar el reporte interactivo en HTML."),
    discussion_md: Optional[Path] = typer.Option(None, "--discussion-md", help="Ruta para exportar plantilla Markdown para GitHub Discussions."),
    json_output: bool = typer.Option(False, "--json", help="Emitir diagnóstico en formato JSON."),
) -> None:
    """Genera directamente la sección de reporte Markdown de HAL para Dredd o exporta a HTML/Discussions."""
    diag = inspeccionar_fuente_o_binario(
        ruta_objetivo=objetivo,
        args=[],
        stdin_data=stdin or "",
    )

    if json_output:
        print(json.dumps(diag.to_dict(), indent=2, ensure_ascii=False))
        raise typer.Exit(code=_codigo_salida(diag))

    if html_output:
        html_code = exportar_html(diag)
        html_output.parent.mkdir(parents=True, exist_ok=True)
        html_output.write_text(html_code, encoding="utf-8")
        console.print(f"[green]✓ Reporte HTML generado en:[/green] [cyan]{html_output}[/cyan]")
        raise typer.Exit(code=_codigo_salida(diag))

    if discussion_md:
        disc_text = exportar_discussion_markdown(diag)
        discussion_md.parent.mkdir(parents=True, exist_ok=True)
        discussion_md.write_text(disc_text, encoding="utf-8")
        console.print(f"[green]✓ Plantilla Discussions generada en:[/green] [cyan]{discussion_md}[/cyan]")
        raise typer.Exit(code=_codigo_salida(diag))

    md_text = generar_seccion_markdown(diag)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(md_text, encoding="utf-8")
        console.print(f"[green]✓ Reporte Markdown exportado a:[/green] [cyan]{output}[/cyan]")
    else:
        print(md_text)
    raise typer.Exit(code=_codigo_salida(diag))


@app.command("inspect")
def inspect_cmd(
    binario: Path = typer.Argument(..., callback=_existente, help="Binario ejecutable a inspeccionar."),
    json_output: bool = typer.Option(False, "--json", help="Emitir diagnóstico en formato JSON."),
    gdb_path: Optional[str] = typer.Option(None, "--gdb", help="Ruta a GDB."),
    output_md: Optional[Path] = typer.Option(None, "--md", "--output-md", help="Generar sección de reporte en Markdown."),
    struct_var: Optional[str] = typer.Option(None, "--struct", "-s", help="Nombre de la variable struct o puntero a struct a inspeccionar."),
    inject_vasquez: bool = typer.Option(False, "--inject-vasquez", help="Activar inyección de fallos con Vasquez vía LD_PRELOAD."),
    fail_malloc_at: Optional[int] = typer.Option(None, "--fail-malloc-at", help="Inyectar fallo en la N-ésima llamada a malloc."),
    fail_realloc_at: Optional[int] = typer.Option(None, "--fail-realloc-at", help="Inyectar fallo en la N-ésima llamada a realloc."),
    fail_calloc_at: Optional[int] = typer.Option(None, "--fail-calloc-at", help="Inyectar fallo en la N-ésima llamada a calloc."),
    vasquez_cascade: bool = typer.Option(False, "--cascade", "--vasquez-cascade", help="Activar fallos en cascada."),
    vasquez_garbage: bool = typer.Option(False, "--garbage-memory", "--vasquez-garbage", help="Envenenar memoria asignada."),
) -> None:
    """Inspecciona un binario compilado ante posibles fallos de ejecución."""
    diag = inspeccionar_fuente_o_binario(
        ruta_objetivo=binario,
        gdb_path=gdb_path,
        struct_nombre=struct_var,
        inyectar_vasquez=inject_vasquez,
        vasquez_fail_malloc_at=fail_malloc_at,
        vasquez_fail_realloc_at=fail_realloc_at,
        vasquez_fail_calloc_at=fail_calloc_at,
        vasquez_cascade=vasquez_cascade,
        vasquez_garbage_memory=vasquez_garbage,
    )

    if output_md:
        md_text = generar_seccion_markdown(diag)
        output_md.parent.mkdir(parents=True, exist_ok=True)
        output_md.write_text(md_text, encoding="utf-8")
        console.print(f"[green]✓ Sección Markdown generada en:[/green] [cyan]{output_md}[/cyan]")
        raise typer.Exit(code=_codigo_salida(diag))

    if json_output:
        print(json.dumps(diag.to_dict(), indent=2, ensure_ascii=False))
        raise typer.Exit(code=_codigo_salida(diag))

    _renderizar_diagnostico_rich(diag)
    raise typer.Exit(code=_codigo_salida(diag))


@app.command("struct")
@app.command("inspect-struct")
def inspect_struct_cmd(
    objetivo: Path = typer.Argument(..., callback=_existente, help="Archivo .c o binario a ejecutar e inspeccionar."),
    struct_nombre: str = typer.Argument(..., help="Nombre de la variable struct o puntero a struct."),
    stdin: Optional[str] = typer.Option(None, "--stdin", "-i", help="Entrada estándar."),
    json_output: bool = typer.Option(False, "--json", help="Emitir salida en formato JSON."),
    gdb_path: Optional[str] = typer.Option(None, "--gdb", help="Ruta a GDB."),
) -> None:
    """Inspecciona y vuelca los campos de una estructura (struct) en memoria (Mejora 22)."""
    diag = inspeccionar_fuente_o_binario(
        ruta_objetivo=objetivo,
        stdin_data=stdin or "",
        gdb_path=gdb_path,
        struct_nombre=struct_nombre,
    )

    if json_output:
        print(json.dumps(diag.campos_struct or {}, indent=2, ensure_ascii=False))
        raise typer.Exit(code=0 if diag.campos_struct else 1)

    if not diag.campos_struct:
        console.print(f"[yellow]No se capturó volcado del struct '{struct_nombre}' (verificá que el símbolo exista en el frame).[/yellow]")
        raise typer.Exit(code=1)

    tabla_struct = Table(title=f"📦 Volcado de Memoria del Struct '{struct_nombre}'")
    tabla_struct.add_column("Campo", style="bold cyan")
    tabla_struct.add_column("Tipo", style="yellow")
    tabla_struct.add_column("Valor en Memoria", style="green")
    for campo, info in diag.campos_struct.items():
        if isinstance(info, dict):
            t = info.get("tipo", "campo")
            v = str(info.get("valor", "—"))
        else:
            v = str(info)
            t = "hex" if v.startswith("0x") else ("str" if v.startswith('"') else "valor")
        tabla_struct.add_row(campo, t, v)
    console.print(tabla_struct)
    raise typer.Exit(code=0)


@app.command("doctor")
def doctor_cmd(
    json_output: bool = typer.Option(False, "--json", help="Emitir diagnóstico del entorno en formato JSON."),
) -> None:
    """Verifica el estado del entorno (GCC, GDB, Valgrind, addr2line)."""
    if json_output:
        estado = obtener_estado_doctor()
        print(json.dumps(estado, indent=2, ensure_ascii=False))
        raise typer.Exit(code=0 if estado["ok"] else 1)

    ok = ejecutar_diagnostico_doctor(console=console)
    if not ok:
        raise typer.Exit(code=1)


# Los comandos secundarios están en cli_extra.py y la presentación en presentacion.py.
from hal import cli_extra  # noqa: E402,F401
from hal.cli_extra import script_reproductor  # noqa: E402,F401


def main() -> None:
    app()


if __name__ == "__main__":
    main()
