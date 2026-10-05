"""Cómo se muestra un diagnóstico de HAL: en la terminal (Rich) y como sección Markdown para dredd.

Salió de `cli.py` (746 líneas, revisión 07); `cli.py` lo reexporta.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from hal.core.advice import obtener_consejos
from hal.core.models import DiagnosticoCrash

console = Console()
err_console = Console(stderr=True)


def _codigo_salida(diag: DiagnosticoCrash) -> int:
    """1 si hubo un crash o HAL no pudo diagnosticar (p. ej., el .c no compila); 0 si la ejecución fue limpia.

    Antes un diagnóstico de error («Fallo de Compilación con GCC») salía con 0, como una ejecución
    exitosa, y un script o un CI no podía distinguirlos (N-ECO-18).
    """
    return 1 if diag.es_crash or diag.tipo_senal == "ERROR" else 0


def _renderizar_diagnostico_rich(
    diag: DiagnosticoCrash,
    ruta_fuente: Optional[Path] = None,
    mostrar_consejos: bool = False,
    mostrar_todos_frames: bool = False,
) -> None:
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
    elif diag.archivo_falla and diag.pista:
        header += f"\n📍 [bold]Ubicación:[/bold] [yellow]{diag.archivo_falla}[/yellow], en la función [cyan]{diag.funcion_falla or 'main'}()[/cyan]"

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

    # Volcado de argumentos del frame superior / culpable
    frame_culpable = None
    for f in diag.frames:
        if f.archivo and not (f.archivo.startswith("/usr/") or f.archivo.startswith("/lib") or f.archivo.startswith("??")):
            frame_culpable = f
            break
    if not frame_culpable and diag.frames:
        frame_culpable = diag.frames[0]

    if frame_culpable and frame_culpable.argumentos:
        tabla_args = Table(title=f"📥 Volcado de Argumentos — Frame #{frame_culpable.nivel} (`{frame_culpable.funcion}`)")
        tabla_args.add_column("Parámetro", style="bold cyan")
        tabla_args.add_column("Valor Recibido", style="bold yellow")
        for arg, val in frame_culpable.argumentos.items():
            tabla_args.add_row(arg, val)
        console.print(tabla_args)

    # Call Stack / Backtrace Table con rutas limpias
    if diag.frames:
        frames_mostrar = [
            f for f in diag.frames
            if mostrar_todos_frames or not (f.archivo and (f.archivo.startswith("/usr/") or f.archivo.startswith("/lib") or f.archivo.startswith("??")))
        ]
        if not frames_mostrar:
            frames_mostrar = diag.frames

        tabla_bt = Table(title="🥞 Pila de Llamadas (Call Stack — Rutas limpias)")
        tabla_bt.add_column("#", justify="right", style="bold")
        tabla_bt.add_column("Función", style="cyan")
        tabla_bt.add_column("Argumentos", style="dim")
        tabla_bt.add_column("Ubicación", style="yellow")
        tabla_bt.add_column("Variables Locales", style="green")

        for f in frames_mostrar:
            ubicacion = f"{Path(f.archivo).name}:{f.linea}" if f.archivo and f.linea else (f.archivo or "—")
            args_str = ", ".join(f"{k}={v}" for k, v in f.argumentos.items()) if f.argumentos else "—"
            locals_str = ", ".join(f"{k}={v}" for k, v in f.variables_locales.items()) if f.variables_locales else "—"
            tabla_bt.add_row(str(f.nivel), f.funcion, args_str, ubicacion, locals_str)

        console.print(tabla_bt)

    # Volcado de Struct en Memoria (Mejora 22)
    if diag.campos_struct:
        tabla_struct = Table(title=f"📦 Volcado de Memoria del Struct '{diag.struct_nombre or 'objeto'}' en el Crash")
        tabla_struct.add_column("Campo", style="bold cyan")
        tabla_struct.add_column("Tipo", style="yellow")
        tabla_struct.add_column("Valor en Memoria", style="green")
        for campo, info in diag.campos_struct.items():
            if isinstance(info, dict):
                tipo_str = info.get("tipo", "campo")
                val_str = str(info.get("valor", "—"))
            else:
                val_str = str(info)
                tipo_str = "hex" if val_str.startswith("0x") else ("str" if val_str.startswith('"') else "valor")
            tabla_struct.add_row(campo, tipo_str, val_str)
        console.print(tabla_struct)

    # Alerta de inyección de Vasquez si fue detectada
    if diag.vasquez_inyeccion_detectada:
        console.print(Panel(
            f"[bold magenta]🧪 AUDITORÍA DE RESILIENCIA CON VASQUEZ ACTIVA[/bold magenta]\n\n"
            f"Se inyectó un fallo deliberado en tiempo de ejecución para auditar la tolerancia a errores de tu código.\n"
            f"[dim]Detalle:[/dim] [yellow]{diag.vasquez_inyeccion_detectada.get('detalle', 'Inyección LD_PRELOAD')}[/yellow]",
            title="💉 Inyección de Fallos (Vasquez)",
            border_style="magenta",
        ))

    # Acción Correctiva
    if diag.accion_correctiva:
        console.print(Panel(
            f"[bold green]💡 ¿Cómo solucionarlo?[/bold green]\n\n{diag.accion_correctiva}",
            title="🛠️ Acción Correctiva Sugerida",
            border_style="green",
        ))
    if diag.pista:
        console.print("[dim]Modo pista: buscá la falla en la función indicada; la línea, los valores y la corrección "
                      "no se muestran.[/dim]")

    if mostrar_consejos:
        console.print("\n[bold cyan]🎓 Consejos Didácticos de Programación Defensiva:[/bold cyan]")
        for c in obtener_consejos()[:2]:
            console.print(Panel(f"[bold]{c['regla']}[/bold]\n\n{c['explicacion']}\n\n[green]{c['ejemplo_correcto']}[/green]", title=c['tema'], border_style="cyan"))


def generar_seccion_markdown(diag: DiagnosticoCrash) -> str:
    """Genera sección de análisis forense y crash para Dredd."""
    status = "fail" if _codigo_salida(diag) else "ok"
    lines = [
        f"<!-- dredd-section: hal, tool=hal, version=1.0.0, status={status} -->\n",
        "## Diagnóstico Forense de Crash y Señales (Hal)\n",
    ]
    if diag.tipo_senal == "ERROR":  # no se pudo ejecutar (p. ej., el .c no compila): no es una ejecución exitosa
        lines.append(f"- **Estado:** ✗ {diag.causa_raiz_titulo}: {diag.explicacion}\n")
        return "\n".join(lines)
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
        if diag.vasquez_inyeccion_detectada:
            lines.append(f"> [!WARNING]\n> **Inyección Activa de Fallos (Vasquez):** {diag.vasquez_inyeccion_detectada.get('detalle', 'Inyección LD_PRELOAD')}\n")
        if diag.accion_correctiva:
            lines.append(f"**Sugerencia de corrección:** {diag.accion_correctiva}\n")
        if diag.campos_struct:
            lines.append(f"### Inspección de Estructura (`{diag.struct_nombre or 'struct'}`)")
            lines.append("| Campo | Tipo | Valor |")
            lines.append("| :--- | :--- | :--- |")
            for campo, info in diag.campos_struct.items():
                if isinstance(info, dict):
                    t_str = info.get("tipo", "campo")
                    v_str = str(info.get("valor", "—"))
                else:
                    v_str = str(info)
                    t_str = "campo"
                c_limpio = str(campo).replace("|", "&#124;")
                t_limpio = str(t_str).replace("|", "&#124;")
                v_limpio = str(v_str).replace("|", "&#124;")
                lines.append(f"| `{c_limpio}` | {t_limpio} | `{v_limpio}` |")
            lines.append("")
        if diag.frames:
            lines.append("### Pila de Ejecución (Stack Frames)")
            lines.append("| Frame # | Función | Ubicación |")
            lines.append("| :---: | :--- | :--- |")
            for f in diag.frames:
                loc = f"`{Path(f.archivo).name}:{f.linea}`" if f.archivo and f.linea else (f.archivo or "—")
                fn_limpio = str(f.funcion).replace("|", "&#124;")
                loc_limpio = str(loc).replace("|", "&#124;")
                lines.append(f"| {f.nivel} | `{fn_limpio}()` | {loc_limpio} |")
            lines.append("")
    return "\n".join(lines)
