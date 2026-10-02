"""Script de gdb para seguir depurando desde el crash (QoL #453).

El diagnóstico dice dónde falló; el script deja al estudiante parado ahí dentro de gdb, con los
comandos que conviene mirar, como puente hacia la depuración interactiva (y hacia bishop).
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from hal.core.models import DiagnosticoCrash


def generar_script_gdb(diag: DiagnosticoCrash, objetivo: Path, args: Optional[List[str]] = None) -> str:
    binario = objetivo.with_suffix("") if objetivo.suffix == ".c" else objetivo
    lineas = [
        "# Script de gdb generado por hal para seguir depurando el crash.",
    ]
    if objetivo.suffix == ".c":
        lineas.append(f"# Compilá con símbolos y abrilo así: gcc -g -O0 {objetivo.name} -o {binario.name} && "
                      f"gdb -x {binario.name}.gdb ./{binario.name}")
    else:
        lineas.append(f"# Abrilo así: gdb -x {binario.name}.gdb ./{binario.name}")
    lineas += [f"# Diagnóstico: {diag.causa_raiz_titulo}", "", "set pagination off"]

    archivo = Path(diag.archivo_falla).name if diag.archivo_falla else None
    if diag.codigo_senal == "STACK_OVERFLOW" and diag.funcion_falla:
        lineas += [
            f"# La recursión no termina: se detiene en las primeras llamadas a {diag.funcion_falla}() para ver",
            "# si los argumentos se acercan al caso base (con `continue` pasás a la siguiente).",
            f"break {diag.funcion_falla}",
        ]
    elif archivo and diag.linea_falla:
        lineas += [f"# Se detiene en la línea donde ocurrió el crash, antes de ejecutarla.",
                   f"break {archivo}:{diag.linea_falla}"]
    elif diag.funcion_falla:
        lineas.append(f"break {diag.funcion_falla}")

    argumentos = " ".join(f'"{a}"' for a in (args or []))
    lineas += [
        f"run {argumentos}".rstrip(),
        "",
        "# Mirá el estado en ese punto:",
        "info args",
        "info locals",
        "backtrace",
    ]
    if diag.variable_culpable:
        lineas += [f"print {diag.variable_culpable}"]
    lineas += ["", "# Para seguir: `next` (siguiente línea), `step` (entrar a la función), `continue`.", ""]
    return "\n".join(lineas)
