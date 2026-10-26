"""La traza paso a paso de bishop hasta el crash (Ola 10, QoL #453, #71).

hal dice dónde falló el programa; bishop muestra cómo se llegó ahí. Para un `.c` que se cae, el
diagnóstico trae el comando de `bishop trace --hasta-falla --html` (en la terminal, el Markdown, el JSON
y el script de gdb), que guarda los últimos pasos antes de la señal y abre la página en el paso exacto de
la falla. `hal run --traza-html RUTA` lo corre directamente. Con una recursión infinita el comando lleva
`--limite-pila 64`, así el Stack Overflow llega en unos miles de pasos.

En modo pista no se propone: la traza muestra la línea y los valores que la pista oculta.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

from hal.core.models import DiagnosticoCrash

LIMITE_PILA_RECURSION_KB = 64
ARCHIVO_ENTRADA = "entrada.txt"


def ruta_html(objetivo: Path) -> Path:
    return Path(objetivo.stem + ".falla.html")


def comando_bishop(diag: DiagnosticoCrash, objetivo: Path, args: Optional[List[str]] = None,
                   entrada: Optional[Path] = None, html: Optional[Path] = None) -> Optional[List[str]]:
    """Los argumentos de `bishop trace` que llevan al crash, o None si no aplica (no es un .c, no hubo
    crash, o es modo pista)."""
    if not diag.es_crash or diag.pista or objetivo.suffix != ".c":
        return None
    comando = ["bishop", "trace", str(objetivo), "--hasta-falla", "--html", str(html or ruta_html(objetivo))]
    if entrada is not None:
        comando += ["--input", str(entrada)]
    if diag.codigo_senal == "STACK_OVERFLOW":
        comando += ["--limite-pila", str(LIMITE_PILA_RECURSION_KB)]
    if args:
        comando += ["--", *args]
    return comando


def completar_visualizacion(diag: DiagnosticoCrash, objetivo: Path, args: Optional[List[str]] = None,
                            stdin_data: str = "") -> None:
    """Agrega al diagnóstico el comando para ver la falla paso a paso (sin ejecutarlo)."""
    comando = comando_bishop(diag, objetivo, args, Path(ARCHIVO_ENTRADA) if stdin_data else None)
    if comando is None:
        return
    diag.visualizacion = {"comando": shlex.join(comando), "html": None}
    if stdin_data:
        diag.visualizacion["nota"] = (f"Guardá en {ARCHIVO_ENTRADA} lo que le pasaste por la entrada estándar "
                                      f"(--stdin) antes de correrlo.")


def generar_traza_html(diag: DiagnosticoCrash, objetivo: Path, destino: Path, args: Optional[List[str]] = None,
                       stdin_data: str = "") -> Tuple[bool, str]:
    """Corre bishop y deja la página en `destino`: (ok, mensaje para el estudiante)."""
    if not shutil.which("bishop"):
        return False, ("bishop no está instalado: es la herramienta que arma la traza paso a paso "
                       "(se instala con mother, en el perfil del estudiante).")
    with tempfile.TemporaryDirectory(prefix="hal-traza-") as tmp:
        entrada = None
        if stdin_data:
            entrada = Path(tmp) / ARCHIVO_ENTRADA
            entrada.write_text(stdin_data, encoding="utf-8")
        comando = comando_bishop(diag, objetivo, args, entrada, destino)
        if comando is None:
            return False, "la traza paso a paso es para un .c que se cae (y no en modo pista)."
        destino.parent.mkdir(parents=True, exist_ok=True)
        try:
            res = subprocess.run([shutil.which("bishop") or "bishop", *comando[1:]], capture_output=True,
                                 text=True, timeout=240)
        except subprocess.TimeoutExpired:
            return False, "bishop tardó demasiado en trazar el programa."
    if res.returncode != 0 or not destino.is_file():
        return False, "bishop no pudo trazar el programa: " + (res.stderr or res.stdout).strip()[-500:]
    if diag.visualizacion is not None:
        diag.visualizacion["html"] = str(destino)
    return True, destino.resolve().as_uri()

