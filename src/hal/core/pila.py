"""Diagnóstico de la pila: recursión sin fin, marco demasiado grande o búfer local desbordado (Ola 10).

Tres fallas que el estudiante ve igual («se rompió la pila») y que se corrigen distinto (QoL #870, #474):

- **Recursión infinita**: miles de marcos de la misma función hasta agotar el límite de la pila. hal mide
  con gdb cuánto ocupa de verdad cada llamada, lo compara con el límite del sistema y le pregunta a
  sebastian si la función tiene caso base: sin caso base (`recursion-sin-caso-base`) no es lo mismo que
  con un caso base que los argumentos nunca alcanzan (`caso-base-inalcanzable`).
- **Marco demasiado grande**: una sola función (casi siempre `main`) con un arreglo local que no entra
  en la pila: no hay recursión, el marco solo ya supera el límite (`arreglo-local-demasiado-grande`).
- **Búfer local desbordado**: la pila no se llenó; se escribió más allá de un arreglo local y se pisó el
  resto del marco de activación (el canario de `-fstack-protector` o la dirección de retorno).

El script de gdb del inspector imprime `MARCOS=funcion:bytes,…` (los primeros marcos, de adentro hacia
afuera); el tamaño de cada uno es la distancia entre su `$sp` y el del marco que lo llamó (en el más
externo, hasta la dirección del marco que informa `info frame`).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from typing import List, Optional, Tuple

from hal.core.models import DiagnosticoCrash

PILA_WINDOWS = 1024 * 1024
PILA_POR_DEFECTO = 8 * 1024 * 1024

# Código de gdb (Python) que agrega el inspector después de `run`.
SCRIPT_MARCOS = """\
python
try:
    import re as _re
    _marco, _partes = gdb.newest_frame(), []
    while _marco is not None and len(_partes) < 40:
        _sp = int(_marco.read_register('sp'))
        _anterior = _marco.older()
        if _anterior is not None:
            _tam = int(_anterior.read_register('sp')) - _sp
        else:
            _marco.select()
            _m = _re.search(r'frame at (0x[0-9a-f]+)', gdb.execute('info frame', to_string=True))
            _tam = int(_m.group(1), 16) - _sp if _m else 0
        _partes.append('%s:%d' % (_marco.name() or '??', _tam))
        _marco = _anterior
    gdb.newest_frame().select()
    print('MARCOS=' + ','.join(_partes))
except Exception:
    pass
end
"""


def limite_de_pila() -> Tuple[int, str]:
    """(bytes, de dónde sale el dato): el programa hereda el límite de hal a través de gdb."""
    if os.name == "nt":
        return PILA_WINDOWS, "1 MiB, el tamaño de pila por defecto de un ejecutable en Windows"
    try:
        import resource

        blando, _ = resource.getrlimit(resource.RLIMIT_STACK)
        if blando not in (resource.RLIM_INFINITY, -1) and blando > 0:
            return int(blando), "el límite de pila del sistema, ulimit -s"
    except (ImportError, ValueError, OSError):
        pass
    return PILA_POR_DEFECTO, "8 MiB, el límite de pila habitual en Linux"


def parsear_marcos(salida_gdb: str) -> List[Tuple[str, int]]:
    m = re.search(r"^MARCOS=(.*)$", salida_gdb, re.MULTILINE)
    if not m:
        return []
    marcos = []
    for parte in m.group(1).split(","):
        funcion, _, tam = parte.rpartition(":")
        if funcion and tam.lstrip("-").isdigit():
            marcos.append((funcion, int(tam)))
    return marcos


def _miles(n: int) -> str:
    return f"{n:,}".replace(",", ".")


def _tamanio(bytes_: int) -> str:
    """En español: 8 MiB, 19,1 MiB, 512 bytes."""
    for unidad, divisor in (("MiB", 1048576), ("KiB", 1024)):
        if bytes_ >= divisor:
            return f"{bytes_ / divisor:.1f}".replace(".0", "").replace(".", ",") + " " + unidad
    return f"{bytes_} bytes"


def caso_base_segun_sebastian(fuente: Optional[Path], funcion: str) -> Optional[bool]:
    """Si `funcion` tiene caso base según el análisis estático de sebastian (como biblioteca, con el extra
    `ecosistema`, o su línea de comandos si está instalado); None si no se pudo saber."""
    if fuente is None or not fuente.is_file() or fuente.suffix != ".c":
        return None
    try:
        from sebastian.core.analyzer import analizar_estatico_funcion, extraer_funciones_c
    except ImportError:
        analizar_estatico_funcion = None  # type: ignore[assignment]
    if analizar_estatico_funcion is not None:
        contenido = fuente.read_text(encoding="utf-8", errors="replace")
        for nombre, cuerpo, linea, _ in extraer_funciones_c(contenido):
            if nombre == funcion:
                return analizar_estatico_funcion(nombre, cuerpo, fuente, linea).tiene_caso_base
        return None
    sebastian = shutil.which("sebastian")
    if not sebastian:
        return None
    try:
        res = subprocess.run([sebastian, "check", str(fuente), "--json"], capture_output=True, text=True, timeout=30)
        reportes = json.loads(res.stdout)
    except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
        return None
    for r in reportes if isinstance(reportes, list) else []:
        if isinstance(r, dict) and r.get("funcion") == funcion and r.get("es_recursiva"):
            return bool(r.get("tiene_caso_base"))
    return None


def _ultimos_argumentos(diag: DiagnosticoCrash, funcion: str) -> str:
    """`n = -8191, -8189, -8187`: el primer argumento en las últimas llamadas, de la más vieja a la última."""
    valores, nombre = [], None
    for f in diag.frames:
        if f.funcion != funcion or not f.argumentos:
            continue
        clave, valor = next(iter(f.argumentos.items()))
        nombre = nombre or clave
        if clave == nombre and not valor.startswith("<"):  # «<error reading variable…>» en el último marco
            valores.append(valor)
        if len(valores) == 4:
            break
    return f"{nombre} = {', '.join(reversed(valores))}" if nombre and len(valores) >= 2 else ""


def _recursion(diag: DiagnosticoCrash, marcos: List[Tuple[str, int]], profundidad: Optional[int],
               limite: int, origen: str, fuente: Optional[Path]) -> None:
    funcion = Counter(f for f, _ in marcos).most_common(1)[0][0] if marcos else (diag.funcion_falla or "")
    tamanios = sorted(t for f, t in marcos if f == funcion and t > 0)
    marco = tamanios[len(tamanios) // 2] if tamanios else 0
    maximo = limite // marco if marco else 0
    caso_base = caso_base_segun_sebastian(fuente, funcion)
    cantidad = (f"más de {_miles(profundidad or 0)}" if (profundidad or 0) >= 5000
                else _miles(profundidad or len(diag.frames)))
    cuenta = (f"Cada llamada a '{funcion}' ocupa {marco} bytes de pila (su marco de activación: parámetros, "
              f"variables locales y la dirección de retorno) y la pila tiene {_tamanio(limite)} ({origen}): "
              f"entran unas {_miles(maximo)} llamadas anidadas, y había {cantidad} sin terminar."
              if marco else f"Había {cantidad} llamadas a '{funcion}' anidadas sin terminar.")
    argumentos = _ultimos_argumentos(diag, funcion)
    if caso_base is False:
        diag.causa_raiz_titulo = f"Recursión infinita: '{funcion}' no tiene caso base"
        diag.explicacion = (
            f"La función '{funcion}' se llama a sí misma siempre: no tiene un caso base (un `if` que "
            f"devuelva un resultado sin volver a llamarse), así que las llamadas nunca terminan y cada una "
            f"deja su marco en la pila hasta agotarla (Stack Overflow).\n{cuenta}")
        diag.accion_correctiva = (
            f"1. Escribí el caso base de '{funcion}': la condición en la que el problema es tan chico que la "
            f"respuesta se conoce sin recursión (por ejemplo, `if (n == 0) return 0;`), antes de la llamada "
            f"recursiva.\n2. Verificá que cada llamada recursiva achique el problema hacia ese caso.")
    elif caso_base is True:
        diag.causa_raiz_titulo = f"Recursión infinita: '{funcion}' nunca llega a su caso base"
        diag.explicacion = (
            f"La función '{funcion}' tiene caso base, pero los argumentos de las llamadas recursivas no lo "
            f"alcanzan (lo saltean, o se alejan de él), así que la recursión no termina y la pila se agota "
            f"(Stack Overflow).\n{cuenta}"
            + (f"\nEn las últimas llamadas: {argumentos}." if argumentos else ""))
        diag.accion_correctiva = (
            f"1. Mirá cómo cambian los argumentos de una llamada a la siguiente y si pueden saltear la "
            f"condición del caso base (por ejemplo, restar de a 2 con `n == 0` como caso base y un `n` "
            f"impar).\n2. Usá una condición que no se pueda saltear (`n <= 0` en vez de `n == 0`).\n"
            f"3. Si los argumentos sí se acercan pero son demasiados pasos para la pila, la recursión es "
            f"correcta pero demasiado profunda: reescribila con un ciclo.")
    else:
        diag.explicacion = diag.explicacion.rstrip() + "\n" + cuenta
    diag.codigo_senal = "STACK_OVERFLOW"
    diag.funcion_falla = diag.funcion_falla or funcion
    causa = ("recursion-infinita" if caso_base is None
             else "caso-base-inalcanzable" if caso_base else "recursion-sin-caso-base")
    diag.pila = {"causa": causa,
                 "funcion": funcion, "marco_bytes": marco, "limite_bytes": limite,
                 "profundidad": profundidad, "profundidad_maxima_estimada": maximo, "caso_base": caso_base}


def _marco_gigante(diag: DiagnosticoCrash, funcion: str, tam: int, limite: int, origen: str) -> None:
    diag.codigo_senal = "STACK_FRAME_TOO_LARGE"
    diag.causa_raiz_titulo = f"Arreglo local demasiado grande para la pila (en '{funcion}')"
    diag.explicacion = (
        f"Las variables locales de '{funcion}' ocupan {_tamanio(tam)}, y la pila de todo el programa tiene "
        f"{_tamanio(limite)} ({origen}). No es una recursión: el marco de activación de una sola llamada no "
        f"entra, así que el programa se cae al usar el arreglo local, aunque el índice sea válido.")
    diag.accion_correctiva = (
        "1. Reservá el arreglo grande en memoria dinámica (`int *datos = malloc(n * sizeof(int));`, "
        "verificando que no devuelva NULL y liberándolo con `free`).\n"
        "2. O declaralo `static` o global, si su tamaño es fijo: así no vive en la pila.")
    diag.funcion_falla = diag.funcion_falla or funcion
    diag.pila = {"causa": "arreglo-local-demasiado-grande", "funcion": funcion, "marco_bytes": tam,
                 "limite_bytes": limite}


def _bufer_local(diag: DiagnosticoCrash, canario: bool) -> None:
    funcion = diag.funcion_falla or "la función"
    como = ("gcc puso un valor testigo (el «canario» de -fstack-protector) entre las variables locales y la "
            "dirección de retorno, y al salir de la función lo encontró cambiado, así que abortó el programa"
            if canario else
            "al terminar la función, el procesador saltó a la dirección de retorno pisada y el programa se cayó")
    diag.causa_raiz_titulo = f"Desborde de un arreglo local sobre el marco de activación de '{funcion}'"
    diag.explicacion = (
        f"No se llenó la pila: se escribió más allá del final de un arreglo local de '{funcion}' y se pisó el "
        f"resto de su marco de activación (otras variables y la dirección a la que la función vuelve). "
        f"La falla aparece recién al retornar: {como}.")
    diag.accion_correctiva = (
        "1. Buscá en esa función las escrituras en arreglos locales: copias de cadenas (`strcpy`, `strcat`, "
        "`sprintf`, `gets`, `scanf(\"%s\")`) y ciclos que llegan hasta el tamaño del arreglo (`i <= N`).\n"
        "2. Usá las versiones con límite (`fgets`, `snprintf`, `strncpy` con el terminador, `%9s` en "
        "`scanf`) y recordá el lugar del `'\\0'` al dimensionar una cadena.")
    diag.es_buffer_overflow_ret = True
    diag.pila = {"causa": "desborde-de-buffer-local", "funcion": diag.funcion_falla, "canario": canario}


def diagnosticar_pila(diag: DiagnosticoCrash, salida_gdb: str, fuente: Optional[Path] = None,
                      profundidad: Optional[int] = None) -> DiagnosticoCrash:
    """Reescribe el diagnóstico cuando la falla es de la pila (ver el docstring del módulo)."""
    if not diag.es_crash:
        return diag
    if profundidad is None:
        m = re.search(r"PROFUNDIDAD=(\d+)", salida_gdb)
        profundidad = int(m.group(1)) if m else None
    texto = salida_gdb.lower()
    canario = "stack smashing detected" in texto or any(f.funcion == "__stack_chk_fail" for f in diag.frames)
    if canario or diag.codigo_senal == "RET_ADDR_CORRUPTED":
        _bufer_local(diag, canario)
        return diag
    marcos = parsear_marcos(salida_gdb)
    limite, origen = limite_de_pila()
    if diag.codigo_senal == "STACK_OVERFLOW":
        _recursion(diag, marcos, profundidad, limite, origen, fuente)
        return diag
    if "SEGV" in diag.tipo_senal and marcos:
        funcion, tam = max(marcos, key=lambda m: m[1])
        if tam >= limite * 0.5 and sum(t for _, t in marcos if t > 0) >= limite * 0.9:
            _marco_gigante(diag, funcion, tam, limite, origen)
    return diag

