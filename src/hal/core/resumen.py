"""Síntesis pedagógica del crash, sin jerga del sistema operativo (`hal explain --resumen`, Ola 10, QoL #472).

El diagnóstico completo habla de señales, `SEGV_MAPERR`, direcciones y registros: es lo que un docente
necesita, pero a un estudiante de P1 le tapa la causa. El resumen dice, en cuatro renglones, dónde se cortó
el programa (archivo, línea, función y la línea de código), qué pasó en términos del código C, qué hacer y
qué página del apunte repasar (el enlace de la categoría, de yutani.hallazgos).

Los textos salen del código del hallazgo (`taxonomia.clasificar`), no de la explicación técnica; en modo
pista se omiten la línea, la variable y qué hacer.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Callable, Dict, Optional

from yutani.hallazgos import enlace_apunte

from hal.core.models import DiagnosticoCrash
from hal.core.taxonomia import clasificar

# Palabras que el resumen no usa (los tests lo verifican sobre cada código).
JERGA = ("señal", "sigsegv", "sigabrt", "sigfpe", "sigbus", "segmentation", "segv", "core", "dump", "kernel",
         "sistema operativo", "registro", "$rip", "0x", "stack overflow", "violación de segmento")


def _de(var: Optional[str], sin: str = "un puntero") -> str:
    return f"el puntero '{var}'" if var else sin


# código → (qué pasó, qué hacer); cada uno recibe el diagnóstico.
_TEXTOS: Dict[str, tuple[Callable[[DiagnosticoCrash], str], Callable[[DiagnosticoCrash], str]]] = {
    "acceso-invalido": (
        lambda d: (f"Se usó {_de(d.variable_culpable)} que vale NULL: no apunta a ningún dato, así que no se puede "
                   f"leer ni escribir a través de él." if _es_nulo(d) else
                   f"Se leyó o escribió a través de {_de(d.variable_culpable)} que apunta fuera de la memoria del "
                   f"programa (un índice fuera del arreglo o un puntero mal calculado)."),
        lambda d: ("Antes de usarlo, verificá que no sea NULL (por ejemplo, lo que devuelve malloc o fopen) y "
                   "decidí qué hacer si lo es." if _es_nulo(d) else
                   "Revisá los índices y los límites de los ciclos: un arreglo de N elementos va de 0 a N - 1."),
    ),
    "puntero-sin-inicializar": (
        lambda d: f"Se usó {_de(d.variable_culpable)} sin inicializar: contiene un valor cualquiera, no una dirección válida.",
        lambda d: "Inicializá cada puntero al declararlo: con la dirección de una variable, con malloc o con NULL.",
    ),
    "acceso-sin-permiso": (
        lambda d: "Se intentó escribir en memoria de solo lectura, como una cadena literal (char *s = \"hola\").",
        lambda d: "Si vas a modificar la cadena, guardala en un arreglo: char s[] = \"hola\";",
    ),
    "puntero-a-local": (
        lambda d: "Se usó la dirección de una variable local de una función que ya terminó: esa variable ya no existe.",
        lambda d: "No devuelvas la dirección de una variable local: devolvé el valor, o reservá la memoria con malloc.",
    ),
    "recursion-sin-caso-base": (
        lambda d: f"La función '{_funcion(d)}' se llama a sí misma sin parar: no tiene un caso base, y cada llamada "
                  f"ocupa un lugar en la pila hasta que no entra ninguna más.",
        lambda d: f"Escribí el caso base de '{_funcion(d)}' (el if que devuelve un resultado sin volver a llamarse) "
                  f"antes de la llamada recursiva.",
    ),
    "caso-base-inalcanzable": (
        lambda d: f"La función '{_funcion(d)}' tiene caso base, pero sus argumentos nunca lo alcanzan, así que se "
                  f"llama a sí misma sin parar hasta llenar la pila.",
        lambda d: "Seguí cómo cambian los argumentos en cada llamada y usá una condición que no se pueda saltear "
                  "(n <= 0 en vez de n == 0).",
    ),
    "arreglo-local-demasiado-grande": (
        lambda d: f"Un arreglo local de '{_funcion(d)}' es más grande que toda la pila del programa: no entra.",
        lambda d: "Reservalo con malloc (y liberalo con free), o declaralo static si su tamaño es fijo.",
    ),
    "desborde-de-buffer": (
        lambda d: f"Se escribió más allá del final de un arreglo local de '{_funcion(d)}' y se pisaron los datos "
                  f"que la función necesita para volver.",
        lambda d: "Buscá copias de cadenas sin límite (strcpy, gets, scanf con %s) y ciclos que llegan hasta el "
                  "tamaño del arreglo; usá fgets, snprintf o un ancho en scanf (%9s).",
    ),
    "uso-despues-de-free": (
        lambda d: f"Se usó memoria que ya se había liberado con free{_a_traves(d)}.",
        lambda d: "Después de free, poné el puntero en NULL y no lo uses más; liberá recién cuando terminaste.",
    ),
    "free-invalido": (
        lambda d: "Se llamó a free con algo que no vino de malloc (una variable local, un puntero movido) o dos veces.",
        lambda d: "Llamá a free una sola vez por cada malloc, con el mismo puntero que devolvió malloc.",
    ),
    "sin-memoria": (
        lambda d: "Se pidió más memoria de la que hay (casi siempre un tamaño negativo o enorme en malloc).",
        lambda d: "Revisá la cuenta del tamaño que le pasás a malloc y verificá que no devuelva NULL.",
    ),
    "assert-fallido": (
        lambda d: f"No se cumplió un assert{f': {d.expresion_assert}' if d.expresion_assert else ''}.",
        lambda d: "La condición del assert es lo que el código suponía: buscá por qué no vale en este caso.",
    ),
    "division-por-cero": (
        lambda d: "Se dividió un entero por cero (con / o con %).",
        lambda d: "Antes de dividir, verificá que el divisor no sea cero.",
    ),
    "abort": (
        lambda d: "El programa se cortó a sí mismo porque detectó un error grave (abort).",
        lambda d: "Mirá el mensaje que imprimió justo antes de cortarse y la función donde ocurrió.",
    ),
    "acceso-desalineado": (
        lambda d: "Se accedió a un dato a través de un puntero convertido a otro tipo que no le corresponde.",
        lambda d: "Evitá convertir punteros entre tipos distintos; copiá los bytes con memcpy si hace falta.",
    ),
    "sin-terminar": (
        lambda d: "El programa no terminó en el tiempo permitido: probablemente un ciclo que no termina o que "
                  "espera una entrada que no llega.",
        lambda d: "Revisá que la condición de cada ciclo cambie en algún momento y lo que el programa lee.",
    ),
}


def _es_nulo(d: DiagnosticoCrash) -> bool:
    if "nul" in d.causa_raiz_titulo.lower():
        return True
    try:
        return d.direccion_memoria is not None and int(d.direccion_memoria, 16) < 0x1000
    except ValueError:
        return False


def _funcion(d: DiagnosticoCrash) -> str:
    return (d.pila or {}).get("funcion") or d.funcion_falla or "main"


def _a_traves(d: DiagnosticoCrash) -> str:
    return f" (a través de '{d.variable_culpable}')" if d.variable_culpable else ""


def _linea_de_codigo(d: DiagnosticoCrash) -> Optional[str]:
    if not (d.archivo_falla and d.linea_falla):
        return None
    try:
        lineas = Path(d.archivo_falla).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    return lineas[d.linea_falla - 1].strip() if 0 < d.linea_falla <= len(lineas) else None


def resumir(diag: DiagnosticoCrash) -> Dict[str, Optional[str]]:
    """{donde, codigo, que_paso, que_hacer, para_repasar}; sin crash, sólo `que_paso`."""
    if diag.tipo_senal == "ERROR":
        return {"donde": None, "codigo": None, "que_paso": f"No se pudo ejecutar: {diag.causa_raiz_titulo}.",
                "que_hacer": "Si no compila, corregí primero los errores de compilación (daedalus los explica).",
                "para_repasar": None}
    if not diag.es_crash and diag.codigo_senal != "SIN_TERMINAR":
        return {"donde": None, "codigo": None, "que_paso": "El programa terminó sin cortarse.", "que_hacer": None,
                "para_repasar": None}
    codigo, categoria = clasificar(diag)
    que_paso, que_hacer = _TEXTOS.get(codigo, (
        lambda d: "El programa se cortó por un error al ejecutarse.",
        lambda d: "Mirá la línea indicada y los valores de las variables en ese punto (bishop trace --html).",
    ))
    pista = diag.pista
    donde = None
    if diag.archivo_falla:
        lugar = Path(diag.archivo_falla).name + (f":{diag.linea_falla}" if diag.linea_falla and not pista else "")
        donde = f"{lugar}, en la función {diag.funcion_falla or 'main'}()"
    sin_variable = diag if not pista else replace(diag, variable_culpable=None)
    return {
        "donde": donde,
        "codigo": None if pista else _linea_de_codigo(diag),
        "que_paso": que_paso(sin_variable),
        "que_hacer": None if pista else que_hacer(diag),
        "para_repasar": enlace_apunte(categoria),
    }


def texto_resumen(resumen: Dict[str, Optional[str]]) -> str:
    lineas = []
    if resumen["donde"]:
        lineas.append(f"Se cortó en {resumen['donde']}:" if resumen["codigo"] else f"Se cortó en {resumen['donde']}.")
        if resumen["codigo"]:
            lineas.append(f"    {resumen['codigo']}")
    lineas.append(f"Qué pasó: {resumen['que_paso']}" if resumen["donde"] else str(resumen["que_paso"]))
    if resumen["que_hacer"]:
        lineas.append(f"Qué hacer: {resumen['que_hacer']}")
    if resumen["para_repasar"]:
        lineas.append(f"Para repasar: {resumen['para_repasar']}")
    return "\n".join(lineas)
