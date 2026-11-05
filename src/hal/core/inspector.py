"""Motor de ejecución, captura de crashes e inspección GDB en HAL."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from hal.core.explainer import diagnosticar_crash, diagnosticar_puntero_a_local, diagnosticar_sin_terminar
from hal.core.models import DiagnosticoCrash, StackFrame
from hal.core.pila import diagnosticar_pila

ES_WINDOWS = os.name == "nt"
SCRIPT_CAPTURA = Path(__file__).parent.parent / "gdb_captura.py"


def resolver_binario(ruta: Path) -> Path:
    """En Windows, `gcc -o prog` escribe `prog.exe` y la terminal de MSYS2 acepta `./prog`: si `prog` no
    existe y `prog.exe` sí, se usa ese (N-ECO-10)."""
    if ES_WINDOWS and not ruta.exists():
        con_exe = ruta.with_name(ruta.name + ".exe")
        if con_exe.is_file():
            return con_exe
    return ruta


def obtener_libreria_vasquez() -> Optional[Path]:
    """Localiza o compila dinámicamente la biblioteca inyectora libvasquez_inject.so."""
    # 1. vasquez instalado (extra `ecosistema`)
    try:
        from vasquez.core.cache import get_cached_injector_library
        return get_cached_injector_library()
    except Exception:
        pass

    # 2. Buscar en el directorio de caché de usuario ~/.cache/vasquez/
    cache_dir = Path.home() / ".cache" / "vasquez"
    if cache_dir.exists():
        so_files = sorted(cache_dir.glob("libvasquez_inject_*.so"), key=lambda p: p.stat().st_mtime, reverse=True)
        if so_files:
            return so_files[0]

    return None


def _compilar_con_daedalus(
    archivo_c: Path,
    binario_out: Path,
    flags_adicionales: Optional[List[str]] = None,
) -> Optional[Tuple[bool, Optional[Path], str]]:
    try:
        from daedalus.core.compiler import compilar_archivos
    except ImportError:
        return None  # sin el extra `ecosistema` se usa el camino propio
    flags = ["-g", "-O0"]
    if flags_adicionales:
        flags.extend(flags_adicionales)
    res = compilar_archivos([archivo_c], binario_salida=binario_out, flags_adicionales=flags)
    return res.exito, (binario_out if res.exito else None), res.stderr_crudo


def _try_import_nostromo():
    try:
        from nostromo.core.sandbox import ejecutar_aislado
    except ImportError:
        return None  # sin el extra `ecosistema` se usa el camino propio
    return ejecutar_aislado


def compilar_codigo_c(
    archivo_c: Path,
    directorio_destino: Path,
    flags_adicionales: Optional[List[str]] = None,
) -> Tuple[bool, Optional[Path], str]:
    """Compila el código C con símbolos de depuración (-g -O0) delegando en DAEDALUS."""
    if not archivo_c.is_file():
        return False, None, f"El archivo '{archivo_c}' no existe."

    # En Windows gcc agrega .exe al binario: se devuelve la ruta que existe (N-ECO-10).
    binario_out = directorio_destino / (archivo_c.stem + (".exe" if ES_WINDOWS else ""))

    daed_res = _compilar_con_daedalus(archivo_c, binario_out, flags_adicionales)
    if daed_res is not None:
        return daed_res

    gcc_path = shutil.which("gcc") or "gcc"

    cmd = [
        gcc_path,
        "-g",
        "-O0",
        "-std=c11",
        "-Wall",
        "-Wextra",
        str(archivo_c.resolve()),
        "-o",
        str(binario_out.resolve()),
        "-lm",
    ]
    if flags_adicionales:
        cmd.extend(flags_adicionales)

    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res.returncode != 0:
            return False, None, res.stderr
        return True, binario_out, res.stderr  # advertencias: las usa el diagnóstico
    except subprocess.TimeoutExpired:
        return False, None, "La compilación excedió el tiempo límite (10s)."
    except Exception as e:
        return False, None, f"Error al ejecutar gcc: {e}"


def ejecutar_con_gdb(
    binario: Path,
    args: Optional[List[str]] = None,
    stdin_data: str = "",
    gdb_path: Optional[str] = None,
    timeout_segundos: int = 5,
    struct_nombre: Optional[str] = None,
    env_vars: Optional[Dict[str, str]] = None,
) -> Tuple[int, str, str, Optional[Dict[str, Any]]]:
    """Ejecuta el binario bajo gdb: (retorno, stdout, stderr, captura).

    La captura es el JSON de `hal/gdb_captura.py`; stdout y stderr son del programa. Sin gdb, o con
    un gdb sin Python, lo ejecuta directo y la captura es None.
    """
    gdb_bin = gdb_path or shutil.which("gdb") or "gdb"
    if not shutil.which(gdb_bin):
        return (*ejecutar_directo(binario, args, stdin_data, timeout_segundos), None)

    with tempfile.TemporaryDirectory(prefix="hal-captura-") as temporal:
        carpeta = Path(temporal)
        resultado = carpeta / "captura.json"
        config = carpeta / "config.json"
        config.write_text(json.dumps({
            "argumentos": " ".join(f'"{a}"' for a in (args or [])),
            "entorno": env_vars or {},
            "struct": struct_nombre.strip().lstrip("*") if struct_nombre else None,
            "resultado": str(resultado),
        }), encoding="utf-8")
        # El binario es del estudiante: nada de cargar los scripts que pudiera traer.
        cmd = [gdb_bin, "-nx", "-batch", "-iex", "set auto-load off", "-x", str(SCRIPT_CAPTURA), str(binario.resolve())]
        try:
            res = subprocess.run(
                cmd,
                input=stdin_data,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout_segundos + 5,
                env={**os.environ, **(env_vars or {}), "HAL_CAPTURA_CONFIG": str(config)},
            )
        except subprocess.TimeoutExpired:
            return 124, "", "Tiempo de ejecución excedido (Timeout).", None
        try:
            return res.returncode, res.stdout, res.stderr, json.loads(resultado.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return (*ejecutar_directo(binario, args, stdin_data, timeout_segundos), None)


def ejecutar_directo(
    binario: Path,
    args: Optional[List[str]] = None,
    stdin_data: str = "",
    timeout_segundos: int = 5,
) -> Tuple[int, str, str]:
    """Ejecución directa como fallback cuando GDB no está instalado."""
    try:
        nostromo_fn = _try_import_nostromo()
        if nostromo_fn:
            res_aislado = nostromo_fn(
                binario,
                args=args,
                stdin_texto=stdin_data,
                timeout_segundos=float(timeout_segundos),
                memoria_mb=64,
            )
            return res_aislado.codigo_retorno, res_aislado.stdout, res_aislado.stderr

        cmd = [str(binario.resolve())] + (args or [])
        res = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout_segundos,
        )
        return res.returncode, res.stdout, res.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "Tiempo de ejecución excedido (Timeout)."
    except Exception as e:
        return 1, "", str(e)


# `si_code` de cada señal (siginfo.h de Linux).
CODIGOS_DE_SENAL = {
    "SIGSEGV": {1: "SEGV_MAPERR", 2: "SEGV_ACCERR"},
    "SIGBUS": {1: "BUS_ADRALN", 2: "BUS_ADRERR", 3: "BUS_OBJERR"},
    "SIGFPE": {1: "FPE_INTDIV", 2: "FPE_INTOVF", 3: "FPE_FLTDIV", 4: "FPE_FLTOVF", 5: "FPE_FLTUND", 6: "FPE_FLTRES",
               7: "FPE_FLTINV", 8: "FPE_FLTSUB"},
}
# Cómo termina en Windows un programa que falla: no hay señales, hay excepciones.
EXCEPCIONES_WINDOWS = {0xC0000005: "SIGSEGV", 0xC00000FD: "SIGSEGV", 0xC0000094: "SIGFPE", 0xC000001D: "SIGILL"}

SIN_TRAZA = ("Sin gdb no hay traza: hal sabe cómo terminó el programa, pero no en qué línea. "
             "Con `hal doctor` ves qué falta instalar.")


def _terminacion_sin_gdb(retorno: int) -> Dict[str, Any]:
    """Lo que se sabe de un programa ejecutado directo: sólo cómo terminó."""
    numero = retorno if retorno < 0 else retorno - 128 if 128 < retorno <= 192 else None
    if retorno in EXCEPCIONES_WINDOWS:
        return {"terminacion": "senal", "senal": EXCEPCIONES_WINDOWS[retorno]}
    if numero is not None:
        try:
            return {"terminacion": "senal", "senal": signal.Signals(abs(numero)).name}
        except ValueError:
            pass
    return {"terminacion": "salida", "codigo_salida": retorno}


def _sin_fallas(codigo: Optional[int]) -> DiagnosticoCrash:
    """El programa terminó por su cuenta, sin ninguna señal."""
    if not codigo:
        return DiagnosticoCrash(
            tipo_senal="NINGUNA",
            codigo_senal="EXIT_SUCCESS",
            direccion_memoria=None,
            causa_raiz_titulo="Ejecución Exitosa (Sin Fallos)",
            explicacion="El programa ejecutó y finalizó normalmente con código de retorno 0 sin registrar señales de fallo.",
            accion_correctiva="No se requiere ninguna corrección.",
            es_crash=False,
        )
    return DiagnosticoCrash(
        tipo_senal="NINGUNA",
        codigo_senal="EXIT_FAILURE",
        direccion_memoria=None,
        causa_raiz_titulo=f"El programa terminó con código de retorno {codigo}",
        explicacion=(f"El programa no se cayó: terminó por su cuenta y devolvió {codigo}, que por convención "
                     "significa que algo salió mal."),
        accion_correctiva="Buscá el `return` de `main` o el `exit` que devuelve ese valor y revisá qué lo provoca.",
        es_crash=False,
    )


def diagnostico_desde_captura(
    captura: Dict[str, Any],
    salida_programa: str = "",
    struct_nombre: Optional[str] = None,
    vasquez_injected: bool = False,
) -> DiagnosticoCrash:
    """El diagnóstico a partir de la captura de `hal/gdb_captura.py`.

    `salida_programa` es lo que el programa escribió: ahí están los mensajes de la biblioteca
    («free(): invalid pointer», «stack smashing detected») y los de vasquez.
    """
    if captura["terminacion"] == "salida":
        return _sin_fallas(captura.get("codigo_salida"))

    frames = [StackFrame(**f) for f in captura.get("frames", [])]
    senal = captura["senal"]
    profundidad = captura.get("profundidad")
    diag = diagnosticar_crash(
        senal=senal,
        codigo_senal=CODIGOS_DE_SENAL.get(senal, {}).get(captura.get("si_code") or 0),
        direccion_memoria=captura.get("direccion"),
        frames=frames,
        gdb_output=salida_programa,
        vasquez_injected=vasquez_injected,
        profundidad_pila=profundidad,
        pila_corrupta=bool(captura.get("pila_corrupta")),
    )
    diag.registros = captura.get("registros", {})
    struct = captura.get("struct")
    if struct:
        diag.campos_struct = struct["campos"]
    diag.struct_nombre = struct["nombre"] if struct else struct_nombre
    return diag


def inspeccionar_fuente_o_binario(
    ruta_objetivo: Path,
    args: Optional[List[str]] = None,
    stdin_data: str = "",
    gdb_path: Optional[str] = None,
    struct_nombre: Optional[str] = None,
    inyectar_vasquez: bool = False,
    vasquez_fail_malloc_at: Optional[int] = None,
    vasquez_fail_realloc_at: Optional[int] = None,
    vasquez_fail_calloc_at: Optional[int] = None,
    vasquez_cascade: bool = False,
    vasquez_garbage_memory: bool = False,
    vasquez_poison_byte: Optional[int] = None,
) -> DiagnosticoCrash:
    """Inspecciona un archivo fuente `.c` (compilándolo previamente) o un binario precompilado."""
    ruta_objetivo = Path(ruta_objetivo)
    if not ruta_objetivo.exists():
        return DiagnosticoCrash(
            tipo_senal="ERROR",
            codigo_senal="FILE_NOT_FOUND",
            direccion_memoria=None,
            causa_raiz_titulo="Archivo no encontrado",
            explicacion=f"No se pudo encontrar el archivo especificado: '{ruta_objetivo}'",
            accion_correctiva="Verificá la ruta al archivo e intentalo de nuevo.",
            es_crash=False,
        )

    # Preparar entorno para inyección de Vasquez si se activó
    env_vars: Dict[str, str] = {}
    vasquez_activo = (
        inyectar_vasquez
        or vasquez_fail_malloc_at is not None
        or vasquez_fail_realloc_at is not None
        or vasquez_fail_calloc_at is not None
        or vasquez_cascade
        or vasquez_garbage_memory
    )
    if vasquez_activo:
        so_lib = obtener_libreria_vasquez()
        if so_lib and so_lib.exists():
            preload_key = "DYLD_INSERT_LIBRARIES" if sys.platform == "darwin" else "LD_PRELOAD"
            env_vars[preload_key] = str(so_lib.resolve())
            env_vars["VASQUEZ_TRACE"] = "1"
        if vasquez_fail_malloc_at is not None and vasquez_fail_malloc_at > 0:
            env_vars["VASQUEZ_MALLOC_FAIL_AT"] = str(vasquez_fail_malloc_at)
        elif inyectar_vasquez and vasquez_fail_malloc_at is None and vasquez_fail_realloc_at is None and vasquez_fail_calloc_at is None:
            env_vars["VASQUEZ_MALLOC_FAIL_AT"] = "1"

        if vasquez_fail_realloc_at is not None and vasquez_fail_realloc_at > 0:
            env_vars["VASQUEZ_REALLOC_FAIL_AT"] = str(vasquez_fail_realloc_at)

        if vasquez_fail_calloc_at is not None and vasquez_fail_calloc_at > 0:
            env_vars["VASQUEZ_CALLOC_FAIL_AT"] = str(vasquez_fail_calloc_at)

        if vasquez_cascade:
            env_vars["VASQUEZ_CASCADE_FAILS"] = "1"

        if vasquez_garbage_memory:
            env_vars["VASQUEZ_GARBAGE_MEMORY"] = "1"
            if vasquez_poison_byte is not None:
                env_vars["VASQUEZ_POISON_BYTE"] = str(vasquez_poison_byte)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        binario = ruta_objetivo
        err = ""

        # Si es código fuente .c, compilar
        if ruta_objetivo.suffix in (".c", ".cpp", ".cc"):
            ok, bin_comp, err = compilar_codigo_c(ruta_objetivo, tmp_path)
            if not ok or not bin_comp:
                return DiagnosticoCrash(
                    tipo_senal="ERROR",
                    codigo_senal="COMPILATION_ERROR",
                    direccion_memoria=None,
                    causa_raiz_titulo="Fallo de Compilación con GCC",
                    explicacion=f"El código no pudo compilarse:\n{err}",
                    accion_correctiva="Corregí los errores de sintaxis o cabeceras indicados por GCC antes de inspeccionar.",
                    es_crash=False,
                )
            binario = bin_comp

        advertencias = err if ruta_objetivo.suffix in (".c", ".cpp", ".cc") else ""
        rc, stdout, stderr, captura = ejecutar_con_gdb(
            binario,
            args=args,
            stdin_data=stdin_data,
            gdb_path=gdb_path,
            struct_nombre=struct_nombre,
            env_vars=env_vars if env_vars else None,
        )
        if rc == 124 and captura is None:
            return diagnosticar_sin_terminar()
        salida_programa = stdout + "\n" + stderr
        diagnostico = diagnostico_desde_captura(
            captura or _terminacion_sin_gdb(rc),
            salida_programa,
            struct_nombre=struct_nombre,
            vasquez_injected=vasquez_activo,
        )
        if captura is None and diagnostico.es_crash:
            diagnostico.explicacion = f"{diagnostico.explicacion.rstrip()}\n\n{SIN_TRAZA}"
        if diagnostico.es_crash:
            diagnostico = diagnosticar_puntero_a_local(diagnostico, advertencias)
            fuente = ruta_objetivo if ruta_objetivo.suffix == ".c" else None
            diagnostico = diagnosticar_pila(
                diagnostico,
                salida_programa,
                fuente,
                profundidad=(captura or {}).get("profundidad"),
                marcos=[(f, b) for f, b in (captura or {}).get("marcos_bytes", [])],
            )

        # Si compilamos el fuente, ajustar el nombre de archivo en los frames
        if ruta_objetivo.suffix in (".c", ".cpp", ".cc") and diagnostico.frames:
            for f in diagnostico.frames:
                if f.archivo and Path(f.archivo).name == ruta_objetivo.name:
                    f.archivo = str(ruta_objetivo.resolve())
            if diagnostico.archivo_falla and Path(diagnostico.archivo_falla).name == ruta_objetivo.name:
                diagnostico.archivo_falla = str(ruta_objetivo.resolve())

        return diagnostico
