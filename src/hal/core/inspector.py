"""Motor de ejecución, captura de crashes e inspección GDB en HAL."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from hal.core.explainer import diagnosticar_crash
from hal.core.models import DiagnosticoCrash, StackFrame


def parsear_struct_gdb(texto: str) -> Dict[str, Any]:
    """Parsea la representación de un struct emitida por GDB (print *var, print var o info locals).
    
    Retorna un diccionario estructurado de campos con su valor y tipo inferido.
    """
    idx_start = texto.find("{")
    if idx_start == -1:
        return {}

    depth = 0
    idx_end = -1
    in_str = False
    escape = False
    for i in range(idx_start, len(texto)):
        ch = texto[i]
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if not in_str:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    idx_end = i
                    break
    if idx_end == -1:
        idx_end = len(texto)

    inner = texto[idx_start + 1:idx_end]

    chunks = []
    curr = []
    depth = 0
    in_str = False
    escape = False
    for ch in inner:
        if escape:
            escape = False
            curr.append(ch)
            continue
        if ch == "\\":
            escape = True
            curr.append(ch)
            continue
        if ch == '"':
            in_str = not in_str
            curr.append(ch)
            continue
        if not in_str:
            if ch in ("{", "("):
                depth += 1
            elif ch in ("}", ")"):
                depth -= 1
            elif ch == "," and depth == 0:
                chunks.append("".join(curr).strip())
                curr = []
                continue
        curr.append(ch)
    if curr:
        chunks.append("".join(curr).strip())

    campos: Dict[str, Any] = {}
    for chunk in chunks:
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            k = k.strip()
            v = v.strip()
            if v.startswith('"'):
                v = re.sub(r'\\\\(?:[0-9]+|0)', '', v).replace(r'\000', '').replace(r'\0', '').replace('\x00', '')
            tipo = "valor"
            if v.startswith('"'):
                tipo = "string / char[]"
            elif v.startswith("0x") or v in ("(nil)", "NULL"):
                tipo = "puntero / hex"
            elif re.match(r"^-?\d+$", v):
                tipo = "int"
            elif re.match(r"^-?\d+\.\d+", v):
                tipo = "float / double"
            elif v.startswith("{"):
                tipo = "struct anidado"
            campos[k] = {"valor": v, "tipo": tipo}
    return campos


def obtener_libreria_vasquez() -> Optional[Path]:
    """Localiza o compila dinámicamente la biblioteca inyectora libvasquez_inject.so."""
    # 1. Intentar importar vasquez si está disponible
    try:
        from vasquez.core.cache import get_cached_injector_library
        return get_cached_injector_library()
    except Exception:
        pass

    # 2. Intentar agregar repositorio vasquez hermano en sys.path relativo
    try:
        # Resolver relativo al archivo actual dentro del monorepo / subdirectorios
        hermano_vasquez = Path(__file__).resolve().parents[4] / "vasquez" / "src"
        if hermano_vasquez.exists() and str(hermano_vasquez) not in sys.path:
            sys.path.insert(0, str(hermano_vasquez))
            from vasquez.core.cache import get_cached_injector_library
            return get_cached_injector_library()
    except Exception:
        pass

    # 3. Buscar en el directorio de caché de usuario ~/.cache/vasquez/
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
        flags = ["-g", "-O0"]
        if flags_adicionales:
            flags.extend(flags_adicionales)
        res = compilar_archivos([archivo_c], binario_salida=binario_out, flags_adicionales=flags)
        return res.exito, (binario_out if res.exito else None), res.stderr_crudo
    except ImportError:
        import sys
        sibling = Path(__file__).resolve().parents[4] / "daedalus" / "src"
        if sibling.is_dir() and str(sibling) not in sys.path:
            sys.path.insert(0, str(sibling))
            try:
                from daedalus.core.compiler import compilar_archivos
                flags = ["-g", "-O0"]
                if flags_adicionales:
                    flags.extend(flags_adicionales)
                res = compilar_archivos([archivo_c], binario_salida=binario_out, flags_adicionales=flags)
                return res.exito, (binario_out if res.exito else None), res.stderr_crudo
            except ImportError:
                return None
        return None


def _try_import_nostromo():
    try:
        from nostromo.core.sandbox import ejecutar_aislado
        return ejecutar_aislado
    except ImportError:
        import sys
        sibling = Path(__file__).resolve().parents[4] / "nostromo" / "src"
        if sibling.is_dir() and str(sibling) not in sys.path:
            sys.path.insert(0, str(sibling))
            try:
                from nostromo.core.sandbox import ejecutar_aislado
                return ejecutar_aislado
            except ImportError:
                return None
        return None


def compilar_codigo_c(
    archivo_c: Path,
    directorio_destino: Path,
    flags_adicionales: Optional[List[str]] = None,
) -> Tuple[bool, Optional[Path], str]:
    """Compila el código C con símbolos de depuración (-g -O0) delegando en DAEDALUS."""
    if not archivo_c.is_file():
        return False, None, f"El archivo '{archivo_c}' no existe."

    binario_out = directorio_destino / archivo_c.stem

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
        return True, binario_out, ""
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
) -> Tuple[int, str, str]:
    """Ejecuta el binario bajo GDB en modo batch y extrae información forense del crash."""
    gdb_bin = gdb_path or shutil.which("gdb") or "gdb"
    if not shutil.which(gdb_bin):
        # Fallback sin GDB
        return ejecutar_directo(binario, args, stdin_data, timeout_segundos)

    with tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False) as f:
        gdb_script = f.name
        f.write("set pagination off\n")
        f.write("set confirm off\n")
        if env_vars:
            for k, v in env_vars.items():
                f.write(f"set environment {k} {v}\n")
        args_str = " ".join(f'"{a}"' for a in (args or []))
        if args_str:
            f.write(f"set args {args_str}\n")
        f.write("run\n")
        if struct_nombre:
            clean_s = struct_nombre.strip().lstrip("*")
            f.write("echo ===GDB_STRUCT_BEGIN===\n")
            f.write("echo \\n\n")
            f.write("python\n")
            f.write("try:\n")
            f.write(f"    v = gdb.parse_and_eval('{clean_s}')\n")
            f.write("    if v.type.code == gdb.TYPE_CODE_PTR:\n")
            f.write("        print(v.dereference())\n")
            f.write("    else:\n")
            f.write("        print(v)\n")
            f.write("except Exception:\n")
            f.write(f"    try:\n        gdb.execute('print {struct_nombre}')\n    except Exception: pass\n")
            f.write("end\n")
            f.write("echo ===GDB_STRUCT_END===\n")
            f.write("echo \\n\n")
        f.write("echo ===GDB_INFO_PROGRAM===\n")
        f.write("info program\n")
        f.write("echo ===GDB_BACKTRACE===\n")
        f.write("backtrace full\n")
        f.write("echo ===GDB_LOCALS===\n")
        f.write("info locals\n")
        f.write("echo ===GDB_REGISTERS===\n")
        f.write("info registers\n")
        f.write("quit\n")

    try:
        cmd = [
            gdb_bin,
            "--batch",
            "-x",
            gdb_script,
            str(binario.resolve()),
        ]
        full_env = os.environ.copy()
        if env_vars:
            full_env.update(env_vars)
        res = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout_segundos + 5,
            env=full_env,
        )
        return res.returncode, res.stdout, res.stderr
    finally:
        if os.path.exists(gdb_script):
            os.remove(gdb_script)


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


def parsear_salida_gdb(
    gdb_stdout: str,
    gdb_stderr: str = "",
    struct_nombre: Optional[str] = None,
    vasquez_injected: bool = False,
) -> DiagnosticoCrash:
    """Parsea las secciones estructuradas emitidas por GDB."""
    senal = "SIGSEGV"
    codigo_senal = None
    direccion = None
    frames: List[StackFrame] = []
    salida_prog = ""

    # 1. Detectar señal y dirección
    m_sig = re.search(r"Program received signal (\w+),\s*([^.\n]+)", gdb_stdout)
    if m_sig:
        senal = m_sig.group(1).strip()
        codigo_senal = m_sig.group(2).strip()

    m_addr = re.search(r"address (0x[0-9a-fA-F]+)", gdb_stdout) or re.search(r"at (0x[0-9a-fA-F]+)", gdb_stdout)
    if m_addr:
        direccion = m_addr.group(1)

    # 2. Parsear Backtrace Full
    bt_section = ""
    if "===GDB_BACKTRACE===" in gdb_stdout:
        partes = gdb_stdout.split("===GDB_BACKTRACE===")
        bt_section = partes[1].split("===GDB_LOCALS===")[0]
    else:
        bt_section = gdb_stdout

    frame_re = re.compile(r"^#(\d+)\s+(?:0x[0-9a-fA-F]+\s+in\s+)?([a-zA-Z0-9_<>]+)\s*\((.*?)\)(?:\s+at\s+([^:]+):(\d+))?", re.MULTILINE)
    matches = list(frame_re.finditer(bt_section))

    for i, match in enumerate(matches):
        nivel = int(match.group(1))
        func_name = match.group(2)
        raw_args = match.group(3) or ""
        archivo = match.group(4)
        linea = int(match.group(5)) if match.group(5) else None

        # Parsear argumentos
        args_dict = {}
        if raw_args.strip() and raw_args.strip() != "void":
            for arg_part in raw_args.split(","):
                if "=" in arg_part:
                    k, v = arg_part.split("=", 1)
                    args_dict[k.strip()] = v.strip()

        # Parsear variables locales del frame (entre este match y el siguiente)
        start_idx = match.end()
        end_idx = matches[i + 1].start() if i + 1 < len(matches) else len(bt_section)
        frame_body = bt_section[start_idx:end_idx]

        locals_dict = {}
        for line in frame_body.splitlines():
            line_str = line.strip()
            if "=" in line_str and not line_str.startswith("#"):
                k, v = line_str.split("=", 1)
                if k.isidentifier():
                    locals_dict[k.strip()] = v.strip()

        frames.append(StackFrame(
            nivel=nivel,
            funcion=func_name,
            archivo=archivo,
            linea=linea,
            argumentos=args_dict,
            variables_locales=locals_dict,
        ))

    # Parsear registros de CPU
    registros: Dict[str, str] = {}
    if "===GDB_REGISTERS===" in gdb_stdout:
        reg_section = gdb_stdout.split("===GDB_REGISTERS===")[1]
        for line in reg_section.splitlines():
            partes = line.strip().split()
            if len(partes) >= 2 and not line.startswith("="):
                reg_name = partes[0]
                reg_val = partes[1]
                registros[reg_name] = reg_val

    # Parsear structs (Mejora 22)
    campos_struct: Optional[Dict[str, Any]] = None
    struct_nom = struct_nombre
    if "===GDB_STRUCT_BEGIN===" in gdb_stdout and "===GDB_STRUCT_END===" in gdb_stdout:
        struct_section = gdb_stdout.split("===GDB_STRUCT_BEGIN===")[1].split("===GDB_STRUCT_END===")[0]
        parsed_fields = parsear_struct_gdb(struct_section)
        if parsed_fields:
            campos_struct = parsed_fields

    # Fallback: buscar struct en info locals si no se detectó
    if not campos_struct and "===GDB_LOCALS===" in gdb_stdout:
        locals_section = gdb_stdout.split("===GDB_LOCALS===")[1].split("===GDB_REGISTERS===")[0]
        for l_line in locals_section.splitlines():
            l_line_str = l_line.strip()
            if "=" in l_line_str and "{" in l_line_str and "}" in l_line_str:
                v_name, _ = l_line_str.split("=", 1)
                v_name = v_name.strip()
                if v_name.isidentifier():
                    parsed = parsear_struct_gdb(l_line_str)
                    if parsed:
                        campos_struct = parsed
                        if not struct_nom:
                            struct_nom = v_name
                        break

    # Si no hubo señal detectada pero el proceso terminó con éxito
    if "exited normally" in gdb_stdout or "exited with code 0" in gdb_stdout:
        return DiagnosticoCrash(
            tipo_senal="NINGUNA",
            codigo_senal="EXIT_SUCCESS",
            direccion_memoria=None,
            causa_raiz_titulo="Ejecución Exitosa (Sin Fallos)",
            explicacion="El programa ejecutó y finalizó normalmente con código de retorno 0 sin registrar señales de fallo.",
            accion_correctiva="No se requiere ninguna corrección.",
            frames=frames,
            registros=registros,
            salida_programa=salida_prog,
            es_crash=False,
            campos_struct=campos_struct,
            struct_nombre=struct_nom,
        )

    diag = diagnosticar_crash(
        senal=senal,
        codigo_senal=codigo_senal,
        direccion_memoria=direccion,
        frames=frames,
        gdb_output=gdb_stdout + "\n" + gdb_stderr,
        salida_prog=salida_prog,
        vasquez_injected=vasquez_injected,
    )
    diag.registros = registros
    diag.campos_struct = campos_struct
    diag.struct_nombre = struct_nom
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

        _, stdout, stderr = ejecutar_con_gdb(
            binario,
            args=args,
            stdin_data=stdin_data,
            gdb_path=gdb_path,
            struct_nombre=struct_nombre,
            env_vars=env_vars if env_vars else None,
        )
        diagnostico = parsear_salida_gdb(
            stdout,
            stderr,
            struct_nombre=struct_nombre,
            vasquez_injected=vasquez_activo,
        )

        # Si compilamos el fuente, ajustar el nombre de archivo en los frames
        if ruta_objetivo.suffix in (".c", ".cpp", ".cc") and diagnostico.frames:
            for f in diagnostico.frames:
                if f.archivo and Path(f.archivo).name == ruta_objetivo.name:
                    f.archivo = str(ruta_objetivo.resolve())
            if diagnostico.archivo_falla and Path(diagnostico.archivo_falla).name == ruta_objetivo.name:
                diagnostico.archivo_falla = str(ruta_objetivo.resolve())

        return diagnostico
