"""Motor de ejecución, captura de crashes e inspección GDB en HAL."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

from hal.core.explainer import diagnosticar_crash
from hal.core.models import DiagnosticoCrash, StackFrame


def compilar_codigo_c(
    archivo_c: Path,
    directorio_destino: Path,
    flags_adicionales: Optional[List[str]] = None,
) -> Tuple[bool, Optional[Path], str]:
    """Compila el código C con símbolos de depuración (-g -O0)."""
    if not archivo_c.is_file():
        return False, None, f"El archivo '{archivo_c}' no existe."

    gcc_path = shutil.which("gcc") or "gcc"
    binario_out = directorio_destino / archivo_c.stem

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
        args_str = " ".join(f'"{a}"' for a in (args or []))
        if args_str:
            f.write(f"set args {args_str}\n")
        f.write("run\n")
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
        res = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout_segundos + 5,
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
    cmd = [str(binario.resolve())] + (args or [])
    try:
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


def parsear_salida_gdb(gdb_stdout: str, gdb_stderr: str = "") -> DiagnosticoCrash:
    """Parsea las secciones estructuradas emitidas por GDB."""
    senal = "SIGSEGV"
    codigo_senal = None
    direccion = None
    frames: List[StackFrame] = []
    salida_prog = ""

    # 1. Detectar señal y dirección
    # Ej: "Program received signal SIGSEGV, Segmentation fault."
    # Ej: "Program received signal SIGABRT, Aborted."
    # Ej: "0x0000555555555169 in main () at crash.c:12"
    m_sig = re.search(r"Program received signal (\w+),\s*([^.\n]+)", gdb_stdout)
    if m_sig:
        senal = m_sig.group(1).strip()
        codigo_senal = m_sig.group(2).strip()

    m_addr = re.search(r"address (0x[0-9a-fA-F]+)", gdb_stdout) or re.search(r"at (0x[0-9a-fA-F]+)", gdb_stdout)
    if m_addr:
        direccion = m_addr.group(1)

    # 2. Parsear Backtrace Full
    # Formato típico:
    # #0  0x0000555555555169 in invertir_vector (vec=0x0, n=5) at main.c:15
    #         i = 0
    #         temp = 0
    # #1  0x00005555555551d0 in main () at main.c:22
    #         vec = 0x0
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
        )

    diag = diagnosticar_crash(
        senal=senal,
        codigo_senal=codigo_senal,
        direccion_memoria=direccion,
        frames=frames,
        gdb_output=gdb_stdout + "\n" + gdb_stderr,
        salida_prog=salida_prog,
    )
    diag.registros = registros
    return diag


def inspeccionar_fuente_o_binario(
    ruta_objetivo: Path,
    args: Optional[List[str]] = None,
    stdin_data: str = "",
    gdb_path: Optional[str] = None,
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

        _, stdout, stderr = ejecutar_con_gdb(binario, args=args, stdin_data=stdin_data, gdb_path=gdb_path)
        diagnostico = parsear_salida_gdb(stdout, stderr)

        # Si compilamos el fuente, ajustar el nombre de archivo en los frames
        if ruta_objetivo.suffix in (".c", ".cpp", ".cc") and diagnostico.frames:
            for f in diagnostico.frames:
                if f.archivo and Path(f.archivo).name == ruta_objetivo.name:
                    f.archivo = str(ruta_objetivo.resolve())
            if diagnostico.archivo_falla and Path(diagnostico.archivo_falla).name == ruta_objetivo.name:
                diagnostico.archivo_falla = str(ruta_objetivo.resolve())

        return diagnostico
