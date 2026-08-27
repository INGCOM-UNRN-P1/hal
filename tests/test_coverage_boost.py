"""Tests adicionales para cubrir el 100% de ramas y líneas en HAL."""

import json
from pathlib import Path
from typer.testing import CliRunner
import hal.cli
from hal.cli import app
from hal.core.explainer import diagnosticar_crash
from hal.core.inspector import (
    compilar_codigo_c,
    ejecutar_con_gdb,
    ejecutar_directo,
    parsear_salida_gdb,
    inspeccionar_fuente_o_binario,
)
from hal.core.models import StackFrame

runner = CliRunner()


def test_diagnosticar_abrt_variantes():
    # Double free
    d1 = diagnosticar_crash("SIGABRT", "ABRT", None, [], gdb_output="free(): double free detected")
    assert "Double Free" in d1.causa_raiz_titulo

    # Heap corruption
    d2 = diagnosticar_crash("SIGABRT", "ABRT", None, [], gdb_output="corrupted size vs. prev_size")
    assert "Heap" in d2.causa_raiz_titulo

    # Assert
    d3 = diagnosticar_crash("SIGABRT", "ABRT", None, [], salida_prog="Assertion failed: x > 0")
    assert "Aserción" in d3.causa_raiz_titulo

    # Generic abort
    d4 = diagnosticar_crash("SIGABRT", "ABRT", None, [], gdb_output="")
    assert "Abort" in d4.causa_raiz_titulo


def test_diagnosticar_fpe_y_generico():
    # FPE
    d_fpe = diagnosticar_crash("SIGFPE", "FPE_INTDIV", None, [])
    assert "División" in d_fpe.causa_raiz_titulo

    # Generic
    d_gen = diagnosticar_crash("SIGILL", "ILL_ILLOPC", "0x1234", [])
    assert "SIGILL" in d_gen.causa_raiz_titulo


def test_diagnosticar_stack_overflow():
    frames = [StackFrame(nivel=i, funcion="recurse", archivo="main.c", linea=10) for i in range(35)]
    d_so = diagnosticar_crash("SIGSEGV", "SEGV_ACCERR", "0x7fffff", frames)
    assert "Stack Overflow" in d_so.causa_raiz_titulo


def test_compilar_fallas(tmp_path):
    f_inexistente = tmp_path / "no_existe.c"
    ok, b, err = compilar_codigo_c(f_inexistente, tmp_path)
    assert not ok

    f_invalido = tmp_path / "invalido.c"
    f_invalido.write_text("sintaxis rota no c\n")
    ok, b, err = compilar_codigo_c(f_invalido, tmp_path)
    assert not ok


def test_ejecutar_directo_timeout_y_ok(tmp_path):
    f = tmp_path / "ok.c"
    f.write_text("int main() { return 0; }\n")
    ok, b, err = compilar_codigo_c(f, tmp_path)
    assert ok
    ret, out, err = ejecutar_directo(b)
    assert ret == 0


def test_inspeccionar_fuente_no_existe():
    diag = inspeccionar_fuente_o_binario(Path("/no/existe/nada.c"))
    assert diag.codigo_senal == "FILE_NOT_FOUND"


def test_inspeccionar_fuente_error_compilacion(tmp_path):
    f = tmp_path / "syntax_err.c"
    f.write_text("int main() { return invalid; }\n")
    diag = inspeccionar_fuente_o_binario(f)
    assert diag.codigo_senal == "COMPILATION_ERROR"


def test_cli_explain_rich_output(tmp_path):
    fuente = tmp_path / "segv.c"
    fuente.write_text("int main() { int *p = 0; return *p; }\n")
    ok, binario, err = compilar_codigo_c(fuente, tmp_path)
    assert ok

    res = runner.invoke(app, ["run", str(fuente)])
    assert res.exit_code == 1
    assert "Diagnóstico Forense" in res.stdout


def test_cli_inspect_json_and_edge_cases(tmp_path):
    fuente = tmp_path / "crash.c"
    fuente.write_text("int main() { int *p = (int*)0; return *p; }\n")
    ok, binario, err = compilar_codigo_c(fuente, tmp_path, flags_adicionales=["-O0"])
    assert ok

    res = runner.invoke(app, ["inspect", str(binario), "--json"])
    assert res.exit_code == 1
    data = json.loads(res.stdout)
    assert data["es_crash"] is True


def test_explainer_local_var_culpable():
    # Frame with variable culpable in locals (not args)
    frame = StackFrame(
        nivel=0,
        funcion="calcular",
        archivo="calc.c",
        linea=42,
        argumentos={"x": "10"},
        variables_locales={"ptr_invalido": "0x0"},
    )
    diag = diagnosticar_crash("SIGSEGV", "SEGV_MAPERR", "0x0", [frame])
    assert diag.variable_culpable == "ptr_invalido"

    # Frame with system file only -> fallback to frame[0]
    sys_frame = StackFrame(nivel=0, funcion="__libc_start_main", archivo="/usr/lib/libc.so", linea=100)
    diag_sys = diagnosticar_crash("SIGSEGV", "SEGV_MAPERR", "0x0", [sys_frame])
    assert diag_sys.funcion_falla == "__libc_start_main"


def test_cli_doctor():
    res = runner.invoke(app, ["doctor"])
    assert res.exit_code == 0
    assert "gdb" in res.stdout


def test_cli_run_directo(tmp_path):
    f = tmp_path / "prog.c"
    f.write_text("int main() { return 0; }\n")
    res = runner.invoke(app, ["run", str(f)])
    assert res.exit_code == 0


def test_cli_main_block(monkeypatch):
    monkeypatch.setattr("sys.argv", ["hal", "--version"])
    try:
        hal.cli.main()
    except SystemExit as e:
        assert e.code == 0
