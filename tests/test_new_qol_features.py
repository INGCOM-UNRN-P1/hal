"""Pruebas unitarias de funcionalidades QoL añadidas en HAL."""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from typer.testing import CliRunner


from hal.cli import app
from hal.core.advice import obtener_consejos
from hal.core.doctor import ejecutar_diagnostico_doctor
from hal.core.explainer import diagnosticar_crash
from hal.core.fd_audit import auditar_descriptores_archivo
from hal.core.models import StackFrame
from hal.core.symbols import desofuscar_direccion, inspeccionar_variables_globales
from hal.core.valgrind_parser import parsear_log_valgrind
from hal.core.inspector import inspeccionar_fuente_o_binario, parsear_struct_gdb

runner = CliRunner()


def test_sigbus_detection():
    diag = diagnosticar_crash(
        senal="SIGBUS",
        codigo_senal="BUS_ADRALN",
        direccion_memoria="0x7fff0001",
        frames=[StackFrame(nivel=0, funcion="acceso_desalineado", archivo="bus.c", linea=15)],
    )
    assert diag.tipo_senal == "SIGBUS"
    assert "Desalineación" in diag.causa_raiz_titulo
    assert "BUS_ADRALN" in diag.codigo_senal


def test_doctor_core():
    ok = ejecutar_diagnostico_doctor()
    assert isinstance(ok, bool)


def test_valgrind_parser():
    sample_log = """
==12345== Invalid read of size 4
==12345==    at 0x555555555169: main (crash.c:12)
==12345==  Address 0x0 is not stack'd, malloc'd or (recently) free'd
==12345== 
==12345== LEAK SUMMARY:
==12345==    definitely lost: 40 bytes in 1 blocks
"""
    res = parsear_log_valgrind(sample_log)
    assert res["total_errores"] == 2
    assert res["fugas_bytes"] == 40
    assert not res["sin_errores"]


def test_cli_valgrind(tmp_path: Path):
    log_file = tmp_path / "valgrind.log"
    log_file.write_text("==100== Invalid write of size 8\n==100== definitely lost: 100 bytes in 2 blocks\n", encoding="utf-8")

    result = runner.invoke(app, ["valgrind", str(log_file), "--json"])
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["total_errores"] >= 2


def test_fd_audit(tmp_path: Path):
    c_file = tmp_path / "fds.c"
    c_file.write_text("""
#include <stdio.h>
int main() {
    FILE *f1 = fopen("data.txt", "r");
    FILE *f2 = fopen("out.txt", "w");
    fclose(f1);
    return 0;
}
""", encoding="utf-8")

    res = auditar_descriptores_archivo(c_file)
    assert res["total_aperturas"] == 2
    assert res["total_cierres"] == 1
    assert res["total_huerfanos"] == 1
    assert res["huerfanos"][0]["variable"] == "f2"


def test_cli_check_fds(tmp_path: Path):
    c_file = tmp_path / "clean_fds.c"
    c_file.write_text("""
#include <stdio.h>
int main() {
    FILE *f = fopen("data.txt", "r");
    if (f) fclose(f);
    return 0;
}
""", encoding="utf-8")

    result = runner.invoke(app, ["check-fds", str(c_file)])
    assert result.exit_code == 0
    assert "cerrados adecuadamente" in result.output


def test_advice_command():
    consejos = obtener_consejos()
    assert len(consejos) >= 5

    result = runner.invoke(app, ["advice"])
    assert result.exit_code == 0
    assert "Consejo #" in result.output


def test_resolve_addr(tmp_path: Path):
    dummy_bin = tmp_path / "dummy"
    dummy_bin.write_bytes(b"\x7fELF")

    res = desofuscar_direccion(dummy_bin, "0x1234")
    assert "direccion" in res


def test_use_after_free_detection():
    gdb_log = """
    ==1234==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010
    READ of size 4 at 0x602000000010 thread T0
    0x602000000010 is located 0 bytes inside of 40-byte region [0x602000000010,0x602000000038)
    freed by thread T0 here:
        #0 0x7ffff7a00123 in free
        #1 0x555555555180 in main at uaf.c:8
    """
    diag = diagnosticar_crash(
        senal="SIGSEGV",
        codigo_senal="SEGV_ACCERR",
        direccion_memoria="0x602000000010",
        frames=[StackFrame(nivel=0, funcion="main", archivo="uaf.c", linea=10)],
        gdb_output=gdb_log,
    )
    assert diag.es_use_after_free is True
    assert diag.codigo_senal == "USE_AFTER_FREE"
    assert "Use-After-Free" in diag.causa_raiz_titulo
    assert "free(p); p = NULL;" in diag.accion_correctiva


def test_oom_enomem_detection():
    gdb_log = "malloc: Cannot allocate memory\nProgram received signal SIGABRT, Aborted."
    diag = diagnosticar_crash(
        senal="SIGABRT",
        codigo_senal="ABRT",
        direccion_memoria=None,
        frames=[StackFrame(nivel=0, funcion="main", archivo="oom.c", linea=6, variables_locales={"huge": "18446744073709551615"})],
        gdb_output=gdb_log,
    )
    assert diag.es_oom_enomem is True
    assert diag.codigo_senal == "ENOMEM_OOM"
    assert "ENOMEM / Out-Of-Memory" in diag.causa_raiz_titulo
    assert "integer overflow" in diag.accion_correctiva


def test_invalid_free_detection():
    gdb_err = "free(): invalid pointer\nProgram received signal SIGABRT, Aborted."
    diag = diagnosticar_crash(
        senal="SIGABRT",
        codigo_senal="ABRT",
        direccion_memoria=None,
        frames=[StackFrame(nivel=0, funcion="main", archivo="bad_free.c", linea=7)],
        salida_prog=gdb_err,
    )
    assert diag.es_invalid_free is True
    assert diag.codigo_senal == "INVALID_POINTER_FREE"
    assert "Invalid Pointer Free" in diag.causa_raiz_titulo
    assert "pila" in diag.explicacion


def test_invalid_free_execution(tmp_path: Path):
    c_code = tmp_path / "bad_free.c"
    c_code.write_text("""
#include <stdlib.h>
int main() {
    int x = 123;
    free(&x);
    return 0;
}
""", encoding="utf-8")
    diag = inspeccionar_fuente_o_binario(c_code)
    assert diag.es_crash is True
    assert (
        diag.es_invalid_free is True
        or diag.codigo_senal == "INVALID_POINTER_FREE"
        or "invalid pointer" in diag.salida_programa.lower()
        or diag.tipo_senal in ("SIGSEGV", "SIGABRT")
    )


def test_struct_parser_unit():
    raw_gdb = '$1 = {id = 42, nombre = "Antigravity\\000\\000", score = 98.75, sig = 0x555555558000}'
    fields = parsear_struct_gdb(raw_gdb)
    assert "id" in fields
    assert fields["id"]["valor"] == "42"
    assert fields["id"]["tipo"] == "int"
    assert fields["nombre"]["valor"] == '"Antigravity"'
    assert "string" in fields["nombre"]["tipo"]
    assert fields["score"]["valor"] == "98.75"
    assert "double" in fields["score"]["tipo"] or "float" in fields["score"]["tipo"]
    assert fields["sig"]["valor"] == "0x555555558000"
    assert "hex" in fields["sig"]["tipo"]


def test_struct_inspection_cli(tmp_path: Path):
    c_code = tmp_path / "struct_crash.c"
    c_code.write_text("""
#include <stdio.h>
#include <stdlib.h>

typedef struct Alumno {
    int padron;
    char nombre[16];
    double nota;
} Alumno;

int main() {
    Alumno a = {101234, "Enehuen", 9.5};
    int *ptr = NULL;
    *ptr = 1;
    return 0;
}
""", encoding="utf-8")
    result = runner.invoke(app, ["struct", str(c_code), "a", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "padron" in data
    assert data["padron"]["valor"] == "101234"

    res_run = runner.invoke(app, ["run", str(c_code), "--struct", "a", "--json"])
    assert res_run.exit_code == 1  # Hubo crash
    run_data = json.loads(res_run.output)
    assert run_data["campos_struct"] is not None
    assert "padron" in run_data["campos_struct"]


def test_vasquez_injection_detection_unit():
    gdb_out = "[vasquez] INJECTING FAULT: MALLOC forced NULL at invocation 1\nProgram received signal SIGSEGV"
    diag = diagnosticar_crash(
        senal="SIGSEGV",
        codigo_senal="SEGV_MAPERR",
        direccion_memoria="0x0",
        frames=[StackFrame(nivel=0, funcion="main", archivo="app.c", linea=15, variables_locales={"buffer": "0x0"})],
        gdb_output=gdb_out,
        vasquez_injected=True,
    )
    assert diag.vasquez_inyeccion_detectada is not None
    assert diag.vasquez_inyeccion_detectada["inyectado"] is True
    assert "VASQUEZ" in diag.explicacion


def test_vasquez_injection_cli_integration(tmp_path: Path):
    from hal.core.inspector import obtener_libreria_vasquez
    if not obtener_libreria_vasquez():
        pytest.skip("Librería inyectora de Vasquez no disponible en el entorno")

    c_code = tmp_path / "vasquez_test.c"
    c_code.write_text("""
#include <stdlib.h>
int main() {
    int *arr = (int *)malloc(sizeof(int) * 4);
    arr[0] = 42; // Crash si malloc devuelve NULL
    free(arr);
    return 0;
}
""", encoding="utf-8")
    res = runner.invoke(app, ["run", str(c_code), "--inject-vasquez", "--fail-malloc-at", "1", "--json"])
    assert res.exit_code == 1
    data = json.loads(res.output)
    assert data["es_crash"] is True
    assert data["vasquez_inyeccion_detectada"] is not None


