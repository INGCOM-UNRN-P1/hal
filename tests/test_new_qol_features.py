"""Pruebas unitarias de funcionalidades QoL añadidas en HAL."""

from __future__ import annotations

import json
from pathlib import Path
from typer.testing import CliRunner

from hal.cli import app
from hal.core.advice import obtener_consejos
from hal.core.doctor import ejecutar_diagnostico_doctor
from hal.core.explainer import diagnosticar_crash
from hal.core.fd_audit import auditar_descriptores_archivo
from hal.core.models import StackFrame
from hal.core.symbols import desofuscar_direccion, inspeccionar_variables_globales
from hal.core.valgrind_parser import parsear_log_valgrind

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
