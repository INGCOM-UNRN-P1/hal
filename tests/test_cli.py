"""Tests de integración de la CLI de HAL."""

import json
from pathlib import Path
from typer.testing import CliRunner
from hal.cli import app

runner = CliRunner()


def test_cli_version():
    res = runner.invoke(app, ["--version"])
    assert res.exit_code == 0
    assert "HAL" in res.stdout


def test_cli_doctor():
    res = runner.invoke(app, ["doctor"])
    assert res.exit_code == 0
    assert "Compilador GCC" in res.stdout


def test_cli_run_archivo_inexistente():
    res = runner.invoke(app, ["run", "no_existe_archivo.c"])
    assert res.exit_code == 0 or "no existe" in res.stdout or "Error" in res.stderr


def test_cli_run_codigo_exitoso(tmp_path):
    fuente = tmp_path / "ok.c"
    fuente.write_text("#include <stdio.h>\nint main(void) { printf(\"Hola\\n\"); return 0; }\n")

    res = runner.invoke(app, ["run", str(fuente)])
    assert res.exit_code == 0
    assert "Exitosa" in res.stdout


def test_cli_run_json_output(tmp_path):
    fuente = tmp_path / "crash.c"
    fuente.write_text("#include <stdio.h>\nint main(void) { int* p = NULL; *p = 10; return 0; }\n")

    res = runner.invoke(app, ["run", str(fuente), "--json"])
    assert res.exit_code == 1
    data = json.loads(res.stdout)
    assert data["es_crash"] is True
    assert data["tipo_senal"] == "SIGSEGV"
