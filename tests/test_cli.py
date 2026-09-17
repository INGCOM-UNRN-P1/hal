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
    assert data["schema_version"] == "1.0.0"
    assert "archivo" in data
    assert "linea" in data
    # Comprobar que no se filtran rutas absolutas en archivo_falla
    assert not data["archivo_falla"].startswith("/")


def test_cli_doctor_json():
    res = runner.invoke(app, ["doctor", "--json"])
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert "ok" in data
    assert "herramientas" in data
    assert "gcc" in data["herramientas"]


def test_cli_advice_json():
    res = runner.invoke(app, ["advice", "--json"])
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert isinstance(data, list)
    assert len(data) >= 3
    assert "regla" in data[0]


def test_cli_generate_reproducer_json(tmp_path):
    fuente = tmp_path / "crash.c"
    fuente.write_text("int main(void) { return 0; }\n")
    out_sh = tmp_path / "reprod.sh"
    res = runner.invoke(app, ["generate-reproducer", str(fuente), "-o", str(out_sh), "--json"])
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["ok"] is True
    assert out_sh.is_file()
