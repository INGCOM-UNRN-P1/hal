"""hal no da por buena una entrada que no pudo diagnosticar (N-ECO-18).

- Un archivo que no existe: `hal check no_existe.c` mostraba «Archivo no
  encontrado» y salía con 0. Ahora es un error de uso (código 2).
- Un .c que no compila: «Error en HAL: Fallo de Compilación con GCC» salía con
  0 (el código solo miraba si hubo un crash) y el informe para dredd decía
  «Ejecución Exitosa». Ahora sale con 1 y el informe lo marca como fallo.
"""

import shutil

import pytest
from typer.testing import CliRunner

from hal.cli import app

runner = CliRunner()


@pytest.mark.parametrize("comando", ["check", "run", "report", "inspect", "replay", "registers", "check-fds",
                                     "inspect-globals", "generate-reproducer", "struct"])
def test_un_archivo_que_no_existe_es_un_error_de_uso(comando, tmp_path):
    res = runner.invoke(app, [comando, str(tmp_path / "no_existe.c")], env={"COLUMNS": "200"})
    assert res.exit_code == 2, res.output
    assert "no_existe.c" in res.output


@pytest.mark.skipif(shutil.which("gcc") is None, reason="requiere gcc")
def test_un_fuente_que_no_compila_sale_con_1_y_el_informe_lo_marca(tmp_path):
    fuente = tmp_path / "roto.c"
    fuente.write_text("int main(void) { return x; }\n", encoding="utf-8")
    res = runner.invoke(app, ["check", str(fuente)])
    assert res.exit_code == 1, res.output

    informe = tmp_path / "hal.md"
    res = runner.invoke(app, ["check", str(fuente), "--md", str(informe)])
    assert res.exit_code == 1
    texto = informe.read_text(encoding="utf-8")
    assert "status=fail" in texto and "Ejecución Exitosa" not in texto
