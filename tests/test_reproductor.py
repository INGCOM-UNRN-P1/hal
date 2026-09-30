"""Script reproductor sin ruta fija en /tmp y con citas correctas para el shell (N-HAL-02)."""

import shutil
import subprocess

import pytest
from rich.text import Text
from typer.testing import CliRunner

from hal.cli import app, script_reproductor

runner = CliRunner()


def _asan_disponible() -> bool:
    """El script compila con ASan/UBSan: sin libasan instalado no se puede ejecutar."""
    if shutil.which("gcc") is None:
        return False
    prueba = subprocess.run(["gcc", "-fsanitize=address,undefined", "-x", "c", "-", "-o", "/dev/null"],
                            input="int main(void){return 0;}", capture_output=True, text=True)
    return prueba.returncode == 0


PROGRAMA = r"""#include <stdio.h>
int main(int argc, char **argv) {
    char linea[128];
    for (int i = 1; i < argc; i++) printf("arg[%d]=%s\n", i, argv[i]);
    if (fgets(linea, sizeof linea, stdin)) printf("stdin=%s", linea);
    return 0;
}
"""


def test_no_usa_una_ruta_fija_de_tmp(tmp_path):
    fuente = tmp_path / "app.c"
    fuente.write_text(PROGRAMA)
    script = script_reproductor(fuente)
    assert "/tmp/crash_app" not in script
    assert "mktemp -d" in script
    assert "trap" in script


@pytest.mark.skipif(not _asan_disponible(), reason="requiere gcc con libasan y libubsan")
def test_el_script_reproduce_con_entrada_y_argumentos_citados(tmp_path):
    carpeta = tmp_path / "con espacios $HOME"
    carpeta.mkdir()
    fuente = carpeta / "app.c"
    fuente.write_text(PROGRAMA)
    salida = tmp_path / "reproducir.sh"
    res = runner.invoke(app, ["generate-reproducer", str(fuente), "-o", str(salida),
                              "--stdin", "it's $(echo inyectado)", "--args", "'uno dos' tres"])
    assert res.exit_code == 0, res.output
    ejecucion = subprocess.run(["bash", str(salida)], capture_output=True, text=True, timeout=120)
    assert ejecucion.returncode == 0, ejecucion.stderr
    assert "arg[1]=uno dos" in ejecucion.stdout
    assert "arg[2]=tres" in ejecucion.stdout
    assert "stdin=it's $(echo inyectado)" in ejecucion.stdout


def test_args_mal_formado_es_error_de_uso(tmp_path):
    fuente = tmp_path / "app.c"
    fuente.write_text(PROGRAMA)
    res = runner.invoke(app, ["generate-reproducer", str(fuente), "-o", str(tmp_path / "r.sh"), "--args", "'sin cerrar"],
                        env={"COLUMNS": "200"})
    assert res.exit_code == 2
    # Texto plano: en GitHub Actions, Typer resalta la salida con códigos ANSI que parten «--args».
    assert "--args" in Text.from_ansi(res.output).plain


@pytest.mark.skipif(shutil.which("gcc") is None, reason="requiere gcc")
def test_el_script_de_un_binario_cita_ruta_entrada_y_argumentos(tmp_path):
    carpeta = tmp_path / "con espacios $HOME"
    carpeta.mkdir()
    fuente = carpeta / "app.c"
    fuente.write_text(PROGRAMA)
    binario = carpeta / "app"
    subprocess.run(["gcc", str(fuente), "-o", str(binario)], check=True)
    salida = tmp_path / "reproducir.sh"
    res = runner.invoke(app, ["generate-reproducer", str(binario), "-o", str(salida),
                              "--stdin", "it's $(echo inyectado)", "--args", "'uno dos' tres"])
    assert res.exit_code == 0, res.output
    ejecucion = subprocess.run(["bash", str(salida)], capture_output=True, text=True, timeout=60)
    assert ejecucion.returncode == 0, ejecucion.stderr
    assert "arg[1]=uno dos" in ejecucion.stdout
    assert "arg[2]=tres" in ejecucion.stdout
    assert "stdin=it's $(echo inyectado)" in ejecucion.stdout
