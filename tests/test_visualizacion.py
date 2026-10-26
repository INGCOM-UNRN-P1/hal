"""Ola 10: el crash de un .c trae el comando de bishop para verlo paso a paso hasta la falla."""

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from hal.cli import app
from hal.core.gdb_script import generar_script_gdb
from hal.core.models import DiagnosticoCrash
from hal.core.pista import diagnostico_en_pista
from hal.core.visualizacion import comando_bishop, completar_visualizacion, generar_traza_html
from hal.presentacion import generar_seccion_markdown

runner = CliRunner()
con_gdb = pytest.mark.skipif(not (shutil.which("gcc") and shutil.which("gdb")), reason="hace falta gcc y gdb")
con_bishop = pytest.mark.skipif(not shutil.which("bishop"), reason="hace falta bishop")

SEGV = """\
#include <stdio.h>
int main(void)
{
    int *p = NULL;
    printf("%d\\n", *p);
    return 0;
}
"""


def _diag(**cambios):
    base = dict(tipo_senal="SIGSEGV", codigo_senal="SEGV_MAPERR", direccion_memoria="0x0",
                causa_raiz_titulo="Desreferencia de puntero nulo", explicacion="e", accion_correctiva="a",
                archivo_falla="tp.c", linea_falla=5, funcion_falla="main")
    base.update(cambios)
    return DiagnosticoCrash(**base)


def test_comando_para_un_c_que_se_cae():
    assert comando_bishop(_diag(), Path("tp.c")) == ["bishop", "trace", "tp.c", "--hasta-falla", "--html",
                                                     "tp.falla.html"]
    con_todo = comando_bishop(_diag(codigo_senal="STACK_OVERFLOW"), Path("tp.c"), ["-v", "x"], Path("e.txt"))
    assert con_todo[-7:] == ["--input", "e.txt", "--limite-pila", "64", "--", "-v", "x"]


@pytest.mark.parametrize("diag, objetivo", [
    (_diag(), Path("tp")),  # un binario: bishop necesita el fuente
    (_diag(es_crash=False, tipo_senal="NINGUNA"), Path("tp.c")),
    (diagnostico_en_pista(_diag()), Path("tp.c")),  # la traza mostraría la línea y los valores
])
def test_sin_comando(diag, objetivo):
    assert comando_bishop(diag, objetivo) is None
    completar_visualizacion(diag, objetivo)
    assert diag.visualizacion is None and "visualizacion" not in diag.to_dict()


def test_en_json_markdown_y_script_de_gdb():
    diag = _diag()
    completar_visualizacion(diag, Path("tp.c"), stdin_data="3\n")
    comando = "bishop trace tp.c --hasta-falla --html tp.falla.html --input entrada.txt"
    assert diag.to_dict()["visualizacion"]["comando"] == comando and "entrada.txt" in diag.visualizacion["nota"]
    assert comando in generar_seccion_markdown(diag)
    assert f"# Para verlo paso a paso en el navegador: {comando}" in generar_script_gdb(diag, Path("tp.c"))


def test_sin_bishop(monkeypatch, tmp_path):
    monkeypatch.setattr("hal.core.visualizacion.shutil.which", lambda nombre: None)
    ok, mensaje = generar_traza_html(_diag(), tmp_path / "tp.c", tmp_path / "x.html")
    assert not ok and "bishop no está instalado" in mensaje


@con_gdb
def test_cli_json_trae_el_comando(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "tp.c").write_text(SEGV, encoding="utf-8")
    res = runner.invoke(app, ["run", "tp.c", "--json"])
    datos = json.loads(res.stdout)
    assert datos["visualizacion"]["comando"] == "bishop trace tp.c --hasta-falla --html tp.falla.html"
    assert "visualizacion" not in json.loads(runner.invoke(app, ["run", "tp.c", "--json", "--pista"]).stdout)


@con_gdb
@con_bishop
def test_cli_traza_html(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "tp.c").write_text(SEGV, encoding="utf-8")
    res = runner.invoke(app, ["run", "tp.c", "--traza-html", "trazas/tp.html", "--json"])
    assert json.loads(res.stdout)["visualizacion"]["html"] == "trazas/tp.html"
    pagina = (tmp_path / "trazas" / "tp.html").read_text(encoding="utf-8")
    assert '"senal": "SIGSEGV"' in pagina
