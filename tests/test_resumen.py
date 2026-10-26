"""Ola 10: `hal explain --resumen`, la causa en el código C sin jerga del sistema operativo."""

import json
import shutil

import pytest
from typer.testing import CliRunner

from hal.cli import app
from hal.core.models import DiagnosticoCrash
from hal.core.pista import diagnostico_en_pista
from hal.core.resumen import _TEXTOS, JERGA, resumir, texto_resumen

runner = CliRunner()
con_gdb = pytest.mark.skipif(not (shutil.which("gcc") and shutil.which("gdb")), reason="hace falta gcc y gdb")

SEGV = "#include <stdio.h>\nint main(void)\n{\n    int *p = NULL;\n    printf(\"%d\\n\", *p);\n    return 0;\n}\n"


def _diag(tmp_path=None, **cambios):
    archivo = None
    if tmp_path is not None:
        archivo = tmp_path / "tp.c"
        archivo.write_text(SEGV, encoding="utf-8")
    base = dict(tipo_senal="SIGSEGV", codigo_senal="SEGV_MAPERR", direccion_memoria="0x0",
                causa_raiz_titulo="Desreferencia de Puntero Nulo (NULL Pointer Dereference)",
                explicacion="SIGSEGV en 0x0 (SEGV_MAPERR)", accion_correctiva="a",
                archivo_falla=str(archivo) if archivo else "tp.c", linea_falla=5, funcion_falla="main",
                variable_culpable="p")
    base.update(cambios)
    return DiagnosticoCrash(**base)


def test_resumen_de_un_puntero_nulo(tmp_path):
    r = resumir(_diag(tmp_path))
    assert r["donde"] == "tp.c:5, en la función main()" and r["codigo"] == 'printf("%d\\n", *p);'
    assert "el puntero 'p' que vale NULL" in r["que_paso"] and "verificá que no sea NULL" in r["que_hacer"]
    assert r["para_repasar"] == "https://ingcom-unrn-p1.github.io/punteros"
    texto = texto_resumen(r)
    assert texto.splitlines()[0] == "Se cortó en tp.c:5, en la función main():" and len(texto.splitlines()) == 5


@pytest.mark.parametrize("codigo", sorted(_TEXTOS))
def test_ningun_texto_usa_jerga(codigo, monkeypatch):
    monkeypatch.setattr("hal.core.resumen.clasificar", lambda d: (codigo, "punteros"))
    texto = texto_resumen(resumir(_diag(direccion_memoria="0x7ffe1234", pila={"funcion": "f"}))).lower()
    assert not [p for p in JERGA if p in texto], texto


def test_pista_sin_linea_variable_ni_que_hacer(tmp_path):
    r = resumir(diagnostico_en_pista(_diag(tmp_path)))
    assert r["donde"] == "tp.c, en la función main()" and r["codigo"] is None and r["que_hacer"] is None
    assert "'p'" not in r["que_paso"] and r["para_repasar"]


def test_sin_crash_y_con_error():
    assert resumir(_diag(es_crash=False, tipo_senal="NINGUNA"))["que_paso"] == "El programa terminó sin cortarse."
    error = resumir(_diag(es_crash=False, tipo_senal="ERROR", causa_raiz_titulo="Fallo de Compilación con GCC"))
    assert "No se pudo ejecutar" in error["que_paso"] and "daedalus" in error["que_hacer"]


@con_gdb
def test_cli_explain_resumen(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "tp.c").write_text(SEGV, encoding="utf-8")
    res = runner.invoke(app, ["explain", "tp.c", "--resumen"])
    assert res.exit_code == 1 and res.stdout.startswith("Se cortó en tp.c:5, en la función main():")
    assert not [p for p in JERGA if p in res.stdout.lower()]
    datos = json.loads(runner.invoke(app, ["explain", "tp.c", "--resumen", "--json"]).stdout)
    assert datos["resumen"]["donde"].startswith("tp.c:5") and datos["hallazgos"][0]["id"] == "hal:acceso-invalido"
