"""Taxonomía común, esquema JSON del crash y script de gdb."""

import json
import shutil

import pytest
from typer.testing import CliRunner

from hal.cli import app
from hal.core.gdb_script import generar_script_gdb
from hal.core.models import DiagnosticoCrash
from hal.core.taxonomia import clasificar

runner = CliRunner()
con_gdb = pytest.mark.skipif(not (shutil.which("gcc") and shutil.which("gdb")), reason="hace falta gcc y gdb")


def _diag(**cambios):
    base = dict(tipo_senal="SIGSEGV", codigo_senal="SEGV_MAPERR", direccion_memoria="0x0",
                causa_raiz_titulo="Desreferencia de puntero nulo", explicacion="e", accion_correctiva="a",
                archivo_falla="tp.c", linea_falla=7, funcion_falla="cargar")
    base.update(cambios)
    return DiagnosticoCrash(**base)


def _comprobar_contra_el_esquema(datos):
    esquema = json.loads(runner.invoke(app, ["schema"]).stdout)
    assert set(esquema["required"]) <= set(datos)
    for h in datos["hallazgos"]:
        assert set(esquema["properties"]["hallazgos"]["items"]["required"]) <= set(h)


def test_salida_json_cumple_el_esquema_y_trae_hallazgos():
    datos = _diag().to_dict()
    _comprobar_contra_el_esquema(datos)
    (h,) = datos["hallazgos"]
    assert h["id"] == "hal:acceso-invalido" and h["categoria"] == "punteros" and h["linea"] == 7


@pytest.mark.parametrize("cambios, esperado", [
    (dict(codigo_senal="STACK_OVERFLOW"), ("recursion-sin-caso-base", "recursion")),
    (dict(es_use_after_free=True), ("uso-despues-de-free", "memoria")),
    (dict(tipo_senal="SIGFPE", codigo_senal="FPE_INTDIV"), ("division-por-cero", "numeros")),
    (dict(codigo_senal="DANGLING_STACK"), ("puntero-a-local", "punteros")),
])
def test_clasificacion(cambios, esperado):
    assert clasificar(_diag(**cambios)) == esperado


def test_sin_crash_no_hay_hallazgos():
    assert _diag(es_crash=False, tipo_senal="NINGUNA", codigo_senal="EXIT_SUCCESS").to_dict()["hallazgos"] == []


def test_script_de_gdb(tmp_path):
    script = generar_script_gdb(_diag(variable_culpable="lista"), tmp_path / "tp.c", ["datos.txt"])
    assert "break tp.c:7" in script and 'run "datos.txt"' in script and "print lista" in script
    recursion = generar_script_gdb(_diag(codigo_senal="STACK_OVERFLOW", funcion_falla="suma"), tmp_path / "tp.c")
    assert "break suma" in recursion


@con_gdb
def test_check_escribe_el_script(tmp_path):
    fuente = tmp_path / "nulo.c"
    fuente.write_text("#include <stddef.h>\nint main(void)\n{\n    int *p = NULL;\n    return *p;\n}\n", encoding="utf-8")
    res = runner.invoke(app, ["check", str(fuente), "--json", "--gdb-script", str(tmp_path / "nulo.gdb")])
    datos = json.loads(res.stdout)
    _comprobar_contra_el_esquema(datos)
    assert "break nulo.c:5" in (tmp_path / "nulo.gdb").read_text(encoding="utf-8")
