"""Modo pista (`--pista` o P1_PISTA=1): la falla y la función, sin la línea, los valores ni la corrección."""

import json

from typer.testing import CliRunner

import hal.cli as cli
from hal.core.models import DiagnosticoCrash, StackFrame
from hal.core.pista import diagnostico_en_pista, explicacion_sin_ubicacion

runner = CliRunner()


def _crash() -> DiagnosticoCrash:
    return DiagnosticoCrash(
        tipo_senal="SIGSEGV", codigo_senal="SEGV_MAPERR", direccion_memoria="0x0",
        causa_raiz_titulo="Desreferencia de Puntero Nulo",
        explicacion=("El programa intentó leer la memoria del puntero 'v'.\nEn la línea 5, se desreferenció un "
                     "puntero que apuntaba a NULL.\nCausas comunes: un puntero no fue inicializado."),
        accion_correctiva="Verificá `if (v != NULL)` antes de usar v[0].",
        archivo_falla="segv.c", linea_falla=5, funcion_falla="primero", variable_culpable="v",
        frames=[StackFrame(nivel=0, funcion="primero", archivo="segv.c", linea=5, argumentos={"v": "0x0"},
                           variables_locales={"i": "0"}),
                StackFrame(nivel=1, funcion="main", archivo="segv.c", linea=11)],
        registros={"rip": "0x401136"},
    )


def test_diagnostico_en_pista():
    pista = diagnostico_en_pista(_crash())
    assert pista.pista and pista.funcion_falla == "primero" and pista.causa_raiz_titulo
    assert pista.linea_falla is None and pista.variable_culpable is None and pista.accion_correctiva == ""
    assert [(f.funcion, f.linea, f.argumentos, f.variables_locales) for f in pista.frames] == [
        ("primero", None, {}, {}), ("main", None, {}, {})]
    assert pista.registros == {} and pista.explicacion == "Causas comunes: un puntero no fue inicializado."
    # Una ejecución sin falla queda igual.
    limpio = DiagnosticoCrash(tipo_senal="NONE", codigo_senal=None, direccion_memoria=None,
                              causa_raiz_titulo="Sin fallas", explicacion="Terminó bien.", accion_correctiva="",
                              es_crash=False)
    assert diagnostico_en_pista(limpio) is limpio


def test_explicacion_sin_ubicacion():
    assert explicacion_sin_ubicacion("Falló en la línea 12. Revisá los límites.", None) == "Revisá los límites."
    assert explicacion_sin_ubicacion("El índice `i` se pasó. Pasa en bucles.", "i") == "Pasa en bucles."


def test_cli_en_modo_pista(tmp_path, monkeypatch):
    fuente = tmp_path / "segv.c"
    fuente.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    monkeypatch.setattr(cli, "inspeccionar_fuente_o_binario", lambda **k: _crash())
    monkeypatch.delenv("P1_PISTA", raising=False)
    datos = json.loads(runner.invoke(cli.app, ["check", str(fuente), "--json", "--pista"]).stdout)
    assert datos["pista"] is True and datos["linea_falla"] is None and datos["accion_correctiva"] == ""

    monkeypatch.setenv("P1_PISTA", "1")
    res = runner.invoke(cli.app, ["check", str(fuente)], env={"COLUMNS": "300"})
    assert "segv.c, en la función primero()" in res.output and "segv.c:5" not in res.output
    assert "Cómo solucionarlo" not in res.output and "Modo pista" in res.output
