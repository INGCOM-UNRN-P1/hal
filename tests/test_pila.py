"""Ola 10: recursión sin caso base, caso base inalcanzable, marco gigante y búfer local, diferenciados."""

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from hal.cli import app
from hal.core.models import DiagnosticoCrash, StackFrame
from hal.core.pila import _tamanio, caso_base_segun_sebastian, diagnosticar_pila, parsear_marcos
from hal.core.pista import diagnostico_en_pista
from hal.core.taxonomia import clasificar

runner = CliRunner()
con_gdb = pytest.mark.skipif(not (shutil.which("gcc") and shutil.which("gdb")), reason="hace falta gcc y gdb")
MIB = 1024 * 1024

SIN_CASO_BASE = "int suma(int n)\n{\n    return n + suma(n - 1);\n}\n\nint main(void)\n{\n    return suma(10);\n}\n"
CASO_BASE_SALTEADO = ("int factorial(int n)\n{\n    if (n == 0) {\n        return 1;\n    }\n"
                      "    return n * factorial(n - 2);\n}\n\nint main(void)\n{\n    return factorial(5);\n}\n")
ARREGLO_ENORME = ("int main(void)\n{\n    int datos[5000000];\n    for (int i = 0; i < 5000000; i++) {\n"
                  "        datos[i] = i;\n    }\n    return datos[10];\n}\n")
BUFER_LOCAL = ("#include <stdio.h>\n#include <string.h>\nvoid copiar(const char *origen)\n{\n    char destino[8];\n"
               "    strcpy(destino, origen);\n    printf(\"%s\\n\", destino);\n}\n\nint main(void)\n{\n"
               "    copiar(\"una cadena bastante mas larga que ocho bytes, mucho mas larga\");\n    return 0;\n}\n")


def _diag(**cambios):
    base = dict(tipo_senal="SIGSEGV", codigo_senal="STACK_OVERFLOW", direccion_memoria=None,
                causa_raiz_titulo="Stack Overflow", explicacion="Se agotó la pila.", accion_correctiva="a",
                archivo_falla="rec.c", linea_falla=3, funcion_falla="suma",
                frames=[StackFrame(nivel=i, funcion="suma", argumentos={"n": str(-100 - i)}) for i in range(5)])
    base.update(cambios)
    return DiagnosticoCrash(**base)


@pytest.fixture
def limite_8_mib(monkeypatch):
    monkeypatch.setattr("hal.core.pila.limite_de_pila", lambda: (8 * MIB, "ulimit -s"))


def test_parsear_marcos_y_tamanios():
    assert parsear_marcos("x\nMARCOS=suma:32,suma:32,main:20000032\n") == [
        ("suma", 32), ("suma", 32), ("main", 20000032)]
    assert parsear_marcos("sin marcos") == []
    assert (_tamanio(8 * MIB), _tamanio(20000032), _tamanio(1536), _tamanio(40)) == (
        "8 MiB", "19,1 MiB", "1,5 KiB", "40 bytes")


def test_recursion_sin_caso_base(monkeypatch, limite_8_mib):
    monkeypatch.setattr("hal.core.pila.caso_base_segun_sebastian", lambda fuente, funcion: False)
    diag = diagnosticar_pila(_diag(), "PROFUNDIDAD=5000+\nMARCOS=suma:32,suma:32,suma:32")
    assert diag.pila["causa"] == "recursion-sin-caso-base" and diag.pila["marco_bytes"] == 32
    assert diag.pila["profundidad_maxima_estimada"] == 262144 and diag.pila["profundidad"] == 5000
    assert "no tiene caso base" in diag.causa_raiz_titulo and "32 bytes" in diag.explicacion
    assert "262.144" in diag.explicacion and "más de 5.000" in diag.explicacion
    assert "Escribí el caso base" in diag.accion_correctiva
    assert clasificar(diag) == ("recursion-sin-caso-base", "recursion")


def test_caso_base_inalcanzable_muestra_los_argumentos(monkeypatch, limite_8_mib):
    monkeypatch.setattr("hal.core.pila.caso_base_segun_sebastian", lambda fuente, funcion: True)
    diag = diagnosticar_pila(_diag(), "MARCOS=suma:48,suma:48")
    assert diag.pila["causa"] == "caso-base-inalcanzable" and "nunca llega a su caso base" in diag.causa_raiz_titulo
    assert "En las últimas llamadas: n = -103, -102, -101, -100." in diag.explicacion
    assert "n <= 0" in diag.accion_correctiva
    assert clasificar(diag) == ("caso-base-inalcanzable", "recursion")
    # En modo pista no quedan los valores.
    assert "últimas llamadas" not in diagnostico_en_pista(diag).explicacion


def test_sin_sebastian_queda_el_conteo(monkeypatch, limite_8_mib):
    monkeypatch.setattr("hal.core.pila.caso_base_segun_sebastian", lambda fuente, funcion: None)
    diag = diagnosticar_pila(_diag(), "MARCOS=suma:32")
    assert diag.pila["causa"] == "recursion-infinita" and diag.explicacion.startswith("Se agotó la pila.")
    assert "entran unas 262.144" in diag.explicacion


def test_marco_gigante(limite_8_mib):
    diag = diagnosticar_pila(_diag(codigo_senal="SEGV_MAPERR", funcion_falla="main", frames=[]),
                             "MARCOS=main:20000032")
    assert diag.codigo_senal == "STACK_FRAME_TOO_LARGE" and diag.pila["causa"] == "arreglo-local-demasiado-grande"
    assert "19,1 MiB" in diag.explicacion and "No es una recursión" in diag.explicacion
    assert "malloc" in diag.accion_correctiva
    assert clasificar(diag) == ("arreglo-local-demasiado-grande", "arreglos")
    # Un SIGSEGV común (marcos chicos) no cambia.
    comun = diagnosticar_pila(_diag(codigo_senal="SEGV_MAPERR", causa_raiz_titulo="NULL"), "MARCOS=main:48")
    assert comun.causa_raiz_titulo == "NULL" and comun.pila is None


@pytest.mark.parametrize("salida, codigo, canario", [
    ("*** stack smashing detected ***: terminated", "SIGABRT", True),
    ("", "RET_ADDR_CORRUPTED", False),
])
def test_bufer_local(salida, codigo, canario):
    diag = diagnosticar_pila(_diag(tipo_senal="SIGABRT" if canario else "SIGSEGV", codigo_senal=codigo,
                                   funcion_falla="copiar"), salida)
    assert diag.pila == {"causa": "desborde-de-buffer-local", "funcion": "copiar", "canario": canario}
    assert "No se llenó la pila" in diag.explicacion and ("canario" in diag.explicacion) == canario
    assert "fgets" in diag.accion_correctiva and clasificar(diag) == ("desborde-de-buffer", "arreglos")


def test_caso_base_segun_sebastian(tmp_path):
    pytest.importorskip("sebastian")
    (tmp_path / "a.c").write_text(SIN_CASO_BASE, encoding="utf-8")
    (tmp_path / "b.c").write_text(CASO_BASE_SALTEADO, encoding="utf-8")
    assert caso_base_segun_sebastian(tmp_path / "a.c", "suma") is False
    assert caso_base_segun_sebastian(tmp_path / "b.c", "factorial") is True
    assert caso_base_segun_sebastian(tmp_path / "a.c", "otra") is None
    assert caso_base_segun_sebastian(None, "suma") is None


def _correr(tmp_path, monkeypatch, codigo):
    monkeypatch.chdir(tmp_path)
    Path("p.c").write_text(codigo, encoding="utf-8")
    return json.loads(runner.invoke(app, ["run", "p.c", "--json"]).stdout)


@con_gdb
@pytest.mark.parametrize("codigo, causa", [
    (SIN_CASO_BASE, "recursion-sin-caso-base"),
    (CASO_BASE_SALTEADO, "caso-base-inalcanzable"),
    (ARREGLO_ENORME, "arreglo-local-demasiado-grande"),
    (BUFER_LOCAL, "desborde-de-buffer-local"),
])
def test_de_punta_a_punta(tmp_path, monkeypatch, codigo, causa):
    if causa.startswith(("recursion-sin", "caso-base")):
        pytest.importorskip("sebastian")
    if causa == "arreglo-local-demasiado-grande":
        resource = pytest.importorskip("resource")
        blando, _ = resource.getrlimit(resource.RLIMIT_STACK)
        if blando == resource.RLIM_INFINITY or blando > 16 * MIB:
            pytest.skip("la pila del sistema es ilimitada o muy grande")
    datos = _correr(tmp_path, monkeypatch, codigo)
    assert datos["pila"]["causa"] == causa, datos["causa_raiz_titulo"]
