"""Los dos crashes más típicos de P1 (QoL #474 y #472) y el programa que no termina.

Con una recursión sin caso base hal se rompía: gdb tardaba más que el timeout en volcar los cientos
de miles de marcos (`backtrace full`) y salía un TimeoutExpired sin capturar.
"""

import shutil

import pytest

from hal.core.explainer import diagnosticar_puntero_a_local
from hal.core.inspector import inspeccionar_fuente_o_binario, parsear_salida_gdb
from hal.core.models import DiagnosticoCrash

con_gdb = pytest.mark.skipif(not (shutil.which("gcc") and shutil.which("gdb")), reason="hace falta gcc y gdb")


def _fuente(tmp_path, nombre, texto):
    ruta = tmp_path / nombre
    ruta.write_text(texto, encoding="utf-8")
    return ruta


def test_profundidad_de_la_pila_decide_la_recursion():
    salida = ("Program received signal SIGSEGV, Segmentation fault.\n===GDB_PROFUNDIDAD===\nPROFUNDIDAD=5000+\n"
              "===GDB_BACKTRACE===\n#0  0x401136 in suma (n=-261879) at rec.c:3\n"
              "#1  0x40115e in suma (n=-261878) at rec.c:3\nCannot access memory at address 0x7ffe\n===GDB_LOCALS===\n")
    diag = parsear_salida_gdb(salida)
    assert diag.codigo_senal == "STACK_OVERFLOW" and "más de 5000" in diag.explicacion and "'suma'" in diag.explicacion


def test_puntero_a_local_usa_la_advertencia_del_compilador():
    diag = DiagnosticoCrash("SIGSEGV", "SEGV_MAPERR", "0x40048d", "Acceso inválido", "x", "y")
    advertencias = ("local.c: In function ‘crear’:\n"
                    "local.c:5:12: warning: function returns address of local variable [-Wreturn-local-addr]\n")
    diag = diagnosticar_puntero_a_local(diag, advertencias)
    assert diag.codigo_senal == "DANGLING_STACK" and "'crear'" in diag.explicacion and "línea 5" in diag.explicacion
    assert diagnosticar_puntero_a_local(DiagnosticoCrash("SIGSEGV", None, None, "t", "e", "a"), "").codigo_senal is None


@con_gdb
def test_recursion_infinita_real(tmp_path):
    fuente = _fuente(tmp_path, "rec.c", "int suma(int n)\n{\n    return n + suma(n - 1);\n}\n\n"
                                        "int main(void)\n{\n    return suma(5);\n}\n")
    diag = inspeccionar_fuente_o_binario(fuente)
    assert diag.codigo_senal == "STACK_OVERFLOW" and len(diag.frames) <= 30


@con_gdb
def test_puntero_a_local_real(tmp_path):
    fuente = _fuente(tmp_path, "local.c", "#include <stdio.h>\nint *crear(void)\n{\n    int valor = 42;\n"
                                          "    return &valor;\n}\n\nint main(void)\n{\n    int *p = crear();\n"
                                          "    printf(\"%d\\n\", *p);\n    return 0;\n}\n")
    diag = inspeccionar_fuente_o_binario(fuente)
    assert diag.es_crash and diag.codigo_senal == "DANGLING_STACK"


@con_gdb
def test_programa_que_no_termina(tmp_path, monkeypatch):
    from hal.core import inspector

    original = inspector.ejecutar_con_gdb
    monkeypatch.setattr(inspector, "ejecutar_con_gdb", lambda *a, **k: original(*a, **{**k, "timeout_segundos": 1}))
    fuente = _fuente(tmp_path, "lazo.c", "int main(void)\n{\n    volatile int i = 0;\n    while (i == 0)\n    {\n    }\n"
                                         "    return 0;\n}\n")
    diag = inspeccionar_fuente_o_binario(fuente)
    assert diag.codigo_senal == "SIN_TERMINAR" and not diag.es_crash
