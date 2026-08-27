"""Tests unitarios para el motor de inspección y diagnóstico de HAL."""

from pathlib import Path
import pytest
from hal.core.explainer import diagnosticar_crash
from hal.core.inspector import compilar_codigo_c, parsear_salida_gdb, inspeccionar_fuente_o_binario
from hal.core.models import StackFrame


def test_diagnosticar_null_pointer():
    """Verifica el diagnóstico de NULL pointer dereference."""
    frames = [
        StackFrame(
            nivel=0,
            funcion="invertir_vector",
            archivo="main.c",
            linea=15,
            argumentos={"vec": "0x0", "n": "5"},
            variables_locales={"i": "0"},
        )
    ]
    diag = diagnosticar_crash(
        senal="SIGSEGV",
        codigo_senal="SEGV_MAPERR",
        direccion_memoria="0x0",
        frames=frames,
    )
    assert diag.es_crash is True
    assert "NULL" in diag.causa_raiz_titulo
    assert diag.archivo_falla == "main.c"
    assert diag.linea_falla == 15
    assert diag.variable_culpable == "vec"


def test_diagnosticar_stack_overflow():
    """Verifica la detección de recursión infinita / stack overflow."""
    frames = [
        StackFrame(nivel=i, funcion="fibonacci", archivo="fib.c", linea=10)
        for i in range(40)
    ]
    diag = diagnosticar_crash(
        senal="SIGSEGV",
        codigo_senal="SEGV_ACCERR",
        direccion_memoria="0x7fffff7ff000",
        frames=frames,
    )
    assert diag.es_crash is True
    assert "Stack Overflow" in diag.causa_raiz_titulo
    assert "recursivas" in diag.explicacion


def test_diagnosticar_fpe_division_zero():
    """Verifica el diagnóstico de división entera por cero."""
    frames = [
        StackFrame(nivel=0, funcion="calcular_promedio", archivo="calc.c", linea=20)
    ]
    diag = diagnosticar_crash(
        senal="SIGFPE",
        codigo_senal="FPE_INTDIV",
        direccion_memoria=None,
        frames=frames,
    )
    assert diag.es_crash is True
    assert "División" in diag.causa_raiz_titulo
    assert diag.tipo_senal == "SIGFPE"


def test_compilacion_y_ejecucion_segfault_real(tmp_path):
    """Compila y corre un código C con segfault real."""
    codigo_c = """
    #include <stdio.h>

    void provocar_segfault(int* p) {
        *p = 42; // Fallo aquí
    }

    int main(void) {
        int* ptr = NULL;
        provocar_segfault(ptr);
        return 0;
    }
    """
    fuente = tmp_path / "segfault.c"
    fuente.write_text(codigo_c, encoding="utf-8")

    diag = inspeccionar_fuente_o_binario(fuente)
    assert diag.es_crash is True
    assert diag.tipo_senal == "SIGSEGV"
    assert "NULL" in diag.causa_raiz_titulo or "0x0" in str(diag.direccion_memoria)
