"""Tests unitarios para el motor de inspección y diagnóstico de HAL."""

from hal.core.explainer import diagnosticar_crash
from hal.core.inspector import diagnostico_desde_captura, inspeccionar_fuente_o_binario
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


def test_crash_json_schema_version_and_compatibility():
    """Verifica que to_dict emita schema_version y claves compatibles con spunkmeyer."""
    frames = [StackFrame(nivel=0, funcion="main", archivo="app.c", linea=42)]
    diag = diagnosticar_crash("SIGSEGV", "SEGV_MAPERR", "0x0", frames)
    data = diag.to_dict()
    assert data["schema_version"] == "1.0.0"
    assert data["archivo_falla"] == "app.c"
    assert data["linea_falla"] == 42
    assert data["archivo"] == "app.c"
    assert data["linea"] == 42



def _marco(nivel, funcion, archivo, linea, argumentos=None, locales=None):
    return {"nivel": nivel, "funcion": funcion, "archivo": archivo, "linea": linea,
            "argumentos": argumentos or {}, "variables_locales": locales or {}}


def test_captura_con_rutas_de_windows():
    # gdb de MSYS2 informa la ruta con la unidad (N-ECO-22); la captura la trae tal cual.
    diag = diagnostico_desde_captura({"terminacion": "senal", "senal": "SIGSEGV", "frames": [
        _marco(0, "invertir_vector", "C:/Users/alumno/tp/main.c", 15, {"vec": "0x0", "n": "5"}),
        _marco(1, "main", "C:/Users/alumno/tp/main.c", 27),
    ]})
    assert [(f.funcion, f.archivo, f.linea) for f in diag.frames[:2]] == [
        ("invertir_vector", "C:/Users/alumno/tp/main.c", 15),
        ("main", "C:/Users/alumno/tp/main.c", 27),
    ]


def test_captura_sin_siginfo_como_en_windows():
    diag = diagnostico_desde_captura({"terminacion": "senal", "senal": "SIGSEGV", "si_code": None, "direccion": None,
                                      "frames": [_marco(0, "main", "C:/Users/alumno/tp/tp.c", 5, None,
                                                        {"p": "0x0", "contador": "10"})]})
    assert diag.tipo_senal == "SIGSEGV"
    assert diag.codigo_senal == "SEGV_MAPERR"
    assert diag.frames[0].variables_locales == {"p": "0x0", "contador": "10"}
    assert diag.variable_culpable == "p"
    assert "NULL" in diag.causa_raiz_titulo
