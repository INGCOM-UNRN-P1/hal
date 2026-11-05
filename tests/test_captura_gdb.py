"""El diagnóstico a partir de la API Python de gdb (ola R3). Cada caso corre un programa real."""

import importlib
import os
import shutil
import subprocess
import sys
import types

import pytest

from hal.core import inspector
from hal.core.doctor import gdb_tiene_python, obtener_estado_doctor
from hal.core.inspector import _terminacion_sin_gdb, diagnostico_desde_captura, inspeccionar_fuente_o_binario

con_gdb = pytest.mark.skipif(not (shutil.which("gcc") and shutil.which("gdb")), reason="hace falta gcc y gdb")
con_gcc = pytest.mark.skipif(shutil.which("gcc") is None, reason="hace falta gcc")
# Dependen de cómo arma la pila gcc en Linux (canario, recursión de main, marco de main).
solo_linux = pytest.mark.skipif(os.name == "nt", reason="la pila de MinGW se comporta distinto")


def _correr(tmp_path, codigo, **opciones):
    fuente = tmp_path / "prog.c"
    fuente.write_text(codigo, encoding="utf-8")
    return inspeccionar_fuente_o_binario(fuente, **opciones)


@con_gdb
def test_lo_que_imprime_el_programa_no_cambia_el_diagnostico(tmp_path):
    diag = _correr(tmp_path, '#include <stdio.h>\nint main(void) {\n    printf("exited normally\\n");\n    fflush(stdout);\n'
                             "    int *p = NULL;\n    *p = 1;\n    return 0;\n}\n")
    assert diag.es_crash and diag.tipo_senal == "SIGSEGV" and diag.linea_falla == 6


@con_gdb
def test_el_programa_no_puede_inventar_una_senal(tmp_path):
    diag = _correr(tmp_path, '#include <stdio.h>\nint main(void) {\n    printf("Program received signal SIGABRT, Aborted.\\n'
                             '#0  0x1 in falso (x=1) at f.c:9\\n");\n    return 0;\n}\n')
    assert not diag.es_crash and diag.frames == []


@con_gdb
@pytest.mark.parametrize("codigo", [1, 3, 12])
def test_un_codigo_de_retorno_distinto_de_cero_no_es_exito(tmp_path, codigo):
    diag = _correr(tmp_path, f"int main(void) {{\n    return {codigo};\n}}\n")
    assert not diag.es_crash and diag.codigo_senal == "EXIT_FAILURE" and str(codigo) in diag.causa_raiz_titulo


@con_gdb
def test_terminar_bien(tmp_path):
    diag = _correr(tmp_path, "int main(void) {\n    return 0;\n}\n")
    assert not diag.es_crash and diag.codigo_senal == "EXIT_SUCCESS"


@con_gdb
def test_la_direccion_es_la_de_la_falla(tmp_path):
    diag = _correr(tmp_path, "int main(void) {\n    int *p = (int *)0;\n    *p = 1;\n    return 0;\n}\n")
    assert diag.direccion_memoria == "0x0" and diag.variable_culpable == "p"


@con_gdb
def test_un_puntero_invalido_no_es_un_desborde_del_retorno(tmp_path):
    diag = _correr(tmp_path, "int main(void) {\n    char *p = (char *)0x1234;\n    *p = 'a';\n    return 0;\n}\n")
    assert diag.codigo_senal == "WILD_POINTER" and diag.direccion_memoria == "0x1234"
    assert diag.pila is None


@con_gdb
def test_comas_e_igual_dentro_de_una_cadena(tmp_path):
    diag = _correr(tmp_path, 'void g(const char *s) {\n    char *q = 0;\n    *q = s[0];\n}\n'
                             'int main(void) {\n    g("a, b=c");\n    return 0;\n}\n')
    assert list(diag.frames[0].argumentos) == ["s"] and 'a, b=c' in diag.frames[0].argumentos["s"]


CON_STRUCT = """#include <string.h>
typedef struct { char nombre[16]; const char *texto; int edad; struct { int a; } in; } P;
int main(void) {
    P x;
    memset(&x, 0, sizeof x);
    strcpy(x.nombre, "a}b,c=d");
    x.texto = "{\\"raro\\", 2}";
    x.edad = 3;
    char *q = NULL;
    *q = 1;
    return 0;
}
"""


@con_gdb
@pytest.mark.parametrize("opciones", [{}, {"struct_nombre": "x"}])
def test_struct_con_llaves_y_comillas_en_las_cadenas(tmp_path, opciones):
    diag = _correr(tmp_path, CON_STRUCT, **opciones)
    assert diag.struct_nombre == "x"
    assert diag.campos_struct["nombre"] == {"valor": '"a}b,c=d"', "tipo": "char [16]"}
    assert "raro" in diag.campos_struct["texto"]["valor"]
    assert diag.campos_struct["edad"]["valor"] == "3"
    assert "a = 0" in diag.campos_struct["in"]["valor"]


@con_gdb
def test_struct_de_un_marco_que_no_es_el_mas_interno(tmp_path):
    diag = _correr(tmp_path, "#include <string.h>\ntypedef struct { int a; } T;\nint main(void) {\n    T t = { 5 };\n"
                             "    const char *s = NULL;\n    return (int)strlen(s) + t.a;\n}\n", struct_nombre="t")
    assert diag.campos_struct["a"]["valor"] == "5"


@con_gdb
def test_struct_apuntado_por_un_puntero_nulo(tmp_path):
    diag = _correr(tmp_path, "typedef struct { int a; } T;\nint main(void) {\n    T *t = 0;\n    return t->a;\n}\n",
                   struct_nombre="t")
    assert diag.es_crash and not diag.campos_struct


@con_gdb
def test_argumentos_y_entrada_llegan_al_programa(tmp_path):
    diag = _correr(tmp_path, '#include <stdio.h>\n#include <string.h>\nint main(int argc, char **argv) {\n'
                             '    char b[8] = "";\n    fgets(b, 8, stdin);\n'
                             '    return argc == 2 && strcmp(argv[1], "uno dos") == 0 && b[0] == \'z\' ? 7 : 1;\n}\n',
                   args=["uno dos"], stdin_data="zeta\n")
    assert "7" in diag.causa_raiz_titulo


@solo_linux
@con_gdb
@pytest.mark.parametrize("proteccion", ["-fstack-protector-strong", "-fno-stack-protector"])
def test_desborde_de_un_arreglo_local(tmp_path, proteccion):
    fuente = tmp_path / "copia.c"
    fuente.write_text('#include <string.h>\n#include <stdio.h>\nvoid copiar(const char *s) {\n    char b[8];\n'
                      '    strcpy(b, s);\n    printf("%s\\n", b);\n}\nint main(void) {\n'
                      '    copiar("una cadena bastante mas larga que ocho bytes de verdad");\n    return 0;\n}\n',
                      encoding="utf-8")
    binario = tmp_path / "copia"
    subprocess.run(["gcc", "-g", "-O0", "-U_FORTIFY_SOURCE", proteccion, str(fuente), "-o", str(binario)],
                   check=True, capture_output=True)

    diag = inspeccionar_fuente_o_binario(binario)

    assert diag.codigo_senal == "RET_ADDR_CORRUPTED" and diag.funcion_falla == "copiar"
    assert diag.pila["causa"] == "desborde-de-buffer-local"
    assert diag.pila["canario"] == (proteccion == "-fstack-protector-strong")


@solo_linux
@con_gdb
def test_marco_de_main_demasiado_grande(tmp_path):
    diag = _correr(tmp_path, "int main(void) {\n    volatile int v[20000000];\n    v[0] = 1;\n    v[19999999] = 2;\n"
                             "    return v[0];\n}\n")
    assert diag.codigo_senal == "STACK_FRAME_TOO_LARGE" and not diag.es_wild_pointer


@solo_linux
@con_gdb
def test_recursion_de_main_consigo_misma(tmp_path):
    diag = _correr(tmp_path, "int main(int argc, char **argv) {\n    return main(argc + 1, argv) + 1;\n}\n")
    assert diag.codigo_senal == "STACK_OVERFLOW"


@con_gdb
def test_los_registros_llegan_en_hexadecimal(tmp_path):
    diag = _correr(tmp_path, "int main(void) {\n    int *p = 0;\n    return *p;\n}\n")
    assert diag.registros and all(v.startswith("0x") for v in diag.registros.values())


def test_una_captura_parcial_sirve():
    diag = diagnostico_desde_captura({"terminacion": "senal", "senal": "SIGSEGV", "pila_corrupta": True,
                                      "errores": ["frames: se rompió"]})
    assert diag.codigo_senal == "RET_ADDR_CORRUPTED"


@pytest.mark.parametrize("retorno, esperado", [
    (0, {"terminacion": "salida", "codigo_salida": 0}),
    (3, {"terminacion": "salida", "codigo_salida": 3}),
    (-11, {"terminacion": "senal", "senal": "SIGSEGV"}),
    (139, {"terminacion": "senal", "senal": "SIGSEGV"}),
    (0xC0000005, {"terminacion": "senal", "senal": "SIGSEGV"}),
    (0xC0000094, {"terminacion": "senal", "senal": "SIGFPE"}),
])
def test_terminacion_sin_gdb(retorno, esperado):
    assert _terminacion_sin_gdb(retorno) == esperado


@con_gcc
@pytest.mark.parametrize("codigo, crash", [("int main(void) { return 0; }\n", False),
                                           ("int main(void) { int *p = 0; return *p; }\n", True)])
def test_sin_gdb_dice_que_no_hay_traza_y_no_inventa_una_falla(tmp_path, monkeypatch, codigo, crash):
    original = shutil.which
    monkeypatch.setattr(inspector.shutil, "which", lambda n: None if n == "gdb" else original(n))
    diag = _correr(tmp_path, codigo)
    assert diag.es_crash == crash
    assert ("no hay traza" in diag.explicacion) == crash


@con_gdb
def test_gdb_sin_python_cae_a_la_ejecucion_directa(tmp_path, monkeypatch):
    monkeypatch.setattr(inspector, "SCRIPT_CAPTURA", tmp_path / "no_existe.py")
    diag = _correr(tmp_path, "int main(void) { int *p = 0; return *p; }\n")
    assert diag.es_crash and diag.tipo_senal == "SIGSEGV" and "no hay traza" in diag.explicacion


def test_doctor_detecta_gdb_sin_python(monkeypatch):
    assert gdb_tiene_python(None) is False
    monkeypatch.setattr("hal.core.doctor.gdb_tiene_python", lambda gdb: False)
    chequeo = next(c for c in obtener_estado_doctor()["chequeos"] if c["nombre"] == "gdb (Python)")
    assert not chequeo["ok"] and "soporte de Python" in chequeo["detalle"]


@con_gdb
def test_el_codigo_de_error_no_se_presenta_como_exito(tmp_path, capsys):
    from hal.core.exporter import exportar_html
    from hal.core.resumen import resumir
    from hal.presentacion import _renderizar_diagnostico_rich, generar_seccion_markdown

    diag = _correr(tmp_path, "int main(void) {\n    return 2;\n}\n")

    assert "TERMINÓ CON ERROR" in exportar_html(diag) and "EJECUCIÓN EXITOSA" not in exportar_html(diag)
    assert "código de retorno 2" in resumir(diag)["que_paso"]
    assert "Ejecución Exitosa" not in generar_seccion_markdown(diag)
    _renderizar_diagnostico_rich(diag)
    assert "Ejecución Exitosa" not in capsys.readouterr().out


def _script_con_gdb_falso(monkeypatch, evaluar):
    falso = types.ModuleType("gdb")
    falso.error = type("error", (RuntimeError,), {})
    falso.MemoryError = type("MemoryError", (falso.error,), {})
    falso.FRAME_UNWIND_NO_REASON, falso.FRAME_UNWIND_NULL_ID, falso.FRAME_UNWIND_OUTERMOST = 0, 1, 2
    falso.parse_and_eval = evaluar
    monkeypatch.setitem(sys.modules, "gdb", falso)
    monkeypatch.delenv("HAL_CAPTURA_CONFIG", raising=False)
    monkeypatch.delitem(sys.modules, "hal.gdb_captura", raising=False)
    return importlib.import_module("hal.gdb_captura"), falso


def test_siginfo_de_windows(monkeypatch):
    # La forma de EXCEPTION_RECORD es la de windows_get_siginfo_type (gdb/windows-tdep.c).
    def evaluar(expresion):
        if expresion == "$_siginfo.AccessViolationInformation.Address":
            return 0x1234
        raise sys.modules["gdb"].error("There is no member named si_code.")

    captura, _ = _script_con_gdb_falso(monkeypatch, evaluar)

    assert captura.siginfo("SIGSEGV") == (1, "0x1234")


def test_siginfo_de_linux(monkeypatch):
    captura, _ = _script_con_gdb_falso(monkeypatch, lambda _: {"si_code": 2, "_sifields": {"_sigfault": {"si_addr": 16}}})

    assert captura.siginfo("SIGSEGV") == (2, "0x10")


def test_siginfo_de_una_senal_sin_direccion(monkeypatch):
    captura, _ = _script_con_gdb_falso(monkeypatch, lambda _: pytest.fail("no hace falta leerlo"))

    assert captura.siginfo("SIGABRT") == (None, None)


@con_gdb
@pytest.mark.parametrize("retorno, salida_de_hal", [(0, 0), (2, 1)])
def test_hal_devuelve_el_resultado_del_programa(tmp_path, retorno, salida_de_hal):
    import json

    from typer.testing import CliRunner

    from hal.cli import app

    fuente = tmp_path / "prog.c"
    fuente.write_text(f"int main(void) {{\n    return {retorno};\n}}\n", encoding="utf-8")

    res = CliRunner().invoke(app, ["run", str(fuente), "--json"])

    assert res.exit_code == salida_de_hal
    datos = json.loads(res.stdout)
    assert datos["es_crash"] is False
    assert [(h["codigo"], h["severidad"]) for h in datos["hallazgos"]] == (
        [("codigo-de-error", "advertencia")] if retorno else [])
