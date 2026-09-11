"""Pruebas unitarias de las mejoras QoL en HAL (SIGFPE, Wild Pointers, Assert, Buffer Overflow, Exportadores)."""

from __future__ import annotations

import json
from pathlib import Path
from typer.testing import CliRunner

from hal.cli import app, _renderizar_diagnostico_rich
from hal.core.explainer import diagnosticar_crash
from hal.core.exporter import exportar_html, exportar_discussion_markdown
from hal.core.models import DiagnosticoCrash, StackFrame

runner = CliRunner()


def test_sigfpe_division_por_cero_con_divisor():
    frame = StackFrame(
        nivel=0,
        funcion="calcular_promedio",
        archivo="stats.c",
        linea=42,
        argumentos={"total": "100", "cantidad": "0"},
        variables_locales={"resultado": "0"},
    )
    diag = diagnosticar_crash(
        senal="SIGFPE",
        codigo_senal="FPE_INTDIV",
        direccion_memoria=None,
        frames=[frame],
    )
    assert diag.tipo_senal == "SIGFPE"
    assert diag.linea_falla == 42
    assert diag.variable_culpable in ("cantidad", "resultado")
    assert "División por Cero" in diag.causa_raiz_titulo
    assert "cantidad" in diag.explicacion or "divisor" in diag.explicacion


def test_assert_fallido_extraccion_condicion():
    gdb_out = 'Assertion `ptr != ((void *)0)\' failed.\n[1] + 123 abort (core dumped)'
    frame = StackFrame(nivel=0, funcion="procesar", archivo="nodo.c", linea=88)
    diag = diagnosticar_crash(
        senal="SIGABRT",
        codigo_senal=None,
        direccion_memoria=None,
        frames=[frame],
        gdb_output=gdb_out,
    )
    assert diag.tipo_senal == "SIGABRT"
    assert diag.es_assert_fallido is True
    assert diag.expresion_assert == "ptr != ((void *)0)"
    assert "Aserción Fallida" in diag.causa_raiz_titulo
    assert "ptr != ((void *)0)" in diag.explicacion


def test_buffer_overflow_ret_address():
    frame = StackFrame(nivel=0, funcion="??", archivo=None, linea=None)
    gdb_out = "Cannot access memory at address 0x4141414141414141\nProgram received signal SIGSEGV"
    diag = diagnosticar_crash(
        senal="SIGSEGV",
        codigo_senal="SEGV_MAPERR",
        direccion_memoria="0x4141414141414141",
        frames=[frame],
        gdb_output=gdb_out,
    )
    assert diag.es_buffer_overflow_ret is True
    assert "$rip/$eip Overflow" in diag.causa_raiz_titulo
    assert "dirección de retorno" in diag.explicacion


def test_wild_pointer_detection():
    frame = StackFrame(nivel=0, funcion="leer_nodo", archivo="lista.c", linea=19)
    diag = diagnosticar_crash(
        senal="SIGSEGV",
        codigo_senal="SEGV_MAPERR",
        direccion_memoria="0xcccccccccccccccc",
        frames=[frame],
        gdb_output="",
    )
    assert diag.es_wild_pointer is True
    assert "Wild Pointer" in diag.causa_raiz_titulo
    assert "no inicializado" in diag.explicacion


def test_exportador_html():
    frame = StackFrame(nivel=0, funcion="falla", archivo="main.c", linea=10, argumentos={"x": "5"})
    diag = DiagnosticoCrash(
        tipo_senal="SIGSEGV",
        codigo_senal="SEGV_MAPERR",
        direccion_memoria="0x0",
        causa_raiz_titulo="Desreferencia NULL",
        explicacion="Se desreferenció un puntero nulo.",
        accion_correctiva="Validar antes de acceder.",
        frames=[frame],
        es_crash=True,
    )
    html_out = exportar_html(diag)
    assert "<!DOCTYPE html>" in html_out
    assert "HAL Forensics Report" in html_out
    assert "Desreferencia NULL" in html_out
    assert "falla" in html_out


def test_exportador_discussion_markdown():
    frame = StackFrame(nivel=0, funcion="falla", archivo="main.c", linea=10, argumentos={"a": "1"})
    diag = DiagnosticoCrash(
        tipo_senal="SIGSEGV",
        codigo_senal="SEGV_MAPERR",
        direccion_memoria="0x0",
        causa_raiz_titulo="Desreferencia NULL",
        explicacion="Explicación detallada del crash.",
        accion_correctiva="Solución sugerida.",
        frames=[frame],
        es_crash=True,
    )
    md_out = exportar_discussion_markdown(diag)
    assert "### 🚨 Consulta de Depuración — Reporte Forense de HAL" in md_out
    assert "Desreferencia NULL" in md_out
    assert "`falla()`" in md_out


def test_renderizar_diagnostico_rich_top_frame_args(capsys):
    frame1 = StackFrame(nivel=0, funcion="__GI_raise", archivo="/usr/lib/libc.so.6", linea=1)
    frame2 = StackFrame(nivel=1, funcion="mi_funcion", archivo="app.c", linea=25, argumentos={"tam": "0", "ptr": "(nil)"})
    diag = DiagnosticoCrash(
        tipo_senal="SIGSEGV",
        codigo_senal="SEGV_MAPERR",
        direccion_memoria="0x0",
        causa_raiz_titulo="NULL Dereference",
        explicacion="Fallo nulo.",
        accion_correctiva="Revisar.",
        frames=[frame1, frame2],
        es_crash=True,
    )
    _renderizar_diagnostico_rich(diag, mostrar_todos_frames=False)
    # Debe ejecutarse sin error


def test_cli_report_html_y_discussion(tmp_path: Path):
    c_file = tmp_path / "simple.c"
    c_file.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    html_file = tmp_path / "report.html"
    disc_file = tmp_path / "disc.md"

    res1 = runner.invoke(app, ["report", str(c_file), "--html", str(html_file)])
    assert res1.exit_code == 0
    assert html_file.exists()
    assert "<!DOCTYPE html>" in html_file.read_text(encoding="utf-8")

    res2 = runner.invoke(app, ["report", str(c_file), "--discussion-md", str(disc_file)])
    assert res2.exit_code == 0
    assert disc_file.exists()
    assert "### 🚨 Consulta de Depuración" in disc_file.read_text(encoding="utf-8")
