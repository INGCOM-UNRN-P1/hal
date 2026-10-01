"""hal en Windows acepta el binario sin .exe y compila al .exe (N-ECO-10).

`gcc -o prog` escribe prog.exe en Windows y la terminal de MSYS2 acepta ./prog. hal devolvía la ruta
sin .exe (inexistente) y sus comandos rechazaban `prog` con un error de uso.
"""

from __future__ import annotations

import shutil

import pytest
import typer

import hal.core.inspector as inspector
from hal.cli import _existente
from hal.core.inspector import compilar_codigo_c


def test_acepta_el_binario_sin_exe_solo_en_windows(tmp_path, monkeypatch):
    (tmp_path / "prog.exe").write_bytes(b"MZ")
    monkeypatch.setattr(inspector, "ES_WINDOWS", True)
    assert _existente(tmp_path / "prog") == tmp_path / "prog.exe"
    monkeypatch.setattr(inspector, "ES_WINDOWS", False)
    with pytest.raises(typer.BadParameter, match="No existe"):
        _existente(tmp_path / "prog")


@pytest.mark.skipif(shutil.which("gcc") is None, reason="requiere gcc")
def test_compilar_devuelve_un_binario_que_existe(tmp_path, monkeypatch):
    fuente = tmp_path / "ok.c"
    fuente.write_text("int main(void) { return 0; }\n")
    for windows in (False, True):
        monkeypatch.setattr(inspector, "ES_WINDOWS", windows)
        ok, binario, _ = compilar_codigo_c(fuente, tmp_path)
        assert ok and binario.is_file()
        assert binario.suffix == (".exe" if windows else "")
