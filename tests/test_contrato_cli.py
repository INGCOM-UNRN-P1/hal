"""Contrato de línea de comandos (LINEAMIENTOS §3.2, N-ECO-04): el test reutilizable de yutani (N-ECO-14)."""

from __future__ import annotations

from typer.testing import CliRunner
from yutani.testing import pruebas_de_contrato

from hal import __version__
from hal.cli import app

test_ayuda, test_version, test_doctor_json = pruebas_de_contrato(app)


def test_la_version_nombra_la_herramienta():
    assert CliRunner().invoke(app, ["--version"]).output.strip() == f"hal {__version__}"


def test_la_ayuda_esta_en_espanol():
    salida = CliRunner().invoke(app, ["--help"], env={"COLUMNS": "150"}).output
    assert "Comandos" in salida and "Muestra esta ayuda y sale." in salida
