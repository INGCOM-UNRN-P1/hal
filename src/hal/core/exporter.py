"""Módulo de exportación de diagnósticos de fallos en HAL (HTML interactivo y Markdown GitHub Discussions)."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Optional
from hal.core.models import DiagnosticoCrash


def exportar_html(diag: DiagnosticoCrash, titulo_documento: str = "Diagnóstico Forense de HAL") -> str:
    """Genera un reporte HTML autocontenido e interactivo a partir de un DiagnosticoCrash."""
    estado_color = "#e63946" if diag.es_crash else "#2a9d8f"
    estado_texto = f"FALLO: {diag.tipo_senal}" if diag.es_crash else "EJECUCIÓN EXITOSA"

    frames_rows = []
    for f in diag.frames:
        loc = f"{Path(f.archivo).name}:{f.linea}" if f.archivo and f.linea else (f.archivo or "—")
        args_s = html.escape(", ".join(f"{k}={v}" for k, v in f.argumentos.items())) if f.argumentos else "—"
        locals_s = html.escape(", ".join(f"{k}={v}" for k, v in f.variables_locales.items())) if f.variables_locales else "—"
        frames_rows.append(
            f"<tr><td>#{f.nivel}</td><td><code>{html.escape(f.funcion)}()</code></td><td>{args_s}</td><td>{html.escape(loc)}</td><td>{locals_s}</td></tr>"
        )
    frames_table = "\n".join(frames_rows) if frames_rows else "<tr><td colspan='5'>Sin traza de llamadas disponible</td></tr>"

    struct_rows = []
    if diag.campos_struct:
        for campo, info in diag.campos_struct.items():
            if isinstance(info, dict):
                t_str = info.get("tipo", "campo")
                v_str = str(info.get("valor", "—"))
            else:
                t_str = "valor"
                v_str = str(info)
            struct_rows.append(
                f"<tr><td><code>{html.escape(campo)}</code></td><td>{html.escape(t_str)}</td><td><code>{html.escape(v_str)}</code></td></tr>"
            )
    struct_table = "\n".join(struct_rows) if struct_rows else "<tr><td colspan='3'>Sin variables estructuradas inspeccionadas</td></tr>"

    regs_rows = []
    if diag.registros:
        for reg, val in sorted(diag.registros.items()):
            regs_rows.append(f"<tr><td><strong>{html.escape(reg)}</strong></td><td><code>{html.escape(str(val))}</code></td></tr>")
    regs_table = "\n".join(regs_rows) if regs_rows else "<tr><td colspan='2'>Sin registros capturados</td></tr>"

    html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(titulo_documento)}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --card-bg: #1e293b;
            --text: #f8fafc;
            --muted: #94a3b8;
            --border: #334155;
            --accent: {estado_color};
            --font-mono: 'JetBrains Mono', 'Fira Code', Menlo, Consolas, monospace;
        }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 2rem;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        header {{
            border-bottom: 2px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .badge {{
            background: var(--accent);
            color: white;
            padding: 0.4rem 0.8rem;
            border-radius: 6px;
            font-weight: bold;
            font-size: 0.9rem;
            text-transform: uppercase;
        }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        h2 {{
            margin-top: 0;
            color: #38bdf8;
            font-size: 1.25rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.5rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.95rem;
            margin-top: 1rem;
        }}
        th, td {{
            text-align: left;
            padding: 0.6rem 0.8rem;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            color: var(--muted);
            font-weight: 600;
        }}
        code {{
            background: #090d16;
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-family: var(--font-mono);
            font-size: 0.88rem;
            color: #f43f5e;
        }}
        pre {{
            background: #090d16;
            padding: 1rem;
            border-radius: 6px;
            overflow-x: auto;
            font-family: var(--font-mono);
            font-size: 0.9rem;
            color: #a5b4fc;
        }}
        .nav-tabs {{
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1rem;
        }}
        .tab-btn {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            color: var(--muted);
            padding: 0.5rem 1rem;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
        }}
        .tab-btn.active {{
            background: #38bdf8;
            color: #0f172a;
            border-color: #38bdf8;
        }}
        .tab-content {{
            display: none;
        }}
        .tab-content.active {{
            display: block;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1 style="margin: 0; font-size: 1.8rem;">🤖 HAL Forensics Report</h1>
                <p style="margin: 0.2rem 0 0 0; color: var(--muted);">{html.escape(diag.causa_raiz_titulo)}</p>
            </div>
            <span class="badge">{html.escape(estado_texto)}</span>
        </header>

        <div class="card">
            <h2>📘 Explicación Pedagógica</h2>
            <p>{html.escape(diag.explicacion).replace(chr(10), '<br>')}</p>
            <div style="margin-top: 1rem;">
                <h3 style="color: #4ade80; margin-bottom: 0.5rem;">🛠️ Acción Correctiva Sugerida</h3>
                <pre>{html.escape(diag.accion_correctiva)}</pre>
            </div>
        </div>

        <div class="nav-tabs">
            <button class="tab-btn active" onclick="showTab('tab-stack')">🥞 Call Stack</button>
            <button class="tab-btn" onclick="showTab('tab-struct')">📦 Struct Memory</button>
            <button class="tab-btn" onclick="showTab('tab-regs')">⚡ Registros CPU</button>
        </div>

        <div id="tab-stack" class="tab-content active card">
            <h2>Pila de Llamadas (Backtrace)</h2>
            <table>
                <thead>
                    <tr><th>#</th><th>Función</th><th>Argumentos</th><th>Ubicación</th><th>Variables Locales</th></tr>
                </thead>
                <tbody>
                    {frames_table}
                </tbody>
            </table>
        </div>

        <div id="tab-struct" class="tab-content card">
            <h2>Inspección de Structs ({html.escape(diag.struct_nombre or 'N/A')})</h2>
            <table>
                <thead>
                    <tr><th>Campo</th><th>Tipo</th><th>Valor en Memoria</th></tr>
                </thead>
                <tbody>
                    {struct_table}
                </tbody>
            </table>
        </div>

        <div id="tab-regs" class="tab-content card">
            <h2>Registros del Procesador</h2>
            <table>
                <thead>
                    <tr><th>Registro</th><th>Valor Hexadecimal</th></tr>
                </thead>
                <tbody>
                    {regs_table}
                </tbody>
            </table>
        </div>
    </div>

    <script>
        function showTab(tabId) {{
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            event.target.classList.add('active');
        }}
    </script>
</body>
</html>
"""
    return html_content


def exportar_discussion_markdown(diag: DiagnosticoCrash) -> str:
    """Genera plantilla de reporte en formato Markdown lista para GitHub Discussions o Foro de Cátedra."""
    lines = []
    lines.append("### 🚨 Consulta de Depuración — Reporte Forense de HAL\n")
    lines.append(f"**Causa Raíz Identificada:** {diag.causa_raiz_titulo}\n")
    lines.append(f"- **Señal del Sistema:** `{diag.tipo_senal}` ({diag.codigo_senal or 'SIN_CODIGO'})")
    if diag.direccion_memoria:
        lines.append(f"- **Dirección Involucrada:** `{diag.direccion_memoria}`")
    if diag.archivo_falla and diag.linea_falla:
        lines.append(f"- **Punto de Quiebre:** `{Path(diag.archivo_falla).name}:{diag.linea_falla}` (en `{diag.funcion_falla or 'desconocida'}`)")
    if diag.variable_culpable:
        lines.append(f"- **Variable Señalada:** `{diag.variable_culpable}`")
    lines.append("")

    lines.append("#### 📝 Descripción del Problema")
    lines.append(diag.explicacion)
    lines.append("")

    if diag.frames:
        lines.append("#### 🥞 Traza de la Pila (Call Stack)")
        lines.append("| Frame # | Función | Argumentos | Ubicación |")
        lines.append("| :---: | :--- | :--- | :--- |")
        for f in diag.frames:
            if f.archivo and (f.archivo.startswith("/usr/") or f.archivo.startswith("/lib")):
                continue
            loc = f"`{Path(f.archivo).name}:{f.linea}`" if f.archivo and f.linea else (f.archivo or "—")
            args_s = ", ".join(f"{k}={v}" for k, v in f.argumentos.items()) if f.argumentos else "—"
            lines.append(f"| {f.nivel} | `{f.funcion}()` | {args_s} | {loc} |")
        lines.append("")

    lines.append("#### 💡 Hipótesis de Solución")
    lines.append(diag.accion_correctiva)
    lines.append("")

    lines.append("---")
    lines.append("*Plantilla generada automáticamente por HAL para facilitar la consulta técnica.*")
    return "\n".join(lines)
