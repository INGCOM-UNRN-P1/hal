# Changelog

Todos los cambios notables de este proyecto se documentan en este archivo.
Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/);
versiones según [SemVer](https://semver.org/lang/es/).

## [0.2.0] - 2026-09-28

Primera versión con registro de cambios; lo anterior está en el historial de git.

### Agregado

- **cli**: cumplir el contrato de línea de comandos de LINEAMIENTOS §3.2 (N-ECO-04) (`f289f5e`)

### Corregido

- **generate-reproducer**: compilar en un directorio temporal propio y citar ruta, entrada y argumentos (N-HAL-02) (`fb0a82a`)

### Documentación

- agregar el texto de la licencia GPL-3.0-or-later que declara pyproject (N-ECO-06) (`635fab1`)
- incorporar manual de uso integral y referencia tecnica (hal) (`83a5dc1`)

### Mantenimiento

- **calidad**: verificar errores de Python y dependencias vulnerables (N-ECO-08, N-ECO-13) (`e0bffe3`)
- **deps**: mover las dependencias de desarrollo a dependency-groups (N-ECO-07) (`bfef488`)
