"""Módulo de consejos pedagógicos y buenas prácticas defensivas en HAL."""

from __future__ import annotations

from typing import Dict, List


CONSEJOS_DIDACTICOS: List[Dict[str, str]] = [
    {
        "tema": "Inicialización Defensiva de Punteros",
        "regla": "Inicializá siempre todo puntero en NULL al momento de declararlo.",
        "explicacion": "En C, una variable local sin inicializar contiene 'basura' (valores residuales de la memoria de la pila). Si intentás desreferenciarla o chequear `if (p != NULL)`, el chequeo pasará pero la dirección será inválida, provocando un Segfault inmediato.",
        "ejemplo_correcto": "int *ptr = NULL;\nFILE *f = NULL;",
        "ejemplo_incorrecto": "int *ptr; // Peligro: contiene dirección basura",
    },
    {
        "tema": "Protección contra Use-After-Free (Dangling Pointers)",
        "regla": "Asigná inmediatamente NULL al puntero luego de liberarlo con free().",
        "explicacion": "Liberar memoria con `free(p)` le avisa al sistema operativo que el bloque está disponible, pero `p` sigue guardando la dirección antigua. Si luego llamás a `free(p)` de nuevo tendrás un Double Free, o si leés `*p` tendrás Use-After-Free. Hacer `p = NULL;` evita ambos errores porque `free(NULL)` es inocuo en C.",
        "ejemplo_correcto": "free(buffer);\nbuffer = NULL;",
        "ejemplo_incorrecto": "free(buffer); // buffer sigue apuntando a memoria liberada",
    },
    {
        "tema": "Verificación del Valor de Retorno de Asignaciones",
        "regla": "Comprobá siempre si malloc, calloc o fopen retornaron NULL antes de usar el puntero.",
        "explicacion": "Si el sistema se queda sin memoria o el archivo solicitado no existe, la función retornará NULL. Acceder a un puntero sin verificar el retorno causa SIGSEGV (SEGV_MAPERR) en la primera lectura o escritura.",
        "ejemplo_correcto": "char *cad = malloc(100);\nif (cad == NULL) {\n    return ERROR_MEMORIA;\n}",
        "ejemplo_incorrecto": "char *cad = malloc(100);\ncad[0] = 'A'; // Si malloc falló, crash!",
    },
    {
        "tema": "Límites de Arreglos y Lazos",
        "regla": "En C los arreglos de N elementos se indexan de 0 a N-1.",
        "explicacion": "Escribir en `vec[N]` sobrepasa el búfer por 1 elemento (Off-by-one). En el stack esto pisa la dirección de retorno de la función o variables adyacentes; en el heap corrompe los metadatos de glibc.",
        "ejemplo_correcto": "for (size_t i = 0; i < N; i++) { ... }",
        "ejemplo_incorrecto": "for (size_t i = 0; i <= N; i++) { ... } // Error off-by-one",
    },
    {
        "tema": "Terminador Nulo en Cadenas de Caracteres",
        "regla": "Reservá siempre 1 byte adicional para el '\\0' final al manipular strings.",
        "explicacion": "Las funciones estándar de strings (`strlen`, `printf %s`, `strcmp`) avanzan en memoria byte a byte hasta encontrar el terminador `\\0`. Si la cadena no está terminada, continuarán leyendo memoria adyacente hasta causar un Segfault o volcar datos privados.",
        "ejemplo_correcto": "char *str = malloc(longitud + 1);\nstr[longitud] = '\\0';",
        "ejemplo_incorrecto": "char *str = malloc(longitud); // Falta espacio para '\\0'",
    },
]


def obtener_consejos() -> List[Dict[str, str]]:
    """Devuelve la lista completa de consejos didácticos de programación defensiva."""
    return CONSEJOS_DIDACTICOS
