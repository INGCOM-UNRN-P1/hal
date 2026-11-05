"""El programa ejecutado bajo gdb y lo que quedó al terminar, desde la API Python de gdb.

Corre dentro de gdb (`gdb -batch -x`), con su Python y no con el de hal: sólo usa la biblioteca
estándar y el módulo gdb. Lee la configuración de un JSON (ruta en HAL_CAPTURA_CONFIG) y deja el
resultado en otro. La salida de gdb no se interpreta y la del programa no se mezcla con los datos,
así que un `printf` del estudiante no puede falsear el diagnóstico.

La forma del resultado:

- `terminacion`: "senal" o "salida". Con "salida", `codigo_salida`; None si gdb no lo informó.
- `senal`, `si_code`, `direccion`: la señal y, si es de memoria o aritmética, su `siginfo`.
- `profundidad`, `profundidad_cortada`: cuántos marcos había, hasta MAX_PROFUNDIDAD.
- `pila_corrupta`: la pila no se puede recorrer hasta `main`.
- `marcos_bytes`: [función, bytes] de los primeros MAX_MEDIDOS marcos (ver `hal/core/pila.py`).
- `frames`: hasta MAX_MARCOS, con función, archivo, línea, argumentos y variables locales.
- `registros`: nombre → valor en hexadecimal, del marco más interno.
- `struct`: {"nombre", "campos"}, el struct pedido o el primero entre las variables locales.
- `errores`: lo que no se pudo leer; el resto de la captura sigue siendo válido.
"""

import json
import os

import gdb

MAX_MARCOS = 30
MAX_MEDIDOS = 40
# Con una recursión infinita hay cientos de miles de marcos: contarlos tardaba más que el timeout.
MAX_PROFUNDIDAD = 5000
SENALES_CON_DIRECCION = ("SIGSEGV", "SIGBUS", "SIGFPE", "SIGILL")
ERRORES = (gdb.error, gdb.MemoryError, RuntimeError, UnicodeDecodeError, ValueError)
# Por qué gdb dejó de recorrer la pila, cuando no hay nada raro (un hilo no pasa por `main`).
FINES_NORMALES = (gdb.FRAME_UNWIND_NO_REASON, gdb.FRAME_UNWIND_NULL_ID, gdb.FRAME_UNWIND_OUTERMOST)


def texto(valor):
    try:
        return valor.format_string()
    except ERRORES as exc:
        return "<error: %s>" % exc


def anterior(marco):
    """El marco que llamó a `marco`; None si no hay, o si la pila está rota."""
    try:
        return marco.older()
    except ERRORES:
        return None


def termina_el_programa(marco, siguiente):
    """Si `marco` es el `main` de más afuera. Se recorre más allá de `main` para medir su marco, pero
    lo que está por fuera es del arranque de la biblioteca."""
    return marco.name() == "main" and (siguiente is None or siguiente.name() != "main")


def recorrer():
    """(marcos del programa, profundidad, cortada, si la pila se pudo recorrer hasta main)."""
    marcos, marco, llego_a_main = [], gdb.newest_frame(), False
    while marco is not None and len(marcos) < MAX_PROFUNDIDAD:
        siguiente = anterior(marco)
        marcos.append(marco)
        if termina_el_programa(marco, siguiente):
            llego_a_main = True
            break
        marco = siguiente
    cortada = not llego_a_main and marco is not None and len(marcos) >= MAX_PROFUNDIDAD
    return marcos, cortada, llego_a_main


def pila_rota(marcos, cortada, llego_a_main):
    """Si la pila está pisada. El motivo de parada no alcanza: gdb 15 dice «no reason» en toda la
    cadena y gdb 17 un error. Lo que vale en los dos es que, sin llegar a `main`, después de un marco
    del programa vienen direcciones sin símbolo, que son lo que quedó en lugar del retorno."""
    if llego_a_main or cortada or not marcos:
        return False
    try:
        if marcos[-1].unwind_stop_reason() not in FINES_NORMALES:
            return True
        return any(marcos[i].find_sal().symtab is not None and marcos[i + 1].name() is None
                   for i in range(len(marcos) - 1))
    except ERRORES:
        return True


def medir(marcos):
    """Bytes de cada marco: la distancia entre su `sp` y el del marco que lo llamó."""
    medidos = []
    for marco in marcos[:MAX_MEDIDOS]:
        try:
            siguiente = anterior(marco)
            tamanio = int(siguiente.read_register("sp")) - int(marco.read_register("sp")) if siguiente else 0
        except ERRORES:
            tamanio = 0
        medidos.append([marco.name() or "??", tamanio])
    return medidos


def variables(marco):
    """(argumentos, locales) visibles en el marco, de los bloques internos hacia la función."""
    argumentos, locales, vistos = {}, {}, set()
    try:
        bloque = marco.block()
    except RuntimeError:  # sin información de depuración, como en la biblioteca
        return argumentos, locales
    while bloque is not None:
        for simbolo in bloque:
            if simbolo.name in vistos or not (simbolo.is_argument or simbolo.is_variable):
                continue
            vistos.add(simbolo.name)
            try:
                valor = texto(simbolo.value(marco))
            except ERRORES as exc:
                valor = "<error reading variable: %s>" % exc
            (argumentos if simbolo.is_argument else locales)[simbolo.name] = valor
        if bloque.function is not None:
            break
        bloque = bloque.superblock
    return argumentos, locales


def describir(marcos):
    """Los primeros MAX_MARCOS. Uno sin nombre (`??`, un salto a una dirección inválida) no aporta."""
    frames = []
    for nivel, marco in enumerate(marcos[:MAX_MARCOS]):
        nombre = marco.name()
        if not nombre:
            continue
        sal = marco.find_sal()
        argumentos, locales = variables(marco)
        frames.append({"nivel": nivel, "funcion": nombre, "archivo": sal.symtab.filename if sal.symtab else None,
                       "linea": sal.line if sal.symtab and sal.line else None, "argumentos": argumentos,
                       "variables_locales": locales})
    return frames


def registros(marco):
    try:
        nombres = [r.name for r in marco.architecture().registers("general")]
    except (AttributeError, *ERRORES):  # gdb anterior a 11
        return {}
    valores = {}
    for nombre in nombres:
        try:
            valores[nombre] = hex(int(marco.read_register(nombre)) & 0xFFFFFFFFFFFFFFFF)
        except ERRORES:
            continue
    return valores


def siginfo_linux():
    info = gdb.parse_and_eval("$_siginfo")
    return int(info["si_code"]), hex(int(info["_sifields"]["_sigfault"]["si_addr"]))


def siginfo_windows():
    """En Windows `$_siginfo` es un EXCEPTION_RECORD, con la dirección en una unión sin nombre. No
    distingue dirección sin mapear de permiso denegado: se informa como SEGV_MAPERR (1)."""
    return 1, hex(int(gdb.parse_and_eval("$_siginfo.AccessViolationInformation.Address")))


def siginfo(senal):
    """(si_code, dirección de la falla), si la señal los tiene."""
    if senal not in SENALES_CON_DIRECCION:
        return None, None
    for leer in (siginfo_linux, siginfo_windows):
        try:
            return leer()
        except ERRORES:
            continue
    return None, None


def campos_de(valor):
    """Los campos del struct `valor` o del que apunta; None si es otra cosa o no se puede leer."""
    tipo = valor.type.strip_typedefs()
    if tipo.code == gdb.TYPE_CODE_PTR:
        valor = valor.dereference()
        tipo = valor.type.strip_typedefs()
    if tipo.code not in (gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION):
        return None
    valor.fetch_lazy()
    return {f.name: {"valor": texto(valor[f]), "tipo": str(f.type)} for f in tipo.fields() if f.name}


def struct_pedido(expresion, marcos):
    """El struct `expresion`, en el marco más interno donde exista (una falla dentro de la biblioteca
    deja el marco 0 fuera del código del estudiante)."""
    for marco in marcos[:MAX_MARCOS]:
        try:
            marco.select()
            campos = campos_de(gdb.parse_and_eval(expresion))
        except ERRORES:
            continue
        if campos:
            return {"nombre": expresion, "campos": campos}
    return None


def primer_struct_local(marco):
    try:
        bloque = marco.block()
    except RuntimeError:
        return None
    for simbolo in bloque:
        try:
            if simbolo.is_variable and simbolo.type.strip_typedefs().code == gdb.TYPE_CODE_STRUCT:
                campos = campos_de(simbolo.value(marco))
                if campos:
                    return {"nombre": simbolo.name, "campos": campos}
        except ERRORES:
            continue
    return None


def intentar(resultado, clave, funcion, *argumentos):
    """`resultado[clave] = funcion(…)`. Con la pila pisada cualquier lectura puede fallar, y lo demás
    sigue sirviendo para el diagnóstico."""
    try:
        resultado[clave] = funcion(*argumentos)
    except Exception as exc:  # noqa: BLE001 - una falla acá no puede costar toda la captura
        resultado.setdefault("errores", []).append("%s: %s" % (clave, exc))


def capturar_senal(senal, config):
    resultado = {"terminacion": "senal", "senal": senal}
    intentar(resultado, "siginfo", siginfo, senal)
    resultado["si_code"], resultado["direccion"] = resultado.pop("siginfo", (None, None))
    try:
        marcos, cortada, llego_a_main = recorrer()
    except Exception as exc:  # noqa: BLE001
        resultado["errores"] = ["marcos: %s" % exc]
        resultado["pila_corrupta"] = True
        return resultado
    resultado.update(profundidad=len(marcos), profundidad_cortada=cortada)
    intentar(resultado, "pila_corrupta", pila_rota, marcos, cortada, llego_a_main)
    intentar(resultado, "marcos_bytes", medir, marcos)
    intentar(resultado, "frames", describir, marcos)
    if marcos:
        intentar(resultado, "registros", registros, marcos[0])
    if config.get("struct"):
        intentar(resultado, "struct", struct_pedido, config["struct"], marcos)
    if not resultado.get("struct") and marcos:
        intentar(resultado, "struct", primer_struct_local, marcos[0])
    return resultado


def principal():
    config = json.load(open(os.environ["HAL_CAPTURA_CONFIG"], encoding="utf-8"))
    for orden in ("set pagination off", "set confirm off", "set debuginfod enabled off", "set style enabled off",
                  "set backtrace past-main on", "set print null-stop on"):
        try:
            gdb.execute(orden, to_string=True)
        except gdb.error:
            pass
    for clave, valor in config.get("entorno", {}).items():
        gdb.execute("set environment %s %s" % (clave, valor), to_string=True)
    if config.get("argumentos"):
        gdb.execute("set args " + config["argumentos"], to_string=True)

    fin = {}

    def al_detenerse(evento):
        if isinstance(evento, gdb.SignalEvent):
            fin["senal"] = evento.stop_signal

    def al_salir(evento):
        fin["codigo"] = getattr(evento, "exit_code", None)

    gdb.events.stop.connect(al_detenerse)
    gdb.events.exited.connect(al_salir)
    gdb.execute("run", to_string=True)

    if "senal" in fin:
        resultado = capturar_senal(fin["senal"], config)
    else:
        resultado = {"terminacion": "salida", "codigo_salida": fin.get("codigo")}
    # En ASCII: la codificación por omisión del Python de gdb depende del locale.
    with open(config["resultado"], "w", encoding="utf-8") as salida:
        json.dump(resultado, salida)
    try:
        gdb.execute("kill", to_string=True)
    except gdb.error:
        pass


if "HAL_CAPTURA_CONFIG" in os.environ:
    principal()
