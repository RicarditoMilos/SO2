import os
from datetime import datetime
import subprocess
import psycopg2
import sys # Necesario para print(file=sys.stderr)

# Ruta al log de alarmas 
LOG_ALARMAS = "/var/log/hips/alarmas.log"

USUARIOS_NO_ADMITIDOS = ["nobody", "apache", "www-data", "git"] 
sys.path.append("/opt/hips/modules")
from utils.db import conectar_db


def log_alarma(tipo, detalle, origen="sistema"):
    """
    Registra una alarma en el archivo de log y en la tabla alarma_log (si es posible).
    Detalle puede ser el usuario, o el error completo.
    """
    timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
    mensaje_log = f"{timestamp} :: {tipo} :: {origen} :: {detalle}\n"
    
    log_dir = os.path.dirname(LOG_ALARMAS)
    try:
        os.makedirs(log_dir, exist_ok=True)
    except OSError as e:
        print(f"ERROR: No se pudo crear el directorio de log {log_dir}: {e}", file=sys.stderr)
        # Si no podemos crear el directorio, no podemos escribir el log de archivo.
        return

    try:
        with open(LOG_ALARMAS, "a") as f:
            f.write(mensaje_log)
    except Exception as e:
        print(f"ERROR: No se pudo escribir en el archivo de log {LOG_ALARMAS}: {e}", file=sys.stderr)

    # Intentar insertar en la tabla alarma_log
    conn = conectar_db()
    if conn:
        try:
            cur = conn.cursor()
            
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS alarma_log (
                    id SERIAL PRIMARY KEY,
                    fecha TIMESTAMP DEFAULT now(),
                    tipo TEXT NOT NULL,
                    ip TEXT,
                    archivo TEXT -- En este contexto, 'archivo' podría ser el usuario o el detalle
                );
            """)
            conn.commit() # Commit para CREATE TABLE IF NOT EXISTS
            
            cur.execute("""
                INSERT INTO alarma_log (fecha, tipo, ip, archivo)
                VALUES (now(), %s, %s, %s);
            """, (tipo, origen, detalle)) # Usamos 'detalle' para la columna 'archivo'
            conn.commit()
            cur.close()
        except Exception as e:
            # Si falla la inserción en la DB, solo lo logueamos en el archivo y stderr
            print(f"ERROR_DB_ALARMA: Fallo al guardar alarma en DB: {e}", file=sys.stderr)
            try: # Intentar escribir el error de DB en el log de archivo también
                with open(LOG_ALARMAS, "a") as f:
                    f.write(f"{timestamp} :: ERROR_DB_ALARMA_FALLIDA :: {str(e)}\n")
            except:
                pass # Si ni siquiera podemos escribir el error de DB al log, no hay más que hacer.
        finally:
            if conn: # Asegurarse de cerrar la conexión
                conn.close()


def obtener_usuarios_conectados():
    """
    Ejecuta el comando 'who' y parsea su salida para obtener una lista de sesiones.
    """
    try:
        # who -H para encabezados, who -u para usuarios con tiempo de inactividad
        # 'who' por defecto muestra: USER TTY DATE TIME [COMMENT]
        # o USER TTY DATE TIME (HOST)
        # o USER TTY DATE TIME IDLE PID COMMENT (con -u)
        output = subprocess.check_output(["who"], universal_newlines=True)
        
        sesiones_parseadas = []
        for line in output.strip().split("\n"):
            if not line.strip(): # Saltar líneas vacías
                continue
            
            parts = line.strip().split(None, 4) # Split máximo 4 veces
            
            if len(parts) >= 4:
                usuario = parts[0]
                terminal = parts[1]
                fecha = parts[2] + " " + parts[3]
                origen = "localhost" # Valor por defecto
                
                if len(parts) > 4: # Si hay más partes, el origen puede estar aquí
                    # El origen puede venir como '(IP_O_HOSTNAME)'
                    origen_raw = parts[4].strip()
                    if origen_raw.startswith('(') and origen_raw.endswith(')'):
                        origen = origen_raw[1:-1] # Quitar paréntesis
                    elif origen_raw == 'console' or origen_raw == ':0': # Sesiones locales
                        origen = "local_console"
                    else: # Otros posibles formatos o nombres de host
                        origen = origen_raw

                sesiones_parseadas.append({
                    "usuario": usuario,
                    "terminal": terminal,
                    "fecha_login": fecha,
                    "origen": origen
                })
        return sesiones_parseadas
    except FileNotFoundError:
        error_msg = "ERROR: Comando 'who' no encontrado. Asegúrate de que esté en el PATH."
        print(error_msg, file=sys.stderr)
        log_alarma("ERROR_COMANDO_WHO", "sistema", error_msg)
        return []
    except Exception as e:
        error_msg = f"ERROR_WHO: Fallo al ejecutar 'who': {e}"
        print(error_msg, file=sys.stderr)
        log_alarma("ERROR_WHO", "sistema", error_msg)
        return []

def actualizar_sesiones_db(sesiones_actuales):
    """
    Actualiza la tabla sesiones_usuario con las sesiones actualmente activas.
    Borra las sesiones antiguas y añade las nuevas.
    """
    conn = conectar_db()
    if conn is None:
        return False

    try:
        cur = conn.cursor()
        
        # 1. Asegurarse de que la tabla 'sesiones_usuario' existe
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sesiones_usuario (
                id SERIAL PRIMARY KEY,
                usuario TEXT NOT NULL,
                origen TEXT,
                fecha TIMESTAMP DEFAULT now()
            );
        """)
        conn.commit() # Commit para CREATE TABLE IF NOT EXISTS

        # 2. Borrar todas las entradas existentes para limpiarlas y reemplazarlas con las actuales
        cur.execute("DELETE FROM sesiones_usuario;")
        conn.commit()

        # 3. Insertar las sesiones actuales
        for sesion in sesiones_actuales:
            cur.execute(
                "INSERT INTO sesiones_usuario (usuario, origen, fecha) VALUES (%s, %s, now());",
                (sesion['usuario'], sesion['origen']) # Usamos now() de la DB para la fecha
            )
        conn.commit()
        cur.close()
        return True
    except Exception as e:
        error_msg = f"ERROR_DB_SESIONES: Fallo al actualizar sesiones en DB: {e}"
        print(error_msg, file=sys.stderr)
        log_alarma("ERROR_DB_SESIONES", "sistema", error_msg)
        return False
    finally:
        if conn:
            conn.close()


def verificar_y_reportar_usuarios():
    """
    Verifica los usuarios conectados, registra sesiones, chequea no admitidos y genera un reporte.
    """
    reporte_salida = []
    reporte_salida.append("--- Verificación de Usuarios Conectados ---")

    sesiones = obtener_usuarios_conectados()
    
    if not sesiones:
        reporte_salida.append("No se detectaron usuarios conectados o hubo un error al obtener la información.")
        return "\n".join(reporte_salida)

    # Actualizar la base de datos con las sesiones actuales
    db_actualizada = actualizar_sesiones_db(sesiones)
    if not db_actualizada:
        reporte_salida.append("ADVERTENCIA: No se pudieron guardar las sesiones en la base de datos.")

    reporte_salida.append(f"Usuarios conectados actualmente ({len(sesiones)}):")
    
    usuarios_alerta = []

    for sesion in sesiones:
        usuario = sesion['usuario']
        origen = sesion['origen']
        terminal = sesion['terminal']
        fecha_login = sesion['fecha_login']

        reporte_salida.append(f"  - Usuario: {usuario}, Origen: {origen}, Terminal: {terminal}, Login: {fecha_login}")

        if usuario in USUARIOS_NO_ADMITIDOS:
            alerta_msg = f"USUARIO_NO_ADMITIDO: El usuario '{usuario}' inició sesión desde '{origen}'."
            log_alarma("USUARIO_NO_ADMITIDO", usuario, origen) # Log a archivo y DB
            usuarios_alerta.append(alerta_msg)
    
    if usuarios_alerta:
        reporte_salida.append("\n--- ALERTAS DE USUARIOS ---")
        reporte_salida.extend(usuarios_alerta)
    else:
        reporte_salida.append("\nNo se detectaron usuarios no admitidos.")

    reporte_salida.append("--- Fin de la Verificación ---")
    return "\n".join(reporte_salida)

if __name__ == "__main__":

    print(verificar_y_reportar_usuarios())


