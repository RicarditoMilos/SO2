import hashlib
import os
from datetime import datetime
import psycopg2
import sys # Importar sys para manejar sys.exit()

# Archivos críticos a monitorear
ARCHIVOS_CRITICOS = [
    "/etc/passwd",
    "/etc/shadow"
]

LOG_ALARMAS = "/var/log/hips/alarmas.log"

sys.path.append("/opt/hips/modules")
from utils.db import conectar_db
def obtener_hash_guardado(ruta):
    """Obtiene el hash guardado de un archivo desde la base de datos."""
    conn = conectar_db()
    if conn is None:
        return None
    try:
        cur = conn.cursor()
        cur.execute("SELECT hash FROM archivo_hash WHERE ruta = %s;", (ruta,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        return row[0] if row else None
    except Exception as e:
        error_msg = f"ERROR_DB_HASH_GET: Fallo al obtener hash para {ruta}: {e}"
        print(error_msg, file=sys.stderr)
        log_alarma("ERROR_DB_HASH_GET", f"{ruta} - Detalle: {e}")
        return None

def guardar_hash(ruta, hash_valor):
    """Guarda o actualiza el hash de un archivo en la base de datos."""
    conn = conectar_db()
    if conn is None:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO archivo_hash (ruta, hash, fecha)
            VALUES (%s, %s, now())
            ON CONFLICT (ruta)
            DO UPDATE SET hash = EXCLUDED.hash, fecha = now();
        """, (ruta, hash_valor))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        error_msg = f"ERROR_DB_HASH_SAVE: Fallo al guardar hash para {ruta}: {e}"
        print(error_msg, file=sys.stderr)
        log_alarma("ERROR_DB_HASH_SAVE", f"{ruta} - Detalle: {e}")

def calcular_hash(path):
    """Calcula el hash SHA256 de un archivo."""
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except FileNotFoundError:
        print(f"ERROR: Archivo no encontrado: {path}", file=sys.stderr)
        return None
    except PermissionError:
        print(f"ERROR: Permiso denegado para leer el archivo: {path}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"ERROR: Fallo al calcular hash de {path}: {e}", file=sys.stderr)
        return None

def log_alarma(tipo, detalle):
    """Registra una alarma en el archivo de log."""
   
    ip = "localhost"
    timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
    mensaje = f"{timestamp} :: {tipo} :: {ip} :: {detalle}\n"
    
    log_dir = os.path.dirname(LOG_ALARMAS)
    if not os.path.exists(log_dir):
        # Intentar crear el directorio. Si falla por permisos, os.makedirs lanza una excepción.
        try:
            os.makedirs(log_dir, exist_ok=True)
        except OSError as e:
            print(f"ERROR: No se pudo crear el directorio de log {log_dir}: {e}", file=sys.stderr)
            # No podemos escribir el log si el directorio no existe o no hay permisos
            return

    try:
        with open(LOG_ALARMAS, "a") as f:
            f.write(mensaje)
    except Exception as e:
        print(f"ERROR: No se pudo escribir en el archivo de log {LOG_ALARMAS}: {e}", file=sys.stderr)


def verificar_integridad():
    """
    Verifica la integridad de los archivos críticos y devuelve un informe.
    """
    reporte_salida = []
    
    # Asegurarse de que la tabla de la DB existe
    conn = conectar_db()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS archivo_hash (
                    ruta VARCHAR(255) PRIMARY KEY,
                    hash VARCHAR(64) NOT NULL,
                    fecha TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            reporte_salida.append(f"ADVERTENCIA: No se pudo asegurar la tabla 'archivo_hash' en la DB: {e}")
            log_alarma("ERROR_DB_TABLA", f"No se pudo crear/verificar tabla: {e}")
            conn.close() # Asegurarse de cerrar la conexión si falla
            
    else:
        reporte_salida.append("ERROR: No se pudo conectar a la base de datos para verificación de integridad.")
        # Si no hay DB, no podemos hacer el monitoreo basado en hashes previos
        return "\n".join(reporte_salida)


    reporte_salida.append("--- Verificación de Integridad de Archivos Críticos ---")

    for archivo in ARCHIVOS_CRITICOS:
        hash_actual = calcular_hash(archivo)
        
        if hash_actual is None:
            # calcular_hash ya imprime errores a stderr. Aquí solo registramos alarma.
            log_alarma("ERROR_ACCESO_ARCHIVO", f"No se pudo leer/acceder a {archivo}")
            reporte_salida.append(f"  [ERROR] No se pudo leer o acceder al archivo: {archivo}. Posibles permisos.")
            continue

        hash_guardado = obtener_hash_guardado(archivo)

        if hash_guardado:
            if hash_actual != hash_guardado:
                mensaje_alarma = f"MODIFICACION_DETECTADA: El archivo '{archivo}' ha sido MODIFICADO."
                log_alarma("MODIFICACION_DETECTADA", archivo)
                reporte_salida.append(f"  [ALERTA] {mensaje_alarma}")
            else:
                reporte_salida.append(f"  [OK] Archivo '{archivo}' sin cambios detectados.")
        else:
            # Primera vez que se procesa el archivo
            mensaje_info = f"HASH_NO_EXISTENTE_EN_DB: Primer registro para '{archivo}'. Hash guardado."
            log_alarma("HASH_INICIAL_GUARDADO", archivo) # Tipo de alarma más informativo
            reporte_salida.append(f"  [INFO] {mensaje_info}")

        guardar_hash(archivo, hash_actual)

    reporte_salida.append("--- Fin de la Verificación ---")
    return "\n".join(reporte_salida)

if __name__ == "__main__":
  
    print(verificar_integridad())


