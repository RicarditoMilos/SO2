import psycopg2
import os
import sys
import configparser # <-- ¡Importa este módulo!

SECRETS_FILE = "/opt/hips/email_db.ini"


DB_USER = None
DB_PASSWORD = None
DB_NAME = None
DB_HOST = None
DB_PORT = None

# --- Función para cargar las credenciales de la DB desde el archivo ---
def load_db_credentials():
    global DB_USER, DB_PASSWORD, DB_NAME, DB_HOST, DB_PORT
    config = configparser.ConfigParser()
    try:
        # Intenta leer el archivo
        config.read_file(open(SECRETS_FILE))

        # Verifica si la sección [database] y todas las claves necesarias existen
        if 'database' in config and \
           'user' in config['database'] and \
           'password' in config['database'] and \
           'dbname' in config['database'] and \
           'host' in config['database'] and \
           'port' in config['database']:

            DB_USER = config['database']['user']
            DB_PASSWORD = config['database']['password']
            DB_NAME = config['database']['dbname']
            DB_HOST = config['database']['host']
            DB_PORT = config['database']['port']
            print(f"[DEBUG_DB_CREDS] Credenciales de DB cargadas del archivo.", file=sys.stderr)
        else:
            print(f"[DEBUG_DB_CREDS] ERROR: Formato incorrecto en '{SECRETS_FILE}'. Asegúrate de tener la sección [database] y todas las claves (user, password, dbname, host, port).", file=sys.stderr)
            # Si hay un error de formato, asegúrate de que las variables globales queden como None
            DB_USER, DB_PASSWORD, DB_NAME, DB_HOST, DB_PORT = None, None, None, None, None
    except FileNotFoundError:
        print(f"[DEBUG_DB_CREDS] ERROR: Archivo de credenciales '{SECRETS_FILE}' no encontrado. Asegúrate de crearlo y protegerlo con chmod 600.", file=sys.stderr)
        DB_USER, DB_PASSWORD, DB_NAME, DB_HOST, DB_PORT = None, None, None, None, None
    except Exception as e:
        print(f"[DEBUG_DB_CREDS] ERROR inesperado al leer credenciales de DB: {e}", file=sys.stderr)
        DB_USER, DB_PASSWORD, DB_NAME, DB_HOST, DB_PORT = None, None, None, None, None

# --- LLAMADA INICIAL PARA CARGAR CREDENCIALES AL PRINCIPIO DEL MÓDULO ---
# Esto es crucial: asegura que las variables globales DB_USER, DB_PASSWORD, etc.,
# se establezcan tan pronto como el módulo 'db.py' sea importado o ejecutado.
load_db_credentials()

def conectar_db():
    load_db_credentials()
    """Conecta a la base de datos PostgreSQL. Retorna la conexión o None si falla."""
    # Ahora verificamos si las credenciales fueron cargadas por load_db_credentials()
    if not DB_USER or not DB_PASSWORD or not DB_NAME or not DB_HOST or not DB_PORT:
        print("ERROR: Credenciales de base de datos no cargadas correctamente. Revise 'secrets.ini' y sus permisos.", file=sys.stderr)
        return None

    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT
        )
        return conn
    except Exception as e:
        error_msg = f"ERROR_DB_CONEXION: No se pudo conectar a la base de datos: {e}"
        print(error_msg, file=sys.stderr)
        return None



