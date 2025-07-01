import os
from datetime import datetime
import smtplib
from email.message import EmailMessage
import sys
import configparser

LOG_ALARMAS = "/var/log/hips/alarmas.log"

SECRETS_FILE = "/opt/hips/modules/email_db.ini"

GMAIL_USER = None
GMAIL_APP_PASSWORD = None

# --- Función para cargar las credenciales desde el archivo ---
def load_credentials():
    global GMAIL_USER, GMAIL_APP_PASSWORD
    config = configparser.ConfigParser()
    try:
        # Intenta leer el archivo
        config.read_file(open(SECRETS_FILE))
        
        # Verifica si la sección [smtp] y las claves existen
        if 'smtp' in config and 'user' in config['smtp'] and 'password' in config['smtp']:
            GMAIL_USER = config['smtp']['user']
            GMAIL_APP_PASSWORD = config['smtp']['password']
            
        else:
            print(f"[DEBUG_CREDS] ERROR: Formato incorrecto en '{SECRETS_FILE}'. Asegúrate de tener [smtp], user y password.", file=sys.stderr)
            GMAIL_USER = None # Asegurarse de que sigan siendo None si hay error de formato
            GMAIL_APP_PASSWORD = None
    except FileNotFoundError:
        print(f"[DEBUG_CREDS] ERROR: Archivo de credenciales '{SECRETS_FILE}' no encontrado. Asegúrate de crearlo y protegerlo.", file=sys.stderr)
        GMAIL_USER = None
        GMAIL_APP_PASSWORD = None
    except Exception as e:
        print(f"[DEBUG_CREDS] ERROR inesperado al leer credenciales: {e}", file=sys.stderr)
        GMAIL_USER = None
        GMAIL_APP_PASSWORD = None

# Servidor SMTP de Gmail
SMTP_SERVER_EXTERNAL = "smtp.gmail.com"
# Puerto para STARTTLS
SMTP_PORT_EXTERNAL = 587
# --- FIN NUEVAS CONFIGURACIONES ---




def log_alarma(tipo, ip_origen, archivo_afectado=None): # Ajusté los parámetros para mayor claridad y el requisito
    # Formato de mensaje de alarma según tu documento
    load_credentials()
    timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
    mensaje_log = f"{timestamp} :: {tipo} :: {ip_origen}"
    if archivo_afectado:
        mensaje_log += f" :: {archivo_afectado}"
    mensaje_log += "\n"

    # 1. Escribir en el log
    os.makedirs(os.path.dirname(LOG_ALARMAS), exist_ok=True)
    with open(LOG_ALARMAS, "a") as f:
        f.write(mensaje_log)

    # 2. Enviar por correo al administrador
    try:
        msg = EmailMessage()
        msg.set_content(mensaje_log)
        msg['Subject'] = f'[HIPS] Alarma detectada: {tipo}'
        msg['From'] = GMAIL_USER # El remitente será tu cuenta de Gmail
        msg['To'] = GMAIL_USER # Puedes enviar a la misma cuenta para probar o a otra
	

        # --- CAMBIOS EN EL ENVÍO DE CORREO ---
        with smtplib.SMTP(SMTP_SERVER_EXTERNAL, SMTP_PORT_EXTERNAL) as server:
            server.starttls()  # Habilitar TLS
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD) # Autenticarse
            server.send_message(msg)
      
        # --- FIN CAMBIOS EN EL ENVÍO ---

    except Exception as e:
        # Si el envío de correo falla, registramos el error en el mismo log
        error_msg = f"{timestamp} :: ERROR_ENVIO_CORREO_SMTP_EXTERNAL :: {e}\n"
        with open(LOG_ALARMAS, "a") as f:
            f.write(error_msg)
        print(f"[DEBUG] Error al enviar correo (directamente via SMTP): {e}", file=sys.stderr) # <-- DEBUG
        
        

