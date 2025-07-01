import subprocess
import sys
import os
import re
from datetime import datetime

# Añade el directorio 'modules' al path para importar submódulos.
sys.path.append("/opt/hips/modules")

from utils.log import log_alarma
from utils.db import conectar_db

# Umbral para la cantidad de mensajes en la cola de correo.
#MAIL_QUEUE_THRESHOLD = 4
from utils.config import obtener_umbral_cola

def obtener_tamano_cola():
    """
    Obtiene el número de mensajes en la cola de correo de Postfix usando 'postqueue -p'.

    Returns:
        int: La cantidad de mensajes en cola, o -1 si ocurre un error.
    """
    try:
        # Ejecuta 'postqueue -p' para obtener la lista de mensajes en cola.
        # Requiere permisos de sudo.
        resultado = subprocess.run(["sudo", "postqueue", "-p"], capture_output=True, text=True, check=True)
        salida = resultado.stdout
        cantidad_mensajes = 0
        # Cuenta las líneas que representan un mensaje en la cola.
        for linea in salida.splitlines():
            # El patrón busca el ID del mensaje al inicio de la línea.
            if re.match(r'^[0-9A-F]{10,11}\s+', linea.strip()):
                cantidad_mensajes += 1
        return cantidad_mensajes
    except FileNotFoundError:
        error_msg = "ERROR: postqueue no encontrado o Postfix no instalado."
        log_alarma("ERROR_COMANDO_POSTQUEUE", error_msg)
        print(error_msg, file=sys.stderr)
        return -1
    except subprocess.CalledProcessError as e:
        error_msg = f"ERROR al ejecutar postqueue: {e.stderr.strip()}"
        log_alarma("ERROR_POSTQUEUE_EJECUCION", error_msg)
        print(error_msg, file=sys.stderr)
        return -1
    except Exception as e:
        error_msg = f"ERROR inesperado al verificar cola de mail: {e}"
        log_alarma("ERROR_VERIFICAR_COLA_MAIL_GENERICO", error_msg)
        print(error_msg, file=sys.stderr)
        return -1

def registrar_estado_cola(cantidad, umbral, estado):
    """
    Registra el estado actual de la cola de correo en la base de datos.

    Args:
        cantidad (int): Cantidad de mensajes en la cola.
        umbral (int): Umbral configurado para la alerta.
        estado (str): Estado de la cola ('EXCESIVO' o 'NORMAL').
    """
    conn = conectar_db() # Conecta a la base de datos.
    if not conn:
        return
    try:
        cur = conn.cursor()
        # Inserta los datos del estado de la cola en la tabla correspondiente.
        cur.execute("""
            INSERT INTO cola_mail_alerta (cantidad_mails, umbral, estado, fecha)
            VALUES (%s, %s, %s, %s);
        """, (cantidad, umbral, estado, datetime.now()))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        log_alarma("ERROR_REGISTRO_COLA_DB", f"No se pudo guardar estado de cola: {e}")
        print(f"Error al registrar en DB: {e}", file=sys.stderr)

def verificar_cola_mail():
    """
    Función principal para verificar el tamaño de la cola de correo.
    Genera alertas si excede un umbral y, en caso de alerta, intenta detener Postfix.

    Returns:
        str: Un reporte en formato de string con los resultados de la verificación.
    """
    reporte_salida = []
    reporte_salida.append("--- Verificación de Cola de Correo ---")
    umbral = obtener_umbral_cola()

    cantidad = obtener_tamano_cola() # Obtiene el tamaño actual de la cola.

    if cantidad == -1:
        reporte_salida.append("  [ERROR] No se pudo obtener el tamaño de la cola de correo.")
        return "\n".join(reporte_salida)

    reporte_salida.append(f"  Mensajes en cola: {cantidad}")

    if cantidad > umbral:
        reporte_salida.append(f"  [ALERTA] Cola sospechosa: {cantidad} (umbral: {umbral})")
        log_alarma("COLA_MAIL_SOSPECHOSA", f"Cola: {cantidad} supera umbral.")
        registrar_estado_cola(cantidad, umbral, "EXCESIVO")

        reporte_salida.append("  [ACCIÓN] Intentando detener Postfix...")

        try:
            # Intenta detener el servicio Postfix. Requiere sudo.
            subprocess.run(["sudo", "systemctl", "stop", "postfix"], check=True, text=True, capture_output=True)
            msg = "  [ÉXITO] Postfix detenido."
            reporte_salida.append(msg)
            log_alarma("SERVICIO_CORREO_BLOQUEADO", msg)
        except FileNotFoundError:
            msg = "  [ERROR] Comando systemctl no encontrado."
            reporte_salida.append(msg)
            log_alarma("ERROR_COMANDO_SYSTEMCTL", msg)
        except subprocess.CalledProcessError as e:
            msg = f"  [ERROR] Fallo al detener Postfix: {e.stderr.strip()}"
            reporte_salida.append(msg)
            log_alarma("ERROR_DETENER_POSTFIX", msg)
        except Exception as e:
            msg = f"  [ERROR] Error al detener Postfix: {e}"
            reporte_salida.append(msg)
            log_alarma("ERROR_DETENER_POSTFIX_GENERICO", msg)
    else:
        reporte_salida.append("  [OK] Cola dentro del umbral.")
        registrar_estado_cola(cantidad, umbral, "NORMAL")

    reporte_salida.append("--- Fin de la Verificación ---")
    return "\n".join(reporte_salida)

if __name__ == "__main__":
    print(verificar_cola_mail())


