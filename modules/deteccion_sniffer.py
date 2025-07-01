import os
import subprocess
from datetime import datetime
import psutil
import sys # Importar sys para manejar sys.stderr

sys.path.append("/opt/hips/modules")
from utils.log import log_alarma

# Lista de procesos sniffers conocidos
SNIFFERS_CONOCIDOS = ["tcpdump", "wireshark", "ethereal", "ettercap", "dsniff"]

def interfaz_en_modo_promiscuo():
    """
    Verifica si alguna interfaz de red está en modo promiscuo.
    Devuelve True si encuentra una, False en caso contrario.
    """
    try:
        # 'ip link' es más moderno que 'ifconfig' y devuelve información de la interfaz.
        # Buscamos la bandera 'PROMISC'
        output = subprocess.check_output("ip link", shell=True, text=True, stderr=subprocess.PIPE)
        for linea in output.splitlines():
            if "PROMISC" in linea:
                # Extraemos el nombre de la interfaz de la línea (ej. "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP,PROMISC> qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000")
                partes = linea.strip().split(':')
                if len(partes) > 1:
                    nombre_interfaz = partes[1].strip().split(' ')[0]
                    return True, nombre_interfaz
        return False, None
    except FileNotFoundError:
        error_msg = "ERROR: Comando 'ip link' no encontrado. Asegúrate de que esté en el PATH."
        log_alarma("ERROR_COMANDO_IP_LINK", "sistema", error_msg)
        print(error_msg, file=sys.stderr)
        return False, None
    except subprocess.CalledProcessError as e:
        error_msg = f"ERROR_DETECCION_PROMISCUO: Fallo al ejecutar 'ip link': {e.stderr.strip()}"
        log_alarma("ERROR_DETECCION_PROMISCUO", "sistema", error_msg)
        print(error_msg, file=sys.stderr)
        return False, None
    except Exception as e:
        error_msg = f"ERROR_DETECCION_PROMISCUO: Error inesperado: {e}"
        log_alarma("ERROR_DETECCION_PROMISCUO", "sistema", error_msg)
        print(error_msg, file=sys.stderr)
        return False, None

def detectar_procesos_sniffer():
    """
    Detecta procesos de sniffers conocidos en ejecución.
    Devuelve una lista de objetos de proceso de psutil.
    """
    procesos_sospechosos = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']): # Añadimos 'cmdline' para más detalle
        try:
            # psutil.STATUS_ZOMBIE se saltan ya que no se pueden interactuar con ellos
            if proc.status() == psutil.STATUS_ZOMBIE:
                continue

            nombre_proceso = proc.info['name']
            linea_comando = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""

            if nombre_proceso in SNIFFERS_CONOCIDOS or \
               any(sniffer in linea_comando for sniffer in SNIFFERS_CONOCIDOS): # También busca en la línea de comando
                procesos_sospechosos.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Proceso terminó o no tenemos permisos para acceder a su info
            continue
        except Exception as e:
            # Otros errores inesperados al iterar procesos
            print(f"ERROR: Fallo al procesar PID {proc.pid}: {e}", file=sys.stderr)
            continue
    return procesos_sospechosos

def matar_sniffer(proc):
    """
    Intenta terminar un proceso sniffer.
    Devuelve True si fue exitoso, False en caso contrario.
    """
    try:
        # log_alarma("SNIFFER_DETECTADO", f"{proc.info['name']} (PID: {proc.pid})") # Esto se logueará en la función principal
        proc.kill()
        return True
    except psutil.NoSuchProcess:
        # Proceso ya no existe, no hay problema
        return True
    except psutil.AccessDenied:
        log_alarma("ERROR_PERMISOS_KILL", f"No se pudo matar {proc.info['name']} (PID: {proc.pid}) - Permiso denegado")
        print(f"ERROR: Permiso denegado para matar el proceso {proc.info['name']} (PID: {proc.pid}). Necesitas ejecutar con más privilegios.", file=sys.stderr)
        return False
    except Exception as e:
        log_alarma("ERROR_AL_MATAR_SNIFFER", f"{proc.info['name']} (PID: {proc.pid}) - {e}")
        print(f"ERROR: Fallo inesperado al intentar matar {proc.info['name']} (PID: {proc.pid}): {e}", file=sys.stderr)
        return False

def ejecutar_deteccion_sniffer():
    """
    Ejecuta el chequeo de sniffer y genera un reporte para el dashboard.
    """
    reporte_salida = []
    reporte_salida.append("--- Verificación de Sniffers y Modo Promiscuo ---")

    # 1. Verificar modo promiscuo
    promiscuo_activo, interfaz_promiscuo = interfaz_en_modo_promiscuo()
    if promiscuo_activo:
        msg_promiscuo = f"  [ALERTA] Modo Promiscuo ACTIVADO en la interfaz: {interfaz_promiscuo}."
        reporte_salida.append(msg_promiscuo)
        log_alarma("MODO_PROMISCUO_ACTIVADO", f"Interfaz: {interfaz_promiscuo}")
    else:
        reporte_salida.append("  [OK] No se detectó ninguna interfaz en modo promiscuo.")

    # 2. Detectar y (opcionalmente) matar procesos sniffers
    reporte_salida.append("\n  --- Procesos Sniffers Conocidos ---")
    sniffers_detectados = detectar_procesos_sniffer()

    if sniffers_detectados:
        reporte_salida.append(f"  [ALERTA] Se detectaron {len(sniffers_detectados)} posibles sniffers en ejecución:")
        for proc in sniffers_detectados:
            proc_info = proc.info # Cache info to avoid calling it multiple times
            nombre = proc_info['name']
            pid = proc.pid
            cmdline = " ".join(proc_info['cmdline']) if proc.info['cmdline'] else "N/A"
            username = proc_info['username']

            reporte_salida.append(f"    - Nombre: {nombre} (PID: {pid}) - Usuario: {username}")
            reporte_salida.append(f"      Comando: {cmdline}")
            
            # Intentar matar el proceso
            log_alarma("SNIFFER_DETECTADO_INTENTO_KILL", f"Proceso: {nombre} (PID: {pid})")
            if matar_sniffer(proc):
                reporte_salida.append(f"      [ACCIÓN] Proceso {nombre} (PID: {pid}) TERMINADO exitosamente.")
                log_alarma("SNIFFER_TERMINADO", f"Proceso: {nombre} (PID: {pid})")
            else:
                reporte_salida.append(f"      [ADVERTENCIA] Fallo al terminar {nombre} (PID: {pid}). Ver logs para detalles.")
    else:
        reporte_salida.append("  [OK] No se detectaron procesos sniffers conocidos en ejecución.")

    reporte_salida.append("\n--- Fin de la Verificación ---")
    return "\n".join(reporte_salida)

if __name__ == "__main__":

    print(ejecutar_deteccion_sniffer())


