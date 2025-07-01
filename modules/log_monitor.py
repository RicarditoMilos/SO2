import re
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict
import os
import sys # Para print a stderr

sys.path.append("/opt/hips/modules")
from utils.log import log_alarma # Importa la función log_alarma de utils.log
from utils.db import conectar_db

# Unidades de systemd que generan logs de login (ej. SSH)
JOURNAL_UNITS_LOGIN = ["sshd.service"]
# Unidades de systemd que generan logs HTTPD (ej. Apache)
JOURNAL_UNITS_HTTPD = ["httpd.service", "apache2.service"] # Incluye ambos nombres comunes

LOG_ALARMAS = "/var/log/hips/alarmas.log"
LOG_PREVENCION = "/var/log/hips/prevencion.log"

THRESHOLD_LOGIN = 1  # Cantidad de intentos fallidos
TIEMPO_LOGIN = timedelta(hours=1) # Ventana de tiempo para intentos fallidos


def bloquear_ip(ip):
    """Bloquea una IP usando iptables. Requiere permisos de root."""
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True, text=True, capture_output=True)
        mensaje = f"IP {ip} bloqueada por iptables."
        log_alarma("IP_BLOQUEADA", mensaje, ip)
        return True, mensaje
    except FileNotFoundError:
        return False, "ERROR: Comando 'sudo' o 'iptables' no encontrado."
    except subprocess.CalledProcessError as e:
        return False, f"ERROR al bloquear IP {ip}: {e.stderr.strip()}. Necesitas permisos de root."
    except Exception as e:
        return False, f"ERROR inesperado al bloquear IP {ip}: {e}"

def bloquear_usuario(usuario):
    """Bloquea un usuario del sistema (deshabilita login). Requiere permisos de root."""
    try:
        subprocess.run(["sudo", "usermod", "-L", usuario], check=True, text=True, capture_output=True)
        mensaje = f"Usuario '{usuario}' bloqueado (cuenta deshabilitada)."
        log_alarma("USUARIO_BLOQUEADO", mensaje, usuario)
        return True, mensaje
    except FileNotFoundError:
        return False, "ERROR: Comando 'sudo' o 'usermod' no encontrado."
    except subprocess.CalledProcessError as e:
        return False, f"ERROR al bloquear usuario '{usuario}': {e.stderr.strip()}. Necesitas permisos de root."
    except Exception as e:
        return False, f"ERROR inesperado al bloquear usuario '{usuario}': {e}"

def cambiar_contraseña_dummy(usuario):
    """Simula un cambio de contraseña forzado. Requiere permisos de root."""
 
    mensaje = f"Simulado: Cambio de contraseña para '{usuario}'."
    log_alarma("CONTRASENA_FORZADA", mensaje, usuario)
    return True, mensaje

def bajar_servicio_correo():
    """Baja el servicio de correo (ej. Postfix). Requiere permisos de root."""
    try:
        subprocess.run(["sudo", "systemctl", "stop", "postfix"], check=True, text=True, capture_output=True)
        mensaje = "Servicio de correo (postfix) bajado."
        log_alarma("SERVICIO_CORREO_BAJADO", mensaje, "localhost")
        return True, mensaje
    except FileNotFoundError:
        return False, "ERROR: Comando 'sudo' o 'systemctl' no encontrado."
    except subprocess.CalledProcessError as e:
        return False, f"ERROR al bajar servicio de correo: {e.stderr.strip()}. Necesitas permisos de root o el servicio no está corriendo."
    except Exception as e:
        return False, f"ERROR inesperado al bajar servicio de correo: {e}"

# --- Helper para obtener logs de journalctl ---
def get_journal_logs(unit_names, since_time_delta):
    """
    Ejecuta journalctl para obtener logs de unidades de systemd especificadas
    desde un tiempo determinado (e.g., "1 hour ago", "5 minutes ago").
    Devuelve una lista de líneas de log.
    """
    logs = []
    # journalctl --since acepta formatos como "1 hour ago", "5 minutes ago"
    # Convertir timedelta a string legible por journalctl
    total_seconds = int(since_time_delta.total_seconds())
    if total_seconds >= 3600: # Horas
        since_str = f"{total_seconds // 3600} hour ago"
    elif total_seconds >= 60: # Minutos
        since_str = f"{total_seconds // 60} minute ago"
    else: # Segundos
        since_str = f"{total_seconds} second ago"

    # Comando base para journalctl. Usamos 'sudo' para asegurar acceso completo al journal.
    # '--no-pager' para que no intente abrir un paginador (como 'less').
    # '-o short-iso' para un formato de fecha consistente que la regex pueda parsear.
    # '--unit' para filtrar por servicio.
    base_cmd = ["sudo", "journalctl", "--no-pager", "-o", "short-iso"]

    for unit in unit_names:
        cmd = base_cmd + ["--unit", unit, "--since", since_str]
        try:
            # check=True lanzará CalledProcessError si el comando falla
            # text=True para salida como string
            # capture_output=True para capturar stdout y stderr
            result = subprocess.run(cmd, check=True, text=True, capture_output=True)
            logs.extend(result.stdout.splitlines())
        except FileNotFoundError:
            error_msg = f"ERROR: Comando 'sudo' o 'journalctl' no encontrado. Asegúrate de que estén en el PATH."
            log_alarma("ERROR_COMANDO_JOURNALCTL", error_msg, "system")
            print(error_msg, file=sys.stderr)
            return [] # Si journalctl no está, no podemos hacer nada
        except subprocess.CalledProcessError as e:
            error_msg = f"ERROR al obtener logs de journalctl para unidad {unit}: {e.stderr.strip()}"
            log_alarma("ERROR_JOURNALCTL_UNIT_FAILED", error_msg, unit)
            print(error_msg, file=sys.stderr)
            # Continúa con la siguiente unidad si una falla
        except Exception as e:
            error_msg = f"ERROR inesperado al obtener logs de journalctl para unidad {unit}: {e}"
            log_alarma("ERROR_JOURNALCTL_UNEXPECTED", error_msg, unit)
            print(error_msg, file=sys.stderr)
    return logs

# --- Análisis de Logs (modificado para usar get_journal_logs) ---

def analizar_fallos_login_y_reportar():
    """Analiza logs de autenticación desde journalctl en busca de fallos de login."""
    intentos = defaultdict(list)
    reporte = []

    reporte.append("\n--- Análisis de Fallos de Login ---")
    
    # Obtener logs de journalctl para las unidades de login
    log_lines = get_journal_logs(JOURNAL_UNITS_LOGIN, TIEMPO_LOGIN)

    if not log_lines:
        reporte.append("  [ADVERTENCIA] No se obtuvieron logs de autenticación. Verifique permisos (sudo) o si los servicios SSH/autenticación están activos.")
        return reporte

    for linea in log_lines:
        # Regex para capturar fecha (journalctl -o short-iso), IP y USUARIO
        # Example journalctl -o short-iso line: 2023-10-27T19:30:00+0000 myhost sshd[1234]: Failed password for invalid user from 192.168.1.100 port 12345 ssh2
        # Example with authentication failure: 2023-10-27T19:30:00+0000 myhost sudo[5678]: pam_unix(sudo:auth): authentication failure; logname=test uid=1000 euid=0 tty=/dev/pts/0 ruser=test rhost=  user=root
        match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{4})?).*?(?:Failed password for|authentication failure).*?(?:for invalid user |for |user=)(\S+?)(?: from | rhost=)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', linea, re.IGNORECASE)
        
        if match:
            # Groups: (Timestamp, User, IP)
            fecha_str, usuario, ip = match.groups()
            # Parsear la fecha del log (usando short-iso de journalctl)
            # Ejemplo: "2023-10-27T19:30:00+0000"
            try:
                # La Z indica UTC, el +0000 es un offset. datetime.fromisoformat puede manejarlo en Python 3.7+
                # Para mayor compatibilidad o si el offset varía, podemos simplificar.
                # Simplificamos quitando el offset para el parseo inicial
                if '+' in fecha_str: # Eliminar offset de zona horaria si existe
                    fecha_str = fecha_str.split('+')[0]
                elif 'Z' in fecha_str: # Eliminar 'Z' si existe (UTC)
                    fecha_str = fecha_str.replace('Z', '')
                
                fecha_log_entry = datetime.strptime(fecha_str, "%Y-%m-%dT%H:%M:%S")

            except ValueError:
                # Si el parseo de fecha falla, usamos la hora actual para el propósito del umbral local
                fecha_log_entry = datetime.now()
                print(f"ADVERTENCIA: Fallo al parsear fecha '{fecha_str}' de la línea: {linea}", file=sys.stderr)
            
            intentos[ip].append({'fecha': fecha_log_entry, 'usuario': usuario, 'linea': linea.strip()})

    acciones_tomadas = []
    # Journalctl --since ya filtra por el periodo, pero el THRESHOLD lo verificamos localmente
    for ip, lista_intentos in intentos.items():
        # Filtra los intentos que están realmente dentro de la ventana TIEMPO_LOGIN
        # Esto es una doble verificación ya que journalctl --since puede ser un poco impreciso en los límites.
        recientes = [i for i in lista_intentos if datetime.now() - i['fecha'] < TIEMPO_LOGIN]

        if len(recientes) >= THRESHOLD_LOGIN:
            reporte.append(f"  [ALERTA] IP {ip}: {len(recientes)} intentos fallidos de login en la última hora.")
            log_alarma("MULTIPLES_FALLOS_LOGIN", f"IP {ip} con {len(recientes)} fallos.", ip)
            
            # Acción: Bloquear IP
            exito, msg = bloquear_ip(ip)
            acciones_tomadas.append(f"    - {msg}")

            # Identificar el usuario afectado (el último usuario que intentó)
            if recientes:
                usuario_afectado = recientes[-1]['usuario']
                reporte.append(f"    Último usuario intentado: '{usuario_afectado}'.")
                
                
    if not intentos:
        reporte.append("  [OK] No se detectaron intentos fallidos de login en los logs monitoreados.")
    
    if acciones_tomadas:
        reporte.append("\n  --- Acciones de Prevención de Login ---")
        reporte.extend(acciones_tomadas)
    else:
        reporte.append("\n  No se requirieron acciones de prevención de login.")
        
    return reporte


if __name__ == "__main__":
    reporte_final = []
    reporte_final.extend(analizar_fallos_login_y_reportar())
    
    print("\n".join(reporte_final))


