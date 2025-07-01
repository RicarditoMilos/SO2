import re
from collections import defaultdict
from datetime import datetime
import subprocess
import os
import sys

# Permite importar módulos desde /opt/hips.
sys.path.append("/opt/hips")
from utils.log import log_alarma

LOG_FILE = "/opt/hips/modules/sample_ddos_log.txt"  # Ruta al archivo de log de ejemplo de DDoS.
THRESHOLD = 5  # Número máximo de solicitudes DNS por IP antes de considerarla sospechosa.
PUERTO_DNS = "53" # Puerto estándar para el servicio DNS.

def extraer_peticiones_dns(ruta_log):
    """
    Extrae direcciones IP de origen y cuenta las peticiones DNS en un archivo de log.

    Args:
        ruta_log (str): Ruta completa al archivo de log a procesar.

    Returns:
        defaultdict: Un diccionario donde las claves son IPs y los valores son la cantidad de peticiones.
    """
    contador = defaultdict(int)

    with open(ruta_log, "r", errors="ignore") as f:
        for linea in f:
            # Busca líneas que coincidan con el patrón de una petición DNS al puerto 53.
            # Captura la IP de origen.
            match = re.search(r"IP (\d+\.\d+\.\d+\.\d+)\.\d+ > \d+\.\d+\.\d+\.\d+\.53: .*ANY", linea)
            if match:
                ip = match.group(1)  # Extrae la IP de origen.
                contador[ip] += 1    # Incrementa el contador para esa IP.
    return contador

def bloquear_ip(ip):
    """
    Bloquea una dirección IP en el firewall usando iptables y registra la acción.

    Args:
        ip (str): La dirección IP a bloquear.
    """
    # Ejecuta el comando iptables para añadir una regla que bloquee el tráfico de la IP.
    # Requiere permisos de superusuario (sudo) para ejecutar.
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    # Registra la alarma en el sistema de logs.
    log_alarma("DDOS_DETECTADO", f"IP bloqueada: {ip}")

def procesar_log_ddos():
    """
    Procesa el log de DDoS, identifica IPs sospechosas y toma acciones de bloqueo.
    """
    # Obtiene el conteo de peticiones DNS por IP.
    ip_contador = extraer_peticiones_dns(LOG_FILE)
    
    # Itera sobre cada IP y su cantidad de peticiones.
    for ip, cantidad in ip_contador.items():
        # Si la cantidad de peticiones supera el umbral, considera un posible ataque.
        if cantidad >= THRESHOLD:
            print(f"[!] Posible ataque DDoS desde {ip} con {cantidad} peticiones DNS")
            bloquear_ip(ip)  # Llama a la función para bloquear la IP.

if __name__ == "__main__":
    procesar_log_ddos()


