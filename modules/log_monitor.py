import re
import subprocess
from collections import defaultdict
from datetime import datetime
import sys
import os

# Agrega el directorio padre al path para importar módulos.
sys.path.append("/opt/hips/modules")
from utils.log import log_alarma
from utils.db import conectar_db  

# Umbrales para la detección de intentos de acceso no válidos.
MAX_INTENTOS_POR_USUARIO = 5  # Límite de intentos fallidos para un usuario desde una IP.
MAX_INTENTOS_POR_IP = 5       # Límite de usuarios distintos intentando acceder desde una misma IP.

# Configuración de bloqueo
BLOQUEAR_CON_IPTABLES = True  # Activar/desactivar bloqueo con iptables
BLOQUEAR_CON_UFW = False      # Activar/desactivar bloqueo con UFW (alternativa a iptables)
BLOQUEAR_USUARIOS = True      # Activar/desactivar bloqueo de usuarios

def bloquear_ip(ip):
    """
    Bloquea una dirección IP usando iptables o UFW.
    """
    try:
        if BLOQUEAR_CON_IPTABLES:
            # Verificar si la regla ya existe
            check_cmd = f"iptables -C INPUT -s {ip} -j DROP"
            result = subprocess.run(check_cmd, shell=True, stderr=subprocess.PIPE)
            
            if result.returncode != 0:  # La regla no existe
                cmd = f"iptables -A INPUT -s {ip} -j DROP"
                subprocess.run(cmd, shell=True, check=True)
                log_alarma("BLOQUEO_IP", f"IP {ip} bloqueada con iptables")
                print(f"[+] IP {ip} bloqueada con iptables")
        
        if BLOQUEAR_CON_UFW:
            cmd = f"ufw deny from {ip}"
            subprocess.run(cmd, shell=True, check=True)
            log_alarma("BLOQUEO_IP", f"IP {ip} bloqueada con UFW")
            print(f"[+] IP {ip} bloqueada con UFW")
            
        return True
    except subprocess.CalledProcessError as e:
        log_alarma("ERROR_BLOQUEO_IP", f"No se pudo bloquear IP {ip}: {str(e)}")
        print(f"[!] Error al bloquear IP {ip}: {str(e)}", file=sys.stderr)
        return False

def desbloquear_ip(ip):
    """
    Desbloquea una dirección IP previamente bloqueada.
    """
    try:
        if BLOQUEAR_CON_IPTABLES:
            cmd = f"iptables -D INPUT -s {ip} -j DROP"
            subprocess.run(cmd, shell=True, check=True)
            log_alarma("DESBLOQUEO_IP", f"IP {ip} desbloqueada en iptables")
            print(f"[+] IP {ip} desbloqueada en iptables")
        
        if BLOQUEAR_CON_UFW:
            cmd = f"ufw delete deny from {ip}"
            subprocess.run(cmd, shell=True, check=True)
            log_alarma("DESBLOQUEO_IP", f"IP {ip} desbloqueada en UFW")
            print(f"[+] IP {ip} desbloqueada en UFW")
            
        return True
    except subprocess.CalledProcessError as e:
        log_alarma("ERROR_DESBLOQUEO_IP", f"No se pudo desbloquear IP {ip}: {str(e)}")
        print(f"[!] Error al desbloquear IP {ip}: {str(e)}", file=sys.stderr)
        return False

def bloquear_usuario(usuario):
    """
    Bloquea un usuario en el sistema usando usermod o passwd.
    """
    if not BLOQUEAR_USUARIOS:
        return False
        
    try:
        # Verificar si el usuario existe
        check_cmd = f"id {usuario}"
        result = subprocess.run(check_cmd, shell=True, stderr=subprocess.PIPE)
        
        if result.returncode != 0:
            log_alarma("USUARIO_NO_EXISTE", f"Intento de bloquear usuario inexistente: {usuario}")
            return False
            
        # Bloquear el usuario
        cmd = f"usermod --lock {usuario}"
        subprocess.run(cmd, shell=True, check=True)
        
        # Alternativa: expirar la contraseña
        # cmd = f"passwd -e {usuario}"
        # subprocess.run(cmd, shell=True, check=True)
        
        log_alarma("BLOQUEO_USUARIO", f"Usuario {usuario} bloqueado en el sistema")
        print(f"[+] Usuario {usuario} bloqueado en el sistema")
        return True
    except subprocess.CalledProcessError as e:
        log_alarma("ERROR_BLOQUEO_USUARIO", f"No se pudo bloquear usuario {usuario}: {str(e)}")
        print(f"[!] Error al bloquear usuario {usuario}: {str(e)}", file=sys.stderr)
        return False

def desbloquear_usuario(usuario):
    """
    Desbloquea un usuario previamente bloqueado.
    """
    try:
        # Verificar si el usuario existe
        check_cmd = f"id {usuario}"
        result = subprocess.run(check_cmd, shell=True, stderr=subprocess.PIPE)
        
        if result.returncode != 0:
            log_alarma("USUARIO_NO_EXISTE", f"Intento de desbloquear usuario inexistente: {usuario}")
            return False
            
        # Desbloquear el usuario
        cmd = f"usermod --unlock {usuario}"
        subprocess.run(cmd, shell=True, check=True)
        
        log_alarma("DESBLOQUEO_USUARIO", f"Usuario {usuario} desbloqueado en el sistema")
        print(f"[+] Usuario {usuario} desbloqueado en el sistema")
        return True
    except subprocess.CalledProcessError as e:
        log_alarma("ERROR_DESBLOQUEO_USUARIO", f"No se pudo desbloquear usuario {usuario}: {str(e)}")
        print(f"[!] Error al desbloquear usuario {usuario}: {str(e)}", file=sys.stderr)
        return False

def obtener_logs_fallidos():
    """
    Obtiene los logs de intentos de autenticación SSH fallidos del día actual usando journalctl.
    """
    try:
        # Ejecuta 'journalctl' para filtrar logs de SSH fallidos desde hoy.
        # '--no-pager' evita la paginación, 'stderr=subprocess.DEVNULL' suprime errores de journalctl.
        resultado = subprocess.check_output(
            ["journalctl", "-u", "ssh", "--no-pager", "--since", "today"],
            stderr=subprocess.DEVNULL
        ).decode("utf-8")
        return resultado.splitlines()
    except Exception as e:
        print(f"[!] Error obteniendo logs del journal: {e}", file=sys.stderr)
        return []

def registrar_intento(usuario, ip, cantidad):
    conn = conectar_db() # Establece conexión con la base de datos.
    if not conn:
        return # Si la conexión falla, termina la función.
    try:
        cur = conn.cursor()
        # Inserta o actualiza un registro en la tabla 'intentos_acceso'.
        cur.execute("""
            INSERT INTO intentos_acceso (usuario, ip, cantidad, fecha)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (usuario, ip) DO UPDATE SET
            cantidad = EXCLUDED.cantidad, fecha = EXCLUDED.fecha;
        """, (usuario, ip, cantidad, datetime.now())) # Usar ON CONFLICT para actualizar si ya existe.
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        log_alarma("ERROR_REGISTRO_DB_INTENTOS", f"No se pudo guardar intento sospechoso: {e}")
        print(f"[!] Error al registrar en DB: {e}", file=sys.stderr)

def analizar_logs():
    """
    Analiza los logs de SSH fallidos para detectar patrones de fuerza bruta
    y ataques de múltiples usuarios, generando alarmas y bloqueando si es necesario.
    """
    intentos_por_usuario = defaultdict(int) # Contador de intentos (usuario, IP) -> cantidad.
    usuarios_por_ip = defaultdict(set)      # IPs -> conjunto de usuarios intentados.
    alertas = []                           # Lista para almacenar mensajes de alerta.
    ips_bloqueadas = set()                 # IPs que han sido bloqueadas en esta ejecución
    usuarios_bloqueados = set()            # Usuarios que han sido bloqueados en esta ejecución

    logs = obtener_logs_fallidos()

    # Procesa cada línea de log para extraer información.
    for linea in logs:
        if "Failed password" in linea:
            # Extrae usuario e IP de las líneas de "Failed password".
            match = re.search(r"Failed password for (invalid user )?(\S+) from ([\d\.]+)", linea)
            if match:
                usuario = match.group(2)
                ip = match.group(3)
                intentos_por_usuario[(usuario, ip)] += 1
                usuarios_por_ip[ip].add(usuario)

    # Evalúa los intentos por usuario para generar alertas.
    for (usuario, ip), cantidad in intentos_por_usuario.items():
        registrar_intento(usuario, ip, cantidad) # Registra el conteo actual en DB.
        if cantidad >= MAX_INTENTOS_POR_USUARIO:
            mensaje = f"[ALERTA] Usuario sospechoso: '{usuario}' con {cantidad} intentos fallidos desde {ip}"
            print(mensaje)
            log_alarma("INTENTOS_USUARIO", mensaje)
            alertas.append(mensaje)
            
            # Bloquear usuario si está configurado
            if BLOQUEAR_USUARIOS and usuario not in usuarios_bloqueados:
                if bloquear_usuario(usuario):
                    usuarios_bloqueados.add(usuario)

    # Evalúa los intentos por IP para detectar ataques de múltiples usuarios.
    for ip, usuarios in usuarios_por_ip.items():
        if len(usuarios) >= MAX_INTENTOS_POR_IP:
            mensaje = f"[ALERTA] IP sospechosa: {ip} intentó acceder con múltiples usuarios: {', '.join(usuarios)}"
            print(mensaje)
            log_alarma("INTENTOS_IP", mensaje)
            alertas.append(mensaje)
            
            # Bloquear IP si está configurado
            if (BLOQUEAR_CON_IPTABLES or BLOQUEAR_CON_UFW) and ip not in ips_bloqueadas:
                if bloquear_ip(ip):
                    ips_bloqueadas.add(ip)

    # Mensaje final si no se detectaron alertas.
    if not alertas:
        print("[OK] No se detectaron intentos sospechosos hoy.")

def main():
    """
    Función principal para iniciar el análisis de intentos de acceso.
    """
    print("--- Análisis de intentos fallidos por SSH ---")
    analizar_logs()
    print("--- Fin del análisis ---")

if __name__ == "__main__":
    main()


