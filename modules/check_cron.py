import os
import subprocess
import sys
from datetime import datetime

# Añade el directorio '/opt/hips' a la ruta de búsqueda para importar módulos.
sys.path.append("/opt/hips/modules")
from utils.log import log_alarma

# Directorios estándar de configuración de cron.
CRON_DIRS = [
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron"
]

# Palabras clave para identificar posibles actividades maliciosas en cron.
PALABRAS_SOSPECHOSAS = ["wget", "curl", "nc", "bash", "sh", "python", "perl", "rm", "nmap"]

def revisar_archivos_cron():
    """
    Examina los archivos de configuración de cron del sistema en busca de patrones sospechosos.
    """
    reportes = []
    for directorio in CRON_DIRS:
        if not os.path.exists(directorio):
            continue
        for archivo_nombre in os.listdir(directorio):
            ruta_archivo = os.path.join(directorio, archivo_nombre)
            if os.path.isfile(ruta_archivo):
                try:
                    with open(ruta_archivo, "r", errors="ignore") as f:
                        for linea in f:
                            if any(palabra in linea for palabra in PALABRAS_SOSPECHOSAS):
                                mensaje = f"[CRON_SOSPECHOSO] Archivo: {ruta_archivo} -> {linea.strip()}"
                                log_alarma("CRON_SOSPECHOSO", mensaje)
                                reportes.append(mensaje)
                except Exception as e:
                    reportes.append(f"[ERROR] Error al procesar '{ruta_archivo}': {e}")
                    log_alarma("CRON_ERROR_ARCHIVO", f"Error al procesar '{ruta_archivo}': {e}")
    return reportes

def revisar_crontab_usuarios():
    """
    Revisa las tareas cron configuradas para cada usuario del sistema.
    """
    reportes = []
    try:
        usuarios_raw = subprocess.check_output("cut -f1 -d: /etc/passwd", shell=True).decode()
        usuarios = usuarios_raw.splitlines()
        
        for usuario in usuarios:
            try:
                # crontab -l -u <usuario> requiere sudo para otros usuarios.
                salida_crontab = subprocess.check_output(
                    f"crontab -l -u {usuario}", 
                    shell=True, 
                    stderr=subprocess.DEVNULL # Suprime mensajes como "no crontab for user"
                ).decode()
                
                for linea in salida_crontab.splitlines():
                    if any(palabra in linea for palabra in PALABRAS_SOSPECHOSAS):
                        mensaje = f"[CRON_SOSPECHOSO] Usuario: {usuario} -> {linea.strip()}"
                        log_alarma("CRON_SOSPECHOSO", mensaje)
                        reportes.append(mensaje)
            except subprocess.CalledProcessError:
                # Ignora errores cuando un usuario no tiene un crontab.
                continue 
            except Exception as e:
                error_mensaje = f"Error al revisar crontabs de usuario '{usuario}': {e}"
                log_alarma("CRON_ERROR_USUARIO", error_mensaje)
                reportes.append(f"[ERROR] {error_mensaje}")
    except Exception as e:
        error_mensaje_general = f"Error al revisar crontabs de usuarios (general): {e}"
        log_alarma("CRON_ERROR_GENERAL", error_mensaje_general)
        reportes.append(f"[ERROR] {error_mensaje_general}")
    return reportes

def main():
    """
    Función principal que ejecuta las revisiones de cron y muestra el reporte.
    """
    salida = []
    salida.extend(revisar_archivos_cron())
    salida.extend(revisar_crontab_usuarios())

    print("--- Verificación de Tareas Cron ---")
    if salida:
        for linea in salida:
            print(linea)
    else:
        print("No se detectaron tareas cron sospechosas.")
    print("--- Fin de la Verificación ---")

if __name__ == "__main__":
    main()


