
import os
import shutil
import subprocess
import re # ¡Importante! Añadir re
from datetime import datetime
import sys

sys.path.append("/opt/hips/modules")
from utils.log import log_alarma # Asegúrate de que esta importación sea correcta

CUARENTENA_DIR = "/opt/hips/modules/cuarentena"

# Asegúrate de que el directorio de cuarentena existe y es escribible
try:
    os.makedirs(CUARENTENA_DIR, exist_ok=True)
except OSError as e:
    print(f"ERROR: No se pudo crear el directorio de cuarentena '{CUARENTENA_DIR}': {e}", file=sys.stderr)
    sys.exit(1) # Salir si no se puede crear el directorio de cuarentena

def es_sospechoso_archivo(nombre_archivo):
    """
    Define los criterios de sospecha para nombres de archivo.
    Considera extensiones comunes de scripts/ejecutables o nombres muy inusuales.
    """
    extensiones_peligrosas = [".sh", ".py", ".pl", ".bin", ".exe", ".php", ".jsp", ".asp", ".dll"]
    
    # Criterio 1: Extensiones conocidas de scripts/ejecutables
    if any(nombre_archivo.lower().endswith(ext) for ext in extensiones_peligrosas):
        return True
    
    # Criterio 2: Nombres que parecen strings aleatorios (ej. "kjhgdswert.sh")
    # Si el nombre es largo y no contiene casi letras o números, podría ser sospechoso.
    # Evitar falsos positivos con nombres legítimos largos.
    if len(nombre_archivo) > 15: # Longitud mínima para considerar aleatoriedad
        num_alnum = sum(c.isalnum() for c in nombre_archivo)
        # Si menos del 50% de los caracteres son alfanuméricos, y tiene más de 15 caracteres
        if num_alnum / len(nombre_archivo) < 0.5:
             return True

    # Criterio 3: Nombres que contienen caracteres no ASCII imprimibles (fuera de lo normal)
    # Puede indicar ofuscación o binarios
    if not all(32 <= ord(c) <= 126 for c in nombre_archivo): # Caracteres ASCII imprimibles
        return True

    return False

def mover_a_cuarentena(ruta_origen, reporte_salida):
    """
    Mueve un archivo a la carpeta de cuarentena.
    """
    nombre_archivo = os.path.basename(ruta_origen)
    destino = os.path.join(CUARENTENA_DIR, nombre_archivo)
    
    # Asegurarse de que el archivo no sobrescriba uno existente en cuarentena
    contador = 1
    original_destino = destino
    while os.path.exists(destino):
        nombre_sin_ext, ext = os.path.splitext(nombre_archivo)
        destino = os.path.join(CUARENTENA_DIR, f"{nombre_sin_ext}_{contador}{ext}")
        contador += 1

    try:
        # Usar sudo con shutil.move si el script no tiene permisos directos
        # Esto requiere una regla NOPASSWD para "mv" o "shutil.move" en sudoers
        # O ejecutar el script completo con sudo.
        subprocess.run(["sudo", "mv", ruta_origen, destino], check=True, text=True, capture_output=True)
        mensaje = f"Archivo sospechoso '{ruta_origen}' movido a cuarentena: '{destino}'."
        reporte_salida.append(f"  [ACCIÓN] {mensaje}")
        log_alarma("ARCHIVO_SOSPECHOSO_TMP_CUARENTENA", mensaje) # Añadido 'localhost' como IP
        return True
    except FileNotFoundError:
        error_msg = f"  [ERROR] Comando 'sudo' o 'mv' no encontrado. No se pudo mover '{ruta_origen}'."
        reporte_salida.append(error_msg)
        log_alarma("ERROR_MOVER_CUARENTENA_COMANDO", error_msg)
    except subprocess.CalledProcessError as e:
        error_msg = f"  [ERROR] Fallo al mover '{ruta_origen}' a cuarentena: {e.stderr.strip()}. Necesitas permisos de root."
        reporte_salida.append(error_msg)
        log_alarma("ERROR_MOVER_CUARENTENA_PERMISOS", error_msg)
    except Exception as e:
        error_msg = f"  [ERROR] Error inesperado al mover '{ruta_origen}' a cuarentena: {e}"
        reporte_salida.append(error_msg)
        log_alarma("ERROR_MOVER_CUARENTENA_GENERICO", error_msg)
    return False


def buscar_archivos_tmp(reporte_salida):
    """
    Busca archivos sospechosos en /tmp y sus subdirectorios.
    """
    reporte_salida.append("\n--- Búsqueda de Archivos Sospechosos en /tmp ---")
    archivos_encontrados = []
    try:
        for root, dirs, files in os.walk("/tmp"):
            for nombre_archivo in files:
                ruta_completa = os.path.join(root, nombre_archivo)
                if os.path.islink(ruta_completa): # Ignorar symlinks para evitar bucles o problemas
                    continue
                
                
                if es_sospechoso_archivo(nombre_archivo):
                    reporte_salida.append(f"  [ALERTA] Archivo sospechoso detectado: '{ruta_completa}'")
                    log_alarma("ARCHIVO_SOSPECHOSO_TMP_DETECTADO", f"Detectado: {ruta_completa}")
                    archivos_encontrados.append(ruta_completa)
    except PermissionError:
        error_msg = "  [ERROR] Permiso denegado para acceder a /tmp o un subdirectorio. Ejecuta con sudo."
        reporte_salida.append(error_msg)
        log_alarma("ERROR_PERMISO_TMP_LECTURA", error_msg)
    except Exception as e:
        error_msg = f"  [ERROR] Error inesperado al buscar archivos en /tmp: {e}"
        reporte_salida.append(error_msg)
        log_alarma("ERROR_BUSCAR_ARCHIVOS_TMP_GENERICO", error_msg)

    if archivos_encontrados:
        reporte_salida.append("  Iniciando acciones de cuarentena para los archivos detectados...")
        for archivo in archivos_encontrados:
            mover_a_cuarentena(archivo, reporte_salida)
    else:
        reporte_salida.append("  [OK] No se detectaron archivos sospechosos en /tmp.")


def buscar_procesos_tmp(reporte_salida):
    """
    Busca procesos que se están ejecutando desde /tmp.
    """
    reporte_salida.append("\n--- Búsqueda de Procesos Sospechosos en /tmp ---")
    procesos_sospechosos = []
    try:
        # ps auxw para asegurar que se muestre la línea de comando completa
        salida = subprocess.run(["ps", "auxw"], capture_output=True, text=True, check=True)
        for linea in salida.stdout.splitlines():
            # Intentar encontrar el path del ejecutable real, no solo un argumento
            # Esto es más preciso: /proc/<PID>/exe
            # Si el proceso fue eliminado, /proc/<PID>/exe puede aparecer como " (deleted)"
            match = re.search(r'^\S+\s+(\d+)\s+.*?\s+.*?((?:/tmp/.*?|\s?/\w+/\w+/\w+/tmp/.*?))$', linea)
            
            if match:
                pid = match.group(1)
                full_command = match.group(2).strip() # El comando completo que incluye /tmp
                
                # Verificar si el ejecutable en /proc/<pid>/exe apunta a /tmp
                exe_path = ""
                try:
                    exe_path = os.readlink(f"/proc/{pid}/exe")
                except FileNotFoundError: # Proceso ya terminado o no existe /proc/<pid>/exe
                    pass
                except PermissionError: # Faltan permisos para leer /proc/<pid>/exe
                    pass
                
                # Un proceso es sospechoso si su ejecutable está en /tmp
                # O si su línea de comando indica un script en /tmp (menos fiable)
                if exe_path.startswith("/tmp/") or (not exe_path and full_command.startswith("/tmp/")):
                    mensaje = f"Proceso sospechoso en /tmp: PID {pid} :: Comando '{full_command}' :: Ejecutable '{exe_path}'"
                    reporte_salida.append(f"  [ALERTA] {mensaje}")
                    log_alarma("PROCESO_SOSPECHOSO_EN_TMP_DETECTADO", mensaje)
                    procesos_sospechosos.append(pid)
                    
                  
    except FileNotFoundError:
        error_msg = "  [ERROR] Comando 'ps' no encontrado."
        reporte_salida.append(error_msg)
        log_alarma("ERROR_COMANDO_PS", error_msg)
    except subprocess.CalledProcessError as e:
        error_msg = f"  [ERROR] Fallo al ejecutar 'ps auxw': {e.stderr.strip()}"
        reporte_salida.append(error_msg)
        log_alarma("ERROR_PS_EJECUCION", error_msg)
    except Exception as e:
        error_msg = f"  [ERROR] Error inesperado al buscar procesos en /tmp: {e}"
        reporte_salida.append(error_msg)
        log_alarma("ERROR_BUSCAR_PROCESOS_TMP_GENERICO", error_msg)
    
    if not procesos_sospechosos:
        reporte_salida.append("  [OK] No se detectaron procesos sospechosos ejecutándose desde /tmp.")


def main():
    reporte_salida = []
    reporte_salida.append("--- Verificación de Directorio /tmp ---")
    
    buscar_archivos_tmp(reporte_salida)
    buscar_procesos_tmp(reporte_salida)
    
    reporte_salida.append("\n--- Fin de la Verificación de /tmp ---")
    return "\n".join(reporte_salida)

if __name__ == "__main__":
    print(main())
