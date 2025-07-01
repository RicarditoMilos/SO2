import time
import json
import os
import sys
import psutil
from datetime import datetime


sys.path.append("/opt/hips/modules") 
from utils.log import log_alarma 

# Ruta al archivo de configuración de umbrales
THRESHOLD_FILE = "/opt/hips/modules/ramAsig.json"


def cargar_thresholds():
    if not os.path.exists(THRESHOLD_FILE):
        return {"mem_usage_percent": 70, "mem_check_duration": 300} # Valores por defecto más sensatos
    try:
        with open(THRESHOLD_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"Error: El archivo de umbrales '{THRESHOLD_FILE}' no es un JSON válido. Usando valores por defecto.")
        return {"mem_usage_percent": 70, "mem_check_duration": 300}
    except Exception as e:
        print(f"Error al cargar umbrales desde '{THRESHOLD_FILE}': {e}. Usando valores por defecto.")
        return {"mem_usage_percent": 70, "mem_check_duration": 300}


def verificar_consumo_memoria_una_vez():
    """Realiza una única verificación de consumo de memoria y devuelve un informe."""
    umbrales = cargar_thresholds()
    uso_minimo = umbrales.get("mem_usage_percent", 70) # Usar valores por defecto más altos
    # tiempo_espera = umbrales.get("mem_check_duration", 300) # Ya no es relevante para una única ejecución

    reporte = []
    
    # Obtener el total de RAM del sistema para calcular el porcentaje correctamente
    total_ram = psutil.virtual_memory().total
    
    reporte.append(f"--- Informe de Consumo de RAM ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ---")
    reporte.append(f"Umbral de alerta: {uso_minimo}% de RAM.")
    reporte.append(f"RAM Total del Sistema: {total_ram / (1024**3):.2f} GB")
    reporte.append(f"RAM Usada del Sistema: {psutil.virtual_memory().used / (1024**3):.2f} GB ({psutil.virtual_memory().percent}%)")
    reporte.append("-" * 50)
    reporte.append("Procesos que superan el umbral:")

    procesos_detectados_en_esta_corrida = 0

    for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'memory_percent', 'status']):
        try:
            # Skip zombie processes
            if proc.info['status'] == psutil.STATUS_ZOMBIE:
                continue

            mem_percent = proc.info['memory_percent']
            
            # memory_info().rss es Resident Set Size (memoria física usada)
            mem_rss_mb = proc.info['memory_info'].rss / (1024 * 1024) 

            pid = proc.info['pid']
            nombre = proc.info['name']

            if mem_percent >= uso_minimo:
                reporte.append(f"  - Proceso: {nombre} (PID: {pid}) - RAM: {mem_rss_mb:.2f} MB ({mem_percent:.2f}%)")
                # Aquí NO matamos el proceso si se ejecuta desde el dashboard.
                # Para matar procesos, ram.py DEBE ejecutarse como un demonio separado.
               
                procesos_detectados_en_esta_corrida += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            
            continue
        except Exception as e:
            reporte.append(f"  Error al procesar PID {pid} ({nombre}): {e}")
            continue
            
    if procesos_detectados_en_esta_corrida == 0:
        reporte.append("  Ningún proceso excede el umbral de RAM en este momento.")

    reporte.append("-" * 50)
    return "\n".join(reporte) # Devuelve el reporte como una cadena de texto

if __name__ == "__main__":
    
    print(verificar_consumo_memoria_una_vez())
    
   


