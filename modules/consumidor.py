import time
import sys

print("Iniciando consumidor de RAM (aprox. 500MB de forma constante)...")

# Definir la cantidad de RAM a consumir en bytes
TARGET_RAM_BYTES = 500 * 1024 * 1024 # 500 MB

# Esta lista almacenará los datos para mantener la memoria asignada
# Usaremos una lista de bloques más pequeños para una mejor gestión,
# aunque una sola cadena grande también funciona.
data_chunks = []
CHUNK_SIZE_BYTES = 10 * 1024 * 1024 # 10 MB por bloque

try:
    # Asignar memoria en bloques hasta alcanzar el objetivo
    allocated_bytes = 0
    while allocated_bytes < TARGET_RAM_BYTES:
        try:
            # Crea un bloque de datos (una cadena de 'x's)
            chunk = 'x' * CHUNK_SIZE_BYTES
            data_chunks.append(chunk) # Añade el bloque a la lista
            allocated_bytes += CHUNK_SIZE_BYTES
            print(f"Asignando... Total asignado: {allocated_bytes / (1024 * 1024):.0f}MB")
            # Pequeña pausa para permitir que el sistema actualice el uso de memoria
            time.sleep(0.1)
        except MemoryError:
            print(f"¡Error de memoria! No se pudo asignar los {TARGET_RAM_BYTES / (1024 * 1024):.0f}MB deseados. "
                  f"Asignado hasta ahora: {allocated_bytes / (1024 * 1024):.0f}MB.")
            break # Sale si no puede asignar más memoria

    print(f"Memoria asignada y mantenida: ~{allocated_bytes / (1024 * 1024):.0f}MB.")
    print("El proceso se mantendrá activo hasta que lo detengas (Ctrl+C).")

    # Mantiene el proceso vivo indefinidamente para que la RAM se mantenga consumida
    # Usamos un bucle infinito con un sleep para que no consuma CPU innecesariamente
    while True:
        time.sleep(60) # Espera 60 segundos antes de la siguiente verificación (inactividad)

except KeyboardInterrupt:
    print("\nConsumidor de RAM detenido manualmente (Ctrl+C).")
except Exception as e:
    print(f"Ocurrió un error inesperado: {e}")

finally:
    # Opcional: limpiar la lista al finalizar, aunque el sistema operativo lo hará
    # cuando el proceso termine.
    data_chunks = []
    print("Consumidor de RAM finalizado y memoria liberada.")


