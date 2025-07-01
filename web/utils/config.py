import configparser

CONFIG_PATH = "/opt/hips/web/templates/config.ini"

_config = configparser.ConfigParser()
_config.read(CONFIG_PATH)

def obtener_umbral_cola():
    try:
        return int(_config.get("correo", "umbral_cola"))
    except Exception:
        return 4  # valor por defecto si falla



