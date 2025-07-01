from flask import Flask, render_template, request, redirect, url_for, session
import json
import os
import subprocess
import configparser

app = Flask(__name__)
app.secret_key = 'supersecretkey' # ¡Recuerda que esta clave debe ser compleja y secreta en producción!
THRESHOLDS_FILE = '/opt/hips/thresholds.json'
LOG_PATH = "/var/log/hips/alertas.log"
SCRIPTS_DIR = "/opt/hips/modules/" # Directorio base para todos los scripts
CONFIG_PATH = "/opt/hips/web/templates/config.ini"



USUARIO = 'admin'
CONTRASEÑA = 'admin123'

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        pw = request.form['password']
        if user == USUARIO and pw == CONTRASEÑA:
            session['logged_in'] = True # Establecemos 'logged_in' a True
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Credenciales incorrectas')
    return render_template('login.html')

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    # Usamos session.get('logged_in') para ser consistentes con lo que se establece en login
    if not session.get('logged_in'):
        return redirect(url_for('login')) # Redirige al login si no está logueado

    salida = ""
    if request.method == "POST":
        accion = request.form.get("accion")
        # Aquí mapeamos los valores 'accion' de los botones a los scripts reales
        if accion == "cambios/etc/passwd":
            salida = ejecutar_script(os.path.join(SCRIPTS_DIR, "integridad.py"))
        elif accion == "check_users":
            salida = ejecutar_script(os.path.join(SCRIPTS_DIR, "usuarios_conectados.py"))
        elif accion == "check_sniffers":
            salida = ejecutar_script(os.path.join(SCRIPTS_DIR, "deteccion_sniffer.py"))
        elif accion == "log_analyzer":
            salida = ejecutar_script(os.path.join(SCRIPTS_DIR, "log_monitor.py"))
        elif accion == "email_an":
            salida = ejecutar_script(os.path.join(SCRIPTS_DIR, "mail_queue_checker.py"))
        elif accion == "ram":
            salida = ejecutar_script(os.path.join(SCRIPTS_DIR, "ram.py"))
        elif accion == "tmp":
            salida = ejecutar_script(os.path.join(SCRIPTS_DIR, "check_temp.py")) 
        elif accion == "ddos":
            salida = ejecutar_script(os.path.join(SCRIPTS_DIR, "check_ddos_dns.py"))
        elif accion == "cron":
            salida = ejecutar_script(os.path.join(SCRIPTS_DIR, "check_cron.py"))
        elif accion == "ipfalla":
            salida = ejecutar_script(os.path.join(SCRIPTS_DIR, "check_logins.py"))                       
        else:
            salida = "Acción no reconocida."
    
    alertas = leer_alertas()
    return render_template("dashboard.html", salida=salida, alertas=alertas)

# Función para ejecutar scripts externos
def ejecutar_script(ruta_script):
    try:
        # Asegúrate de que 'python3' es el comando correcto para tu sistema.
        # Si tus scripts no son de Python, ajusta esto (ej: ["bash", ruta_script])
        resultado = subprocess.run(
            ["python3", ruta_script],
            capture_output=True, # Captura stdout y stderr
            text=True,           # Decodifica la salida como texto
            check=True           # Lanza CalledProcessError si el comando devuelve un código de salida no cero
        )
        return resultado.stdout
    except subprocess.CalledProcessError as e:
        # Si el script Python devuelve un error, capturamos su salida de error
        return f"Error al ejecutar {ruta_script}:\n{e.stderr}"
    except FileNotFoundError:
        # Si el script o el intérprete python3 no se encuentran
        return f"Error: El script '{ruta_script}' o el intérprete 'python3' no fue encontrado."
    except Exception as e:
        # Para cualquier otro error inesperado
        return f"Error inesperado al ejecutar {ruta_script}: {e}"

# Función para leer alertas del log
def leer_alertas():
    if os.path.exists(LOG_PATH):
        try:
            with open(LOG_PATH, "r") as f:
                return f.read()
        except Exception as e:
            return f"Error al leer el archivo de alertas {LOG_PATH}: {e}"
    else:
        return "No hay alertas registradas."
        
@app.route("/config", methods=["GET", "POST"])
def configurar():
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH)

    if request.method == "POST":
        nuevo_umbral = request.form.get("umbral")
        try:
            umbral_int = int(nuevo_umbral)
            config.set("correo", "umbral_cola", str(umbral_int))
            with open(CONFIG_PATH, "w") as configfile:
                config.write(configfile)
        except ValueError:
            return "Valor inválido", 400
        return redirect("/config")

    umbral_actual = config.get("correo", "umbral_cola", fallback="4")
    return render_template("config.html", umbral=umbral_actual)


@app.route("/logout")
def logout():
    session.pop("logged_in", None) # Limpiamos 'logged_in' de la sesión
    return redirect(url_for('login')) # Redirigimos al login

if __name__ == '__main__':
    app.run(debug=True) # Ejecuta la aplicación Flask en modo depuración
