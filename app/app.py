import os
from flask import Flask, session, redirect, url_for, jsonify
from models.db import get_academia_conn
from models.usuario import Usuario
from middleware.abac import emitir_evento_siem
from services.ttl_worker import iniciar_scheduler_ttl
from routes.auth_routes import auth_bp
from routes.profile_routes import profile_bp
from Admin.routes import admin_bp
from Profe.routes import profe_bp
from Alm.routes import alm_bp

def inicializar_datos_demo():
    conn = get_academia_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS total FROM usuarios_auth")
            if cur.fetchone()["total"] > 0:
                return
    finally:
        conn.close()

    admin = Usuario.crear_usuario(
        "202438968", "Jesus Neria Gomez", "NEGJ061201HPLRRL03", "ng202438968@alm.buap.mx", "AdminPriva2026!", "admin"
    )
    prof = Usuario.crear_usuario(
        "202422353", "Julisa Daniela Cruz Martinez", "CUMJ050512MPLRRL02", "cm202422353@alm.buap.mx", "ProfePriva2026!", "profesor"
    )
    alum = Usuario.crear_usuario(
        "202448106", "Luis Angel Mendez Carretero", "MECL050815HPLRRL01", "mc202448106@alm.buap.mx", "AlumnoPriva2026!", "alumno"
    )
    id_mat = admin.crear_materia("ICSA252", "Privacidad y Seguridad de Datos", "202422353")
    prof.registrar_calificacion("202448106", id_mat, 9.8)

def create_app():
    app = Flask(__name__, static_folder="assets", template_folder="templates")
    app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev_fallback_key")
    app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "uploads")
    app.config["CERT_FOLDER"] = os.path.join(app.root_path, "certificados")
    app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    app.register_blueprint(auth_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(profe_bp)
    app.register_blueprint(alm_bp)

    try:
        inicializar_datos_demo()
    except Exception as e:
        emitir_evento_siem("INIT_SEED_WARN", f"detalle={str(e)}", severidad=4)

    iniciar_scheduler_ttl(app.config["UPLOAD_FOLDER"], app.config["CERT_FOLDER"])

    @app.route("/")
    def index():
        if session.get("token_opaco"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("auth.login"))

    @app.route("/dashboard")
    def dashboard():
        rol = session.get("rol")
        if rol == "admin":
            return redirect(url_for("admin.dashboard"))
        if rol == "profesor":
            return redirect(url_for("profe.dashboard"))
        if rol == "alumno":
            return redirect(url_for("alm.dashboard"))
        return redirect(url_for("auth.login"))

    @app.route("/health")
    def health():
        return jsonify({"status": "online", "service": "Plataforma Privacy-by-Design ICSA 252"})

    return app
