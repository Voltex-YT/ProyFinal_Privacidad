import re
from flask import Blueprint, request, session, redirect, url_for, render_template, jsonify
from models.usuario import Usuario
from middleware.abac import emitir_evento_siem

auth_bp = Blueprint("auth", __name__)

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
MATRICULA_REGEX = re.compile(r"^\d{6,12}$")
CURP_REGEX = re.compile(r"^[A-Z]{4}\d{6}[HM][A-Z]{5}[0-9A-Z]\d$")

def obtener_ip_cliente():
    return request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For") or request.remote_addr or "0.0.0.0"

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("token_opaco"):
            return redirect(url_for("dashboard"))
        return render_template("login.html", tab="login")

    data = request.get_json(silent=True) or request.form
    matricula = (data.get("matricula") or "").strip()
    password = data.get("password") or ""
    ip_origen = obtener_ip_cliente()

    usuario = Usuario.autenticar(matricula, password)
    if not usuario:
        emitir_evento_siem(
            "AUTH_FAIL",
            f"src_ip={ip_origen} matricula={matricula} motivo=credenciales_invalidas_o_expiradas",
            severidad=4
        )
        if request.is_json:
            return jsonify({"error": "Credenciales invalidas o cuenta expirada"}), 401
        return render_template("login.html", error="Credenciales invalidas o cuenta expirada", tab="login"), 401

    session.clear()
    session["token_opaco"] = usuario.token_opaco
    session["rol"] = usuario.rol

    emitir_evento_siem(
        "AUTH_SUCCESS",
        f"src_ip={ip_origen} actor={usuario.token_opaco} rol={usuario.rol}",
        severidad=6
    )

    if request.is_json:
        return jsonify({"status": "ok", "rol": usuario.rol, "token_opaco": usuario.token_opaco})
    return redirect(url_for("dashboard"))

@auth_bp.route("/registro", methods=["POST"])
def registro():
    data = request.get_json(silent=True) or request.form
    matricula = (data.get("matricula") or "").strip()
    nombre = (data.get("nombre_completo") or "").strip()
    curp = (data.get("curp") or "").strip().upper()
    correo = (data.get("correo") or "").strip().lower()
    password = data.get("password") or ""
    ip_origen = obtener_ip_cliente()

    if not MATRICULA_REGEX.match(matricula):
        return render_template("login.html", error_reg="La matricula debe contener entre 6 y 12 digitos numericos.", tab="registro"), 400

    if not EMAIL_REGEX.match(correo):
        return render_template("login.html", error_reg="Formato de correo electronico invalido.", tab="registro"), 400

    if not CURP_REGEX.match(curp):
        return render_template("login.html", error_reg="El formato de CURP (18 caracteres) no es valido.", tab="registro"), 400

    if len(password) < 8:
        return render_template("login.html", error_reg="La contrasena debe tener al menos 8 caracteres.", tab="registro"), 400

    try:
        nuevo = Usuario.crear_usuario(
            matricula=matricula,
            nombre_completo=nombre,
            curp=curp,
            correo=correo,
            password_plano=password,
            rol="alumno"
        )
        emitir_evento_siem(
            "SELF_REGISTER_SUCCESS",
            f"src_ip={ip_origen} token={nuevo.token_opaco} rol=alumno",
            severidad=5
        )
        return render_template("login.html", success="Registro completado en la boveda PII. Ya puedes iniciar sesion.", tab="login")
    except Exception:
        return render_template("login.html", error_reg="No se pudo completar el registro (matricula o CURP ya registrada).", tab="registro"), 400

@auth_bp.route("/logout", methods=["POST", "GET"])
def logout():
    token = session.get("token_opaco", "anonimo")
    session.clear()
    emitir_evento_siem("AUTH_LOGOUT", f"actor={token}", severidad=6)
    return redirect(url_for("auth.login"))
