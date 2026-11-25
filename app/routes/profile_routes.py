import os
from flask import Blueprint, request, session, jsonify, send_from_directory, current_app
from models.usuario import Usuario
from middleware.abac import require_purpose, emitir_evento_siem
from services.image_sanitizer import sanitizar_y_guardar_avatar
from services.arco_cert import ejecutar_supresion_arco

profile_bp = Blueprint("profile", __name__, url_prefix="/perfil")

@profile_bp.route("/datos", methods=["GET"])
@require_purpose("perfil_propio")
def obtener_mis_datos():
    usr = Usuario.obtener_por_token(session["token_opaco"])
    if not usr:
        return jsonify({"error": "Usuario no encontrado"}), 404
    emitir_evento_siem("PII_QUERY", f"actor={usr.token_opaco} recurso=perfil_propio", severidad=6)
    return jsonify({"perfil": usr.obtener_perfil(minimizar=False)})

@profile_bp.route("/rectificar", methods=["POST"])
@require_purpose("perfil_propio")
def rectificar_datos():
    usr = Usuario.obtener_por_token(session["token_opaco"])
    if not usr:
        return jsonify({"error": "Usuario no encontrado"}), 404

    data = request.get_json(silent=True) or request.form
    nuevo_correo = data.get("correo")
    nueva_pass = data.get("password")
    try:
        usr.actualizar_datos_contacto(nuevo_correo=nuevo_correo, nueva_password=nueva_pass)
        emitir_evento_siem("ARCO_RECTIFICATION", f"actor={usr.token_opaco}", severidad=5)
        return jsonify({"status": "datos_actualizados"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@profile_bp.route("/foto", methods=["POST"])
@require_purpose("perfil_propio")
def subir_foto():
    usr = Usuario.obtener_por_token(session["token_opaco"])
    if not usr:
        return jsonify({"error": "Usuario no encontrado"}), 404

    perfil = usr.obtener_perfil(minimizar=False)
    archivo = request.files.get("foto")
    try:
        nombre_limpio = sanitizar_y_guardar_avatar(
            archivo,
            perfil["matricula"],
            current_app.config["UPLOAD_FOLDER"]
        )
        usr.actualizar_foto_perfil(nombre_limpio)
        emitir_evento_siem("AVATAR_SANITIZED_UPLOAD", f"actor={usr.token_opaco} archivo={nombre_limpio}", severidad=6)
        return jsonify({"status": "foto_sanitizada_y_guardada", "archivo": nombre_limpio})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@profile_bp.route("/foto/<path:filename>", methods=["GET"])
@require_purpose("perfil_propio")
def ver_foto_protegida(filename):
    usr = Usuario.obtener_por_token(session["token_opaco"])
    if not usr or usr.foto_ruta != filename:
        return jsonify({"error": "Acceso denegado al recurso de imagen"}), 403
    return send_from_directory(current_app.config["UPLOAD_FOLDER"], filename)

@profile_bp.route("/arco/supresion", methods=["POST"])
@require_purpose("ejercicio_arco")
def solicitar_supresion_arco():
    token = session["token_opaco"]
    try:
        certificado = ejecutar_supresion_arco(
            token,
            current_app.config["UPLOAD_FOLDER"],
            current_app.config["CERT_FOLDER"]
        )
        session.clear()
        return jsonify({"status": "supresion_completada", "certificado": certificado})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@profile_bp.route("/arco/certificado/<id_cert>/<formato>", methods=["GET"])
def descargar_certificado(id_cert, formato):
    if formato not in ("json", "pdf"):
        return jsonify({"error": "Formato no soportado"}), 400
    nombre = f"{id_cert}.{formato}"
    ruta = os.path.join(current_app.config["CERT_FOLDER"], nombre)
    if not os.path.isfile(ruta):
        return jsonify({"error": "Certificado no encontrado"}), 404
    return send_from_directory(current_app.config["CERT_FOLDER"], nombre, as_attachment=True)
