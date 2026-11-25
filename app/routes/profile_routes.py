import os
from flask import Blueprint, request, session, jsonify, send_from_directory, current_app
from models.usuario import Usuario
from middleware.abac import require_purpose, emitir_evento_siem
from services.image_sanitizer import sanitizar_y_guardar_avatar
from services.arco_cert import ejecutar_supresion_arco

profile_bp = Blueprint("profile", __name__, url_prefix="/perfil")

@profile_bp.route("/datos", methods=["GET"])
@require_purpose("perfil_propio")
def obtener_datos():
    usr = Usuario.obtener_por_token(session["token_opaco"])
    if not usr:
        session.clear()
        return jsonify({"error": "Usuario no encontrado"}), 404
    emitir_evento_siem("PII_QUERY", f"actor={usr.token_opaco} accion=consulta_perfil_propio", severidad=6)
    return jsonify({"perfil": usr.obtener_perfil(minimizar=False)})

@profile_bp.route("/rectificar", methods=["POST"])
@require_purpose("perfil_propio")
def rectificar_datos():
    usr = Usuario.obtener_por_token(session["token_opaco"])
    if not usr:
        session.clear()
        return jsonify({"error": "Usuario no encontrado"}), 404

    data = request.get_json(silent=True) or request.form
    nuevo_correo = (data.get("correo") or "").strip() or None
    nueva_pass = data.get("password") or None

    usr.rectificar_datos(nuevo_correo=nuevo_correo, nueva_password=nueva_pass)
    emitir_evento_siem(
        "ARCO_RECTIFICATION",
        f"actor={usr.token_opaco} cambio_correo={bool(nuevo_correo)} cambio_pass={bool(nueva_pass)}",
        severidad=5
    )
    return jsonify({"status": "rectificado", "perfil": usr.obtener_perfil(minimizar=False)})

@profile_bp.route("/foto", methods=["POST"])
@require_purpose("perfil_propio")
def subir_foto():
    usr = Usuario.obtener_por_token(session["token_opaco"])
    if not usr:
        session.clear()
        return jsonify({"error": "Usuario no encontrado"}), 404

    if "foto" not in request.files:
        return jsonify({"error": "Archivo de imagen requerido"}), 400

    archivo = request.files["foto"]
    perfil = usr.obtener_perfil(minimizar=False)
    try:
        nombre_guardado = sanitizar_y_guardar_avatar(
            archivo,
            perfil["matricula"],
            current_app.config["UPLOAD_FOLDER"]
        )
        usr.actualizar_foto(nombre_guardado)
        emitir_evento_siem("IMAGE_EXIF_PURGED", f"actor={usr.token_opaco} archivo={nombre_guardado}", severidad=6)
        return jsonify({"status": "imagen_sanitizada_sin_exif", "archivo": nombre_guardado})
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400

@profile_bp.route("/foto/<filename>", methods=["GET"])
def ver_foto_protegida(filename):
    if not session.get("token_opaco"):
        return jsonify({"error": "Sesion no autenticada"}), 401
    usr = Usuario.obtener_por_token(session["token_opaco"])
    if not usr:
        session.clear()
        return jsonify({"error": "Usuario inexistente"}), 401
    perfil = usr.obtener_perfil(minimizar=False)
    if usr.rol != "admin" and perfil.get("foto_ruta") != filename:
        emitir_evento_siem("UNAUTHORIZED_FILE_ACCESS", f"actor={usr.token_opaco} archivo={filename}", severidad=4)
        return jsonify({"error": "Acceso denegado a archivo ajeno"}), 403
    return send_from_directory(current_app.config["UPLOAD_FOLDER"], filename)

@profile_bp.route("/arco/supresion", methods=["POST"])
@require_purpose("ejercicio_arco")
def supresion_arco():
    token = session.get("token_opaco")
    usr = Usuario.obtener_por_token(token)
    if not usr:
        session.clear()
        return jsonify({"error": "Usuario no encontrado"}), 404

    cert = ejecutar_supresion_arco(
        token,
        current_app.config["UPLOAD_FOLDER"],
        current_app.config["CERT_FOLDER"]
    )
    emitir_evento_siem(
        "ARCO_SUPPRESSION_NIST",
        f"token_sanitizado={cert['token_sanitizado']} cert={cert['id_certificado']} sha256={cert['hash_sha256']}",
        severidad=5
    )

    session.clear()
    return jsonify({
        "status": "suprimido_nist_800_88",
        "sesion_cerrada": True,
        "certificado": cert
    })

@profile_bp.route("/arco/certificado/<id_cert>/<formato>", methods=["GET"])
def descargar_certificado(id_cert, formato):
    seguro_id = os.path.basename(id_cert)
    if formato == "pdf":
        nombre = f"{seguro_id}.pdf"
    elif formato == "json":
        nombre = f"{seguro_id}.json"
    else:
        return jsonify({"error": "Formato invalido"}), 400

    ruta = os.path.join(current_app.config["CERT_FOLDER"], nombre)
    if not os.path.isfile(ruta):
        return jsonify({"error": "Certificado no encontrado"}), 404
    return send_from_directory(current_app.config["CERT_FOLDER"], nombre, as_attachment=True)
