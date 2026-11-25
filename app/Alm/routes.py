from flask import Blueprint, session, jsonify, render_template, redirect, url_for
from models.usuario import Usuario
from middleware.abac import require_purpose, emitir_evento_siem

alm_bp = Blueprint(
    "alm",
    __name__,
    url_prefix="/alumno",
    template_folder=".",
    static_folder=".",
    static_url_path="/static_alm"
)

@alm_bp.route("/dashboard", methods=["GET"])
def dashboard():
    token = session.get("token_opaco")
    rol = session.get("rol")
    if not token or rol != "alumno":
        return redirect(url_for("auth.login"))
    usr = Usuario.obtener_por_token(token)
    if not usr:
        session.clear()
        return redirect(url_for("auth.login"))
    perfil = usr.obtener_perfil(minimizar=False)
    return render_template("alm_dashboard.html", perfil=perfil)

@alm_bp.route("/kardex", methods=["GET"])
@require_purpose("consulta_kardex")
def kardex_alumno():
    alumno = Usuario.obtener_por_token(session["token_opaco"])
    if not alumno or alumno.rol != "alumno":
        return jsonify({"error": "Rol no autorizado"}), 403
    emitir_evento_siem("GRADE_READ", f"actor={alumno.token_opaco} recurso=kardex_propio", severidad=6)
    kardex = alumno.consultar_kardex()
    for item in kardex:
        item["calificacion"] = float(item["calificacion"])
        item["fecha_registro"] = str(item["fecha_registro"])
    return jsonify({"kardex": kardex})
