from flask import Blueprint, request, session, jsonify, render_template, redirect, url_for
from models.usuario import Usuario
from middleware.abac import require_purpose, emitir_evento_siem

profe_bp = Blueprint(
    "profe",
    __name__,
    url_prefix="/profesor",
    template_folder=".",
    static_folder=".",
    static_url_path="/static_profe"
)

@profe_bp.route("/dashboard", methods=["GET"])
def dashboard():
    token = session.get("token_opaco")
    rol = session.get("rol")
    if not token or rol != "profesor":
        return redirect(url_for("auth.login"))
    usr = Usuario.obtener_por_token(token)
    if not usr:
        session.clear()
        return redirect(url_for("auth.login"))
    perfil = usr.obtener_perfil(minimizar=False)
    return render_template("profe_dashboard.html", perfil=perfil)

@profe_bp.route("/materias", methods=["GET"])
@require_purpose("consulta_materias")
def materias_profesor():
    prof = Usuario.obtener_por_token(session["token_opaco"])
    if not prof or prof.rol != "profesor":
        return jsonify({"error": "Rol no autorizado"}), 403
    emitir_evento_siem("GRADE_READ", f"actor={prof.token_opaco} recurso=materias_asignadas", severidad=6)
    return jsonify({"materias": prof.obtener_materias_asignadas()})

@profe_bp.route("/calificaciones", methods=["POST"])
@require_purpose("captura_calificaciones")
def capturar_calificacion():
    prof = Usuario.obtener_por_token(session["token_opaco"])
    if not prof or prof.rol != "profesor":
        return jsonify({"error": "Rol no autorizado"}), 403

    data = request.get_json(silent=True) or request.form
    try:
        prof.registrar_calificacion(
            matricula_alumno=data["matricula_alumno"],
            id_materia=int(data["id_materia"]),
            calificacion=float(data["calificacion"])
        )
        emitir_evento_siem(
            "GRADE_WRITE",
            f"actor={prof.token_opaco} materia={data['id_materia']} calificacion={data['calificacion']}",
            severidad=5
        )
        return jsonify({"status": "calificacion_registrada"})
    except PermissionError as pe:
        return jsonify({"error": str(pe)}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 400
