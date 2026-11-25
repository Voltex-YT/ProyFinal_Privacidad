import os
import json
from flask import Blueprint, request, session, jsonify, render_template, redirect, url_for
from models.usuario import Usuario
from models.db import get_academia_conn
from middleware.abac import require_purpose, emitir_evento_siem
from services.anonymizer import generar_dataset_safe_harbor

admin_bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/admin",
    template_folder=".",
    static_folder=".",
    static_url_path="/static_admin"
)

@admin_bp.route("/dashboard", methods=["GET"])
def dashboard():
    token = session.get("token_opaco")
    rol = session.get("rol")
    if not token or rol != "admin":
        return redirect(url_for("auth.login"))
    usr = Usuario.obtener_por_token(token)
    if not usr:
        session.clear()
        return redirect(url_for("auth.login"))
    perfil = usr.obtener_perfil(minimizar=False)
    return render_template("admin_dashboard.html", perfil=perfil)

@admin_bp.route("/usuarios", methods=["GET"])
@require_purpose("gestion_usuarios")
def listar_usuarios():
    admin = Usuario.obtener_por_token(session["token_opaco"])
    if not admin or admin.rol != "admin":
        return jsonify({"error": "Rol no autorizado"}), 403
    emitir_evento_siem("PII_QUERY", f"actor={admin.token_opaco} accion=listar_usuarios_minimizados", severidad=6)
    return jsonify({"usuarios": admin.listar_usuarios_minimizado()})

@admin_bp.route("/usuarios", methods=["POST"])
@require_purpose("gestion_usuarios")
def registrar_usuario():
    admin = Usuario.obtener_por_token(session["token_opaco"])
    if not admin or admin.rol != "admin":
        return jsonify({"error": "Rol no autorizado"}), 403

    data = request.get_json(silent=True) or request.form
    try:
        ttl = data.get("ttl_dias")
        ttl_valor = int(ttl) if ttl not in (None, "", "0", 0) else None
        nuevo = Usuario.crear_usuario(
            matricula=data["matricula"],
            nombre_completo=data["nombre_completo"],
            curp=data["curp"],
            correo=data["correo"],
            password_plano=data["password"],
            rol=data["rol"],
            ttl_dias=ttl_valor
        )
        emitir_evento_siem(
            "USER_CREATED",
            f"actor={admin.token_opaco} nuevo_token={nuevo.token_opaco} rol={nuevo.rol} ttl={ttl_valor}",
            severidad=5
        )
        return jsonify({"status": "creado", "token_opaco": nuevo.token_opaco, "rol": nuevo.rol}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@admin_bp.route("/materias", methods=["POST"])
@require_purpose("gestion_usuarios")
def crear_materia():
    admin = Usuario.obtener_por_token(session["token_opaco"])
    if not admin or admin.rol != "admin":
        return jsonify({"error": "Rol no autorizado"}), 403

    data = request.get_json(silent=True) or request.form
    try:
        id_mat = admin.crear_materia(
            clave_materia=data["clave_materia"],
            nombre_materia=data["nombre_materia"],
            matricula_profesor=data["matricula_profesor"]
        )
        emitir_evento_siem(
            "COURSE_CREATED",
            f"actor={admin.token_opaco} id_materia={id_mat} clave={data['clave_materia']}",
            severidad=6
        )
        return jsonify({"status": "materia_creada", "id_materia": id_mat}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@admin_bp.route("/exportar-estadisticas", methods=["GET"])
@require_purpose("exportacion_estadistica")
def exportar_safe_harbor():
    token = session["token_opaco"]
    dataset = generar_dataset_safe_harbor(k_minimo=3)
    emitir_evento_siem(
        "SAFE_HARBOR_EXPORT",
        f"actor={token} total_exportados={dataset['total_exportados']} suprimidos={dataset['registros_suprimidos_por_k']}",
        severidad=5
    )
    return jsonify(dataset)

@admin_bp.route("/bitacora-arco", methods=["GET"])
@require_purpose("auditoria_arco")
def consultar_bitacora_arco():
    conn = get_academia_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id_certificado, token_sanitizado, metodo_nist, hash_sha256, fecha_purga FROM bitacora_arco ORDER BY fecha_purga DESC")
            registros = cur.fetchall()
            for r in registros:
                r["fecha_purga"] = str(r["fecha_purga"])
        return jsonify({"bitacora_arco": registros})
    finally:
        conn.close()

@admin_bp.route("/telemetria-siem", methods=["GET"])
@require_purpose("auditoria_arco")
def telemetria_siem():
    log_path = "/app/siem_logs/siem_audit.log"
    alerts_path = "/app/siem_logs/siem_alerts.json"

    eventos = []
    if os.path.isfile(log_path):
        with open(log_path, "r", encoding="utf-8") as f:
            eventos = [line.strip() for line in f.readlines()[-15:]]

    alertas = []
    if os.path.isfile(alerts_path):
        with open(alerts_path, "r", encoding="utf-8") as f:
            for line in f.readlines()[-10:]:
                try:
                    alertas.append(json.loads(line))
                except Exception:
                    pass

    conn = get_academia_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT token_opaco, rol, LEFT(password_hash, 38) AS argon2_preview, salt, expira_en FROM usuarios_auth")
            usuarios_acad = cur.fetchall()
            for u in usuarios_acad:
                u["expira_en"] = str(u["expira_en"]) if u["expira_en"] else "Permanente"
            cur.execute("SELECT id_registro, token_alumno, id_materia, calificacion FROM calificaciones")
            califs = cur.fetchall()
            for c in califs:
                c["calificacion"] = float(c["calificacion"])
    finally:
        conn.close()

    return jsonify({
        "siem_eventos_rfc5424": eventos,
        "siem_alertas_correlacion": alertas,
        "bd_academia_sin_pii": {
            "usuarios_auth": usuarios_acad,
            "calificaciones": califs
        }
    })
