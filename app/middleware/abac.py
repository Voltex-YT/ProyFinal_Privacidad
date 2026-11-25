import os
import socket
import datetime
from functools import wraps
from flask import session, request, jsonify

MATRIZ_POLITICAS_ABAC = {
    "admin": {
        "gestion_usuarios": {"minimizar_pii": True},
        "auditoria_arco": {"minimizar_pii": False},
        "exportacion_estadistica": {"minimizar_pii": True},
        "perfil_propio": {"minimizar_pii": False}
    },
    "profesor": {
        "captura_calificaciones": {"minimizar_pii": True},
        "consulta_materias": {"minimizar_pii": True},
        "perfil_propio": {"minimizar_pii": False}
    },
    "alumno": {
        "consulta_kardex": {"minimizar_pii": False},
        "perfil_propio": {"minimizar_pii": False},
        "ejercicio_arco": {"minimizar_pii": False}
    }
}

def emitir_evento_siem(msgid, mensaje, severidad=4):
    pri = (16 * 8) + severidad
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    paquete = f"<{pri}>1 {timestamp} priva-flask academia-app {os.getpid()} {msgid} - {mensaje}"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(
            paquete.encode("utf-8"),
            (os.getenv("SIEM_HOST", "siem_collector"), int(os.getenv("SIEM_PORT", 5514)))
        )
    finally:
        sock.close()

def require_purpose(proposito_requerido):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            token = session.get("token_opaco")
            rol = session.get("rol")

            if not token or not rol:
                return jsonify({"error": "Sesion no autenticada"}), 401

            proposito_declarado = (
                request.headers.get("X-Purpose")
                or request.args.get("purpose")
                or request.form.get("purpose")
                or (request.get_json(silent=True) or {}).get("purpose")
                or proposito_requerido
            )

            politicas_rol = MATRIZ_POLITICAS_ABAC.get(rol, {})

            if proposito_declarado != proposito_requerido or proposito_requerido not in politicas_rol:
                emitir_evento_siem(
                    "ABAC_DENIED",
                    f"actor={token} rol={rol} intento_proposito={proposito_declarado} esperado={proposito_requerido} ruta={request.path}",
                    severidad=4
                )
                return jsonify({
                    "error": "Acceso denegado por politica ABAC (Function Creep bloqueado)",
                    "rol": rol,
                    "proposito_declarado": proposito_declarado
                }), 403

            request.abac_policy = politicas_rol[proposito_requerido]
            return f(*args, **kwargs)
        return wrapped
    return decorator
