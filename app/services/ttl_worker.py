from datetime import datetime, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from models.db import get_academia_conn
from services.arco_cert import ejecutar_supresion_arco
from middleware.abac import emitir_evento_siem

def purgar_registros_caducados(upload_dir, cert_dir):
    ahora = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_academia_conn()
    tokens_vencidos = []
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT token_opaco FROM usuarios_auth WHERE expira_en IS NOT NULL AND expira_en <= %s",
                (ahora,)
            )
            tokens_vencidos = [row["token_opaco"] for row in cur.fetchall()]
    finally:
        conn.close()

    for token in tokens_vencidos:
        try:
            cert = ejecutar_supresion_arco(token, upload_dir, cert_dir)
            emitir_evento_siem(
                "TTL_EXPIRED_PURGE",
                f"token={token} certificado={cert['id_certificado']}",
                severidad=6
            )
        except Exception as e:
            emitir_evento_siem("TTL_PURGE_ERROR", f"token={token} detalle={str(e)}", severidad=3)

def iniciar_scheduler_ttl(upload_dir, cert_dir):
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        purgar_registros_caducados,
        trigger="interval",
        seconds=60,
        args=[upload_dir, cert_dir],
        id="ttl_purga_automatica",
        replace_existing=True
    )
    scheduler.start()
    return scheduler
