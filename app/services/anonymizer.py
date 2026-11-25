from collections import Counter
from models.db import get_academia_conn

def generalizar_calificacion(nota):
    valor = float(nota)
    if valor >= 9.0:
        return "9.0 - 10.0 (Sobresaliente)"
    if valor >= 8.0:
        return "8.0 - 8.9 (Notable)"
    if valor >= 7.0:
        return "7.0 - 7.9 (Suficiente)"
    if valor >= 6.0:
        return "6.0 - 6.9 (Minimo Aprobatorio)"
    return "< 6.0 (No Aprobado)"

def generar_dataset_safe_harbor(k_minimo=3):
    conn = get_academia_conn()
    try:
        with conn.cursor() as cur:
            sql = """
                SELECT m.clave_materia, m.nombre_materia, c.calificacion, YEAR(c.fecha_registro) AS anio_cohorte
                FROM calificaciones c
                INNER JOIN materias m ON c.id_materia = m.id_materia
            """
            cur.execute(sql)
            filas = cur.fetchall()

        registros_generalizados = []
        for f in filas:
            registros_generalizados.append({
                "clave_materia": f["clave_materia"],
                "nombre_materia": f["nombre_materia"],
                "rango_calificacion": generalizar_calificacion(f["calificacion"]),
                "anio_cohorte": int(f["anio_cohorte"])
            })

        conteo_clases = Counter(
            (r["clave_materia"], r["rango_calificacion"], r["anio_cohorte"])
            for r in registros_generalizados
        )

        dataset_k_anonimo = []
        suprimidos = 0
        for r in registros_generalizados:
            clase = (r["clave_materia"], r["rango_calificacion"], r["anio_cohorte"])
            if conteo_clases[clase] >= k_minimo:
                dataset_k_anonimo.append(r)
            else:
                suprimidos += 1

        return {
            "metodo": "HIPAA Safe Harbor + k-Anonimato",
            "k_aplicado": k_minimo,
            "identificadores_removidos": [
                "token_opaco", "matricula", "nombre_completo", "curp", "correo", "fecha_exacta", "calificacion_exacta"
            ],
            "total_exportados": len(dataset_k_anonimo),
            "registros_suprimidos_por_k": suprimidos,
            "datos": dataset_k_anonimo
        }
    finally:
        conn.close()
