import secrets
from models.db import get_vault_conn

class VaultClient:
    @staticmethod
    def generar_token():
        return f"tok_{secrets.token_hex(24)}"

    @staticmethod
    def registrar_identidad(matricula, nombre_completo, curp, correo):
        token = VaultClient.generar_token()
        conn = get_vault_conn()
        try:
            with conn.cursor() as cur:
                sql = """
                    INSERT INTO identidades_pii (token_opaco, matricula, nombre_completo, curp, correo)
                    VALUES (%s, %s, %s, %s, %s)
                """
                cur.execute(sql, (token, matricula.strip(), nombre_completo.strip(), curp.strip().upper(), correo.strip().lower()))
            conn.commit()
            return token
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def obtener_token_por_matricula(matricula):
        conn = get_vault_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT token_opaco FROM identidades_pii WHERE matricula = %s", (matricula.strip(),))
                row = cur.fetchone()
                return row["token_opaco"] if row else None
        finally:
            conn.close()

    @staticmethod
    def resolver_identidad(token_opaco, minimizar=False):
        conn = get_vault_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT token_opaco, matricula, nombre_completo, curp, correo FROM identidades_pii WHERE token_opaco = %s",
                    (token_opaco,)
                )
                row = cur.fetchone()
                if not row:
                    return None
                if minimizar:
                    partes = row["nombre_completo"].split()
                    nombre_min = f"{partes[0]} {partes[1][0]}." if len(partes) > 1 else partes[0]
                    return {
                        "token_opaco": row["token_opaco"],
                        "matricula": f"***{row['matricula'][-4:]}",
                        "nombre_completo": nombre_min,
                        "curp": f"{row['curp'][:4]}**********{row['curp'][-2:]}",
                        "correo": "***@buap.mx"
                    }
                return row
        finally:
            conn.close()

    @staticmethod
    def actualizar_correo(token_opaco, nuevo_correo):
        conn = get_vault_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE identidades_pii SET correo = %s WHERE token_opaco = %s",
                    (nuevo_correo.strip().lower(), token_opaco)
                )
            conn.commit()
            return True
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
