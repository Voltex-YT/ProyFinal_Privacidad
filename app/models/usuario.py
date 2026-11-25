import os
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from models.db import get_academia_conn
from models.vault_client import VaultClient

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)

class Usuario:
    def __init__(self, id_usuario, token_opaco, rol, foto_ruta=None):
        self.id = id_usuario
        self.token_opaco = token_opaco
        self.rol = rol
        self.foto_ruta = foto_ruta

    @staticmethod
    def _aplicar_pepper(password_plano, salt_hex):
        pepper = os.getenv("APP_PEPPER", "").encode("utf-8")
        combinado = f"{salt_hex}:{password_plano}".encode("utf-8")
        return hmac.new(pepper, combinado, hashlib.sha256).hexdigest()

    @classmethod
    def crear_usuario(cls, matricula, nombre_completo, curp, correo, password_plano, rol, ttl_dias=None):
        token_opaco = VaultClient.registrar_identidad(matricula, nombre_completo, curp, correo)
        salt_hex = secrets.token_hex(16)
        secreto_preparado = cls._aplicar_pepper(password_plano, salt_hex)
        password_hash = ph.hash(secreto_preparado)
        expira_en = None
        if ttl_dias is not None:
            expira_en = (datetime.now(timezone.utc) + timedelta(days=int(ttl_dias))).strftime("%Y-%m-%d %H:%M:%S")

        conn = get_academia_conn()
        try:
            with conn.cursor() as cur:
                sql = """
                    INSERT INTO usuarios_auth (token_opaco, rol, password_hash, salt, expira_en)
                    VALUES (%s, %s, %s, %s, %s)
                """
                cur.execute(sql, (token_opaco, rol, password_hash, salt_hex, expira_en))
                user_id = cur.lastrowid
            conn.commit()
            return cls._instanciar_por_rol(user_id, token_opaco, rol, None)
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @classmethod
    def autenticar(cls, matricula, password_plano):
        token_opaco = VaultClient.obtener_token_por_matricula(matricula)
        if not token_opaco:
            return None

        conn = get_academia_conn()
        try:
            with conn.cursor() as cur:
                sql = """
                    SELECT id, token_opaco, rol, password_hash, salt, foto_ruta, expira_en
                    FROM usuarios_auth
                    WHERE token_opaco = %s
                """
                cur.execute(sql, (token_opaco,))
                row = cur.fetchone()
                if not row:
                    return None

                if row["expira_en"] and row["expira_en"] < datetime.now(timezone.utc).replace(tzinfo=None):
                    return None

                secreto_preparado = cls._aplicar_pepper(password_plano, row["salt"])
                try:
                    ph.verify(row["password_hash"], secreto_preparado)
                except VerifyMismatchError:
                    return None

                return cls._instanciar_por_rol(row["id"], row["token_opaco"], row["rol"], row["foto_ruta"])
        finally:
            conn.close()

    @classmethod
    def obtener_por_token(cls, token_opaco):
        conn = get_academia_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, token_opaco, rol, foto_ruta FROM usuarios_auth WHERE token_opaco = %s",
                    (token_opaco,)
                )
                row = cur.fetchone()
                if not row:
                    return None
                return cls._instanciar_por_rol(row["id"], row["token_opaco"], row["rol"], row["foto_ruta"])
        finally:
            conn.close()

    @staticmethod
    def _instanciar_por_rol(id_usuario, token_opaco, rol, foto_ruta):
        if rol == "admin":
            return Admin(id_usuario, token_opaco, foto_ruta)
        if rol == "profesor":
            return Profesor(id_usuario, token_opaco, foto_ruta)
        return Alumno(id_usuario, token_opaco, foto_ruta)

    def actualizar_foto_perfil(self, nombre_archivo):
        conn = get_academia_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE usuarios_auth SET foto_ruta = %s WHERE token_opaco = %s",
                    (nombre_archivo, self.token_opaco)
                )
            conn.commit()
            self.foto_ruta = nombre_archivo
            return True
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def actualizar_datos_contacto(self, nuevo_correo=None, nueva_password=None):
        if nuevo_correo:
            VaultClient.actualizar_correo(self.token_opaco, nuevo_correo)
        if nueva_password:
            salt_hex = secrets.token_hex(16)
            secreto_preparado = self._aplicar_pepper(nueva_password, salt_hex)
            password_hash = ph.hash(secreto_preparado)
            conn = get_academia_conn()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE usuarios_auth SET password_hash = %s, salt = %s WHERE token_opaco = %s",
                        (password_hash, salt_hex, self.token_opaco)
                    )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
        return True

    def obtener_perfil(self, minimizar=False):
        identidad = VaultClient.resolver_identidad(self.token_opaco, minimizar=minimizar)
        if not identidad:
            return None
        identidad["rol"] = self.rol
        identidad["foto_ruta"] = self.foto_ruta
        return identidad


class Admin(Usuario):
    def __init__(self, id_usuario, token_opaco, foto_ruta=None):
        super().__init__(id_usuario, token_opaco, "admin", foto_ruta)

    def crear_materia(self, clave_materia, nombre_materia, matricula_profesor):
        token_profesor = VaultClient.obtener_token_por_matricula(matricula_profesor)
        if not token_profesor:
            raise ValueError("Profesor no encontrado en la boveda PII")
        conn = get_academia_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO materias (clave_materia, nombre_materia, token_profesor) VALUES (%s, %s, %s)",
                    (clave_materia.strip().upper(), nombre_materia.strip(), token_profesor)
                )
                id_mat = cur.lastrowid
            conn.commit()
            return id_mat
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def listar_usuarios_minimizado(self):
        conn = get_academia_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT token_opaco, rol, expira_en, creado_en FROM usuarios_auth")
                filas = cur.fetchall()
            resultado = []
            for f in filas:
                pii = VaultClient.resolver_identidad(f["token_opaco"], minimizar=True)
                if pii:
                    pii["rol"] = f["rol"]
                    pii["expira_en"] = str(f["expira_en"]) if f["expira_en"] else "Permanente"
                    resultado.append(pii)
            return resultado
        finally:
            conn.close()


class Profesor(Usuario):
    def __init__(self, id_usuario, token_opaco, foto_ruta=None):
        super().__init__(id_usuario, token_opaco, "profesor", foto_ruta)

    def obtener_materias_asignadas(self):
        conn = get_academia_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id_materia, clave_materia, nombre_materia FROM materias WHERE token_profesor = %s",
                    (self.token_opaco,)
                )
                return cur.fetchall()
        finally:
            conn.close()

    def registrar_calificacion(self, matricula_alumno, id_materia, calificacion):
        token_alumno = VaultClient.obtener_token_por_matricula(matricula_alumno)
        if not token_alumno:
            raise ValueError("Alumno no encontrado en la boveda PII")
        conn = get_academia_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id_materia FROM materias WHERE id_materia = %s AND token_profesor = %s",
                    (id_materia, self.token_opaco)
                )
                if not cur.fetchone():
                    raise PermissionError("La materia no pertenece a este profesor")

                cur.execute(
                    "SELECT id_registro FROM calificaciones WHERE token_alumno = %s AND id_materia = %s",
                    (token_alumno, id_materia)
                )
                existente = cur.fetchone()
                if existente:
                    cur.execute(
                        "UPDATE calificaciones SET calificacion = %s WHERE id_registro = %s",
                        (float(calificacion), existente["id_registro"])
                    )
                else:
                    cur.execute(
                        "INSERT INTO calificaciones (token_alumno, id_materia, calificacion) VALUES (%s, %s, %s)",
                        (token_alumno, id_materia, float(calificacion))
                    )
            conn.commit()
            return True
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


class Alumno(Usuario):
    def __init__(self, id_usuario, token_opaco, foto_ruta=None):
        super().__init__(id_usuario, token_opaco, "alumno", foto_ruta)

    def consultar_kardex(self):
        conn = get_academia_conn()
        try:
            with conn.cursor() as cur:
                sql = """
                    SELECT m.clave_materia, m.nombre_materia, c.calificacion, c.fecha_registro
                    FROM calificaciones c
                    INNER JOIN materias m ON c.id_materia = m.id_materia
                    WHERE c.token_alumno = %s
                """
                cur.execute(sql, (self.token_opaco,))
                return cur.fetchall()
        finally:
            conn.close()
