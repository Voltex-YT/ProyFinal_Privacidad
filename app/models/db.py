import os
import pymysql
from pymysql.cursors import DictCursor

def get_academia_conn():
    return pymysql.connect(
        host=os.getenv("ACADEMIA_DB_HOST", "academia_db"),
        user="academia_user",
        password=os.getenv("ACADEMIA_DB_PASS"),
        database="academia_db",
        charset="utf8mb4",
        cursorclass=DictCursor,
        autocommit=False
    )

def get_vault_conn():
    return pymysql.connect(
        host=os.getenv("VAULT_DB_HOST", "vault_pii"),
        user="vault_user",
        password=os.getenv("VAULT_DB_PASS"),
        database="vault_pii",
        charset="utf8mb4",
        cursorclass=DictCursor,
        autocommit=False
    )
