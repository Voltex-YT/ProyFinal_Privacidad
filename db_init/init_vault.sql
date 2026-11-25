CREATE DATABASE IF NOT EXISTS vault_pii CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE vault_pii;

CREATE TABLE identidades_pii (
    token_opaco VARCHAR(64) PRIMARY KEY,
    matricula VARCHAR(20) NOT NULL UNIQUE,
    nombre_completo VARCHAR(150) NOT NULL,
    curp VARCHAR(18) NOT NULL UNIQUE,
    correo VARCHAR(120) NOT NULL,
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
