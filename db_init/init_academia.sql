CREATE DATABASE IF NOT EXISTS academia_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE academia_db;

CREATE TABLE usuarios_auth (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token_opaco VARCHAR(64) NOT NULL UNIQUE,
    rol ENUM('admin', 'profesor', 'alumno') NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(64) NOT NULL,
    foto_ruta VARCHAR(255) DEFAULT NULL,
    expira_en DATETIME NULL,
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE materias (
    id_materia INT AUTO_INCREMENT PRIMARY KEY,
    clave_materia VARCHAR(20) NOT NULL UNIQUE,
    nombre_materia VARCHAR(120) NOT NULL,
    token_profesor VARCHAR(64) NOT NULL
);

CREATE TABLE calificaciones (
    id_registro INT AUTO_INCREMENT PRIMARY KEY,
    token_alumno VARCHAR(64) NOT NULL,
    id_materia INT NOT NULL,
    calificacion DECIMAL(4,2) NOT NULL,
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_materia) REFERENCES materias(id_materia) ON DELETE CASCADE
);

CREATE TABLE bitacora_arco (
    id_certificado VARCHAR(64) PRIMARY KEY,
    token_sanitizado VARCHAR(64) NOT NULL,
    metodo_nist VARCHAR(50) NOT NULL,
    hash_sha256 VARCHAR(64) NOT NULL,
    fecha_purga TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
