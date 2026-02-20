CREATE DATABASE IF NOT EXISTS password_api_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

GRANT ALL PRIVILEGES ON password_api_db.* TO 'db_21030222'@'localhost' IDENTIFIED BY '21030222';
FLUSH PRIVILEGES;

USE password_api_db;

CREATE TABLE IF NOT EXISTS password_requests (
    id                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id             INT UNSIGNED        NULL     COMMENT 'Usuario que la generó (opcional)',
    length              TINYINT UNSIGNED    NOT NULL COMMENT 'Longitud solicitada',
    include_uppercase   TINYINT(1)          NOT NULL DEFAULT 1,
    include_lowercase   TINYINT(1)          NOT NULL DEFAULT 1,
    include_numbers     TINYINT(1)          NOT NULL DEFAULT 1,
    include_symbols     TINYINT(1)          NOT NULL DEFAULT 1,
    exclude_ambiguous   TINYINT(1)          NOT NULL DEFAULT 0,
    count               TINYINT UNSIGNED    NOT NULL DEFAULT 1 COMMENT 'Cantidad de contraseñas generadas',
    created_at          TIMESTAMP           NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_user    (user_id),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  COMMENT='Auditoria de solicitudes de generacion. Sin texto plano.';


CREATE TABLE IF NOT EXISTS generated_passwords (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    request_id      INT UNSIGNED     NOT NULL           COMMENT 'Relacion con la solicitud',
    password_hash   VARCHAR(255)     NOT NULL           COMMENT 'Hash bcrypt de la contrasena',
    strength_score  TINYINT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'Nivel de seguridad 0-100',
    created_at      TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (request_id) REFERENCES password_requests(id) ON DELETE CASCADE,
    INDEX idx_request  (request_id),
    INDEX idx_strength (strength_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  COMMENT='Hashes bcrypt. Permite auditoria y deteccion de duplicados.';

CREATE TABLE IF NOT EXISTS password_validations (
    id                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    password_hash       VARCHAR(255) NOT NULL COMMENT 'Hash bcrypt de la contrasena evaluada',
    requirements_json   JSON         NOT NULL COMMENT 'Requisitos enviados por el cliente',
    result              TINYINT(1)   NOT NULL COMMENT '1 = cumple requisitos, 0 = no cumple',
    created_at          TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_result  (result),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  COMMENT='Log de cada validacion de fortaleza solicitada.';