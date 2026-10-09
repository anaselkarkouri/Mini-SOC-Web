-- Module historique M2 (Omar Babba). Pour une nouvelle base uniquement.
-- Sur une base existante, utiliser migration_20261009.sql après sauvegarde.
USE minisoc_shop;
CREATE TABLE IF NOT EXISTS http_logs (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    event_id      CHAR(32) NOT NULL UNIQUE,
    timestamp     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP  COMMENT 'Date et heure de la requete',
    ip_source     VARCHAR(45)   NOT NULL                            COMMENT 'Adresse IP source de l utilisateur ou attaquant',
    method        VARCHAR(10)   NOT NULL                            COMMENT 'Methode HTTP : GET ou POST',
    url           VARCHAR(512)  NOT NULL                            COMMENT 'Page PHP ciblee par la requete',
    params        TEXT                                              COMMENT 'Parametres GET et POST en JSON (prefixes GET_ / POST_)',
    user_agent    VARCHAR(512)                                      COMMENT 'Navigateur ou outil utilise (sqlmap, Hydra, curl, etc.)',
    response_code SMALLINT      NOT NULL DEFAULT 200               COMMENT 'Code HTTP retourne par l application',
    processed     TINYINT(1)    NOT NULL DEFAULT 0                  COMMENT '0 = non analyse, 1 = traite par le Mini-SIEM',
    INDEX idx_http_pending (processed,timestamp,id),
    INDEX idx_http_login (ip_source,timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
