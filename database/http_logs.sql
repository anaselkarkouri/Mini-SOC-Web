-- Mini-SOC Web — Module M2 : Collecteur de logs HTTP
-- Responsable : Omar Babba
--
-- Ce fichier cree la table http_logs dans la base minisoc_shop.
-- A importer via phpMyAdmin ou la commande :
--   mysql -u root minisoc_shop < database/http_logs.sql
--
-- Note : n importe ce fichier QU APRES avoir importe schema.sql
--        (la base minisoc_shop doit exister).

USE minisoc_shop;

DROP TABLE IF EXISTS http_logs;

CREATE TABLE http_logs (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    timestamp     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP  COMMENT 'Date et heure de la requete',
    ip_source     VARCHAR(45)   NOT NULL                            COMMENT 'Adresse IP source de l utilisateur ou attaquant',
    method        VARCHAR(10)   NOT NULL                            COMMENT 'Methode HTTP : GET ou POST',
    url           VARCHAR(512)  NOT NULL                            COMMENT 'Page PHP ciblee par la requete',
    params        TEXT                                              COMMENT 'Parametres GET et POST en JSON (prefixes GET_ / POST_)',
    user_agent    VARCHAR(512)                                      COMMENT 'Navigateur ou outil utilise (sqlmap, Hydra, curl, etc.)',
    response_code SMALLINT      NOT NULL DEFAULT 200               COMMENT 'Code HTTP retourne par l application',
    processed     TINYINT(1)    NOT NULL DEFAULT 0                  COMMENT '0 = non analyse, 1 = traite par le Mini-SIEM'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
