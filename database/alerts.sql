-- Mini-SOC Web — Module M3 : Moteur Python Mini-SIEM
-- Responsable : Fadoua El-Allagui
--
-- Ce fichier cree les tables alerts et threat_score dans la base minisoc_shop.
-- A importer via phpMyAdmin ou la commande :
--   mysql -u root minisoc_shop < mini_siem/m3_alerts.sql
--
-- Note : n importe ce fichier QU APRES avoir importe schema.sql et http_logs.sql
--        (la base minisoc_shop et la table http_logs doivent exister).

USE minisoc_shop;

-- --------------------------------------------------------
-- Table alerts
-- Stocke chaque attaque detectee par mini_siem.py
-- enrichie avec les donnees MITRE ATT&CK
-- --------------------------------------------------------

DROP TABLE IF EXISTS alerts;

CREATE TABLE alerts (
    id                   INT AUTO_INCREMENT PRIMARY KEY,
    timestamp            DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP  COMMENT 'Date et heure de detection de l attaque',
    log_id               INT           NOT NULL                            COMMENT 'Reference vers http_logs.id (log source)',
    attack_type          VARCHAR(100)  NOT NULL                            COMMENT 'Type : SQL Injection | Cross-Site Scripting | Brute Force',
    severity             VARCHAR(20)   NOT NULL                            COMMENT 'Gravite : LOW | MEDIUM | HIGH | CRITICAL',
    description          TEXT                                              COMMENT 'Description lisible de l attaque detectee',
    payload              TEXT                                              COMMENT 'Contenu suspect envoye par l attaquant',
    source_ip            VARCHAR(45)   NOT NULL                            COMMENT 'Adresse IP de l attaquant',
    url                  VARCHAR(255)  NOT NULL                            COMMENT 'Page web ciblee par l attaque',
    mitre_id             VARCHAR(20)                                       COMMENT 'Identifiant MITRE ATT&CK ex: T1190',
    mitre_tactic         VARCHAR(100)                                      COMMENT 'Tactique MITRE ex: Initial Access',
    mitre_technique      VARCHAR(200)                                      COMMENT 'Technique MITRE ex: Exploit Public-Facing Application',
    recommended_response TEXT                                              COMMENT 'Action recommandee pour traiter l attaque',
    status               VARCHAR(30)   NOT NULL DEFAULT 'nouveau'          COMMENT 'Statut : nouveau | en_cours | resolu | faux_positif',
    UNIQUE KEY uniq_alert_log_attack_ip (log_id, attack_type, source_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table threat_score
-- Score de menace global calcule toutes les 10 secondes
-- par mini_siem.py — permet d afficher une jauge temps
-- reel dans le dashboard SOC d Omar Gaga
-- --------------------------------------------------------

DROP TABLE IF EXISTS threat_score;

CREATE TABLE threat_score (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    timestamp    DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP  COMMENT 'Date et heure du calcul du score',
    score_global INT       NOT NULL DEFAULT 0                  COMMENT 'Score calcule sur les 10 dernieres minutes',
    niveau       VARCHAR(20) NOT NULL                          COMMENT 'Niveau : LOW | MEDIUM | HIGH | CRITICAL',
    detail       TEXT                                          COMMENT 'Detail du calcul par attaque et par IP',
    score_total  INT       NOT NULL DEFAULT 0                  COMMENT 'Score cumulatif total depuis le debut'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
