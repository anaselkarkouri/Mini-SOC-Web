-- Module historique M3 (Fadoua El-Allagui). Pour une nouvelle base uniquement.
-- Sur une base existante, utiliser migration_20261009.sql après sauvegarde.
USE minisoc_shop;
CREATE TABLE IF NOT EXISTS alerts (
    id                   INT AUTO_INCREMENT PRIMARY KEY,
    timestamp            DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP  COMMENT 'Date et heure de detection de l attaque',
    event_timestamp      DATETIME NOT NULL,
    rule_id              VARCHAR(30) NOT NULL,
    rule_version         VARCHAR(30) NOT NULL,
    confidence           VARCHAR(20) NOT NULL,
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
    INDEX idx_alert_time_status (timestamp,status),
    UNIQUE KEY uniq_alert_log_attack_ip (log_id, attack_type, source_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS threat_score (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    timestamp    DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP  COMMENT 'Date et heure du calcul du score',
    score_global INT         NOT NULL DEFAULT 0                  COMMENT 'Score calcule sur les 10 dernieres minutes',
    niveau       VARCHAR(20) NOT NULL                            COMMENT 'Niveau : LOW | MEDIUM | HIGH | CRITICAL',
    detail       TEXT                                            COMMENT 'Detail du calcul par attaque et par IP',
    score_total  INT         NOT NULL DEFAULT 0                  COMMENT 'Score cumulatif total depuis le debut'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS siem_health (id INT PRIMARY KEY,last_cycle DATETIME NOT NULL,rule_version VARCHAR(30) NOT NULL);
CREATE TABLE IF NOT EXISTS alert_audit (
 id INT AUTO_INCREMENT PRIMARY KEY,alert_id INT NOT NULL,changed_at DATETIME NOT NULL,
 actor VARCHAR(80) NOT NULL,old_status VARCHAR(30) NOT NULL,new_status VARCHAR(30) NOT NULL,
 note VARCHAR(1000) NOT NULL,INDEX idx_audit_alert (alert_id,changed_at));
CREATE TABLE IF NOT EXISTS soc_alert_reads (alert_id INT PRIMARY KEY,read_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS soc_login_attempts (ip_hash VARCHAR(64) PRIMARY KEY,attempts INT NOT NULL DEFAULT 0,
 last_attempt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,locked_until DATETIME NULL);
