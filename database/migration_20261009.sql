-- Migration additive pour MariaDB 11.4, sur une copie sauvegardée d'un ancien laboratoire.
-- Aucun DROP ni DELETE. Les anciens contenus sensibles ne sont pas nettoyés par cette migration.
USE minisoc_shop;
ALTER TABLE http_logs ADD COLUMN IF NOT EXISTS event_id CHAR(32) NULL;
UPDATE http_logs SET event_id=MD5(CONCAT('legacy-minisoc-',id)) WHERE event_id IS NULL;
ALTER TABLE http_logs MODIFY event_id CHAR(32) NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_http_event ON http_logs(event_id);
CREATE INDEX IF NOT EXISTS idx_http_pending ON http_logs(processed,timestamp,id);
CREATE INDEX IF NOT EXISTS idx_http_login ON http_logs(ip_source,timestamp);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS event_timestamp DATETIME NULL;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS rule_id VARCHAR(30) NOT NULL DEFAULT 'LEGACY';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS rule_version VARCHAR(30) NOT NULL DEFAULT 'legacy';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS confidence VARCHAR(20) NOT NULL DEFAULT 'non_evaluee';
UPDATE alerts a LEFT JOIN http_logs l ON l.id=a.log_id
 SET a.event_timestamp=COALESCE(l.timestamp,a.timestamp) WHERE a.event_timestamp IS NULL;
ALTER TABLE alerts MODIFY event_timestamp DATETIME NOT NULL;
CREATE INDEX IF NOT EXISTS idx_alert_time_status ON alerts(timestamp,status);
CREATE TABLE IF NOT EXISTS siem_health(id INT PRIMARY KEY,last_cycle DATETIME NOT NULL,rule_version VARCHAR(30) NOT NULL);
CREATE TABLE IF NOT EXISTS alert_audit(id INT AUTO_INCREMENT PRIMARY KEY,alert_id INT NOT NULL,
 changed_at DATETIME NOT NULL,actor VARCHAR(80) NOT NULL,old_status VARCHAR(30) NOT NULL,
 new_status VARCHAR(30) NOT NULL,note VARCHAR(1000) NOT NULL,INDEX idx_audit_alert(alert_id,changed_at));
CREATE TABLE IF NOT EXISTS soc_alert_reads(alert_id INT PRIMARY KEY,read_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS soc_login_attempts(ip_hash VARCHAR(64) PRIMARY KEY,attempts INT NOT NULL DEFAULT 0,
 last_attempt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,locked_until DATETIME NULL);
