#!/bin/sh
set -e
# Identifiants aléatoires hexadécimaux du générateur; aucune valeur incorporée au dépôt.
for value in "$MINISOC_WEB_PASSWORD" "$MINISOC_COLLECTOR_PASSWORD" "$MINISOC_SIEM_PASSWORD" "$MINISOC_SOC_PASSWORD"; do
  case "$value" in ''|*[!a-f0-9]*) echo "Invalid generated credential" >&2; exit 1;; esac
done
docker_process_sql <<SQL
CREATE USER 'minisoc_web'@'%' IDENTIFIED BY '$MINISOC_WEB_PASSWORD';
CREATE USER 'minisoc_collector'@'%' IDENTIFIED BY '$MINISOC_COLLECTOR_PASSWORD';
CREATE USER 'minisoc_siem'@'%' IDENTIFIED BY '$MINISOC_SIEM_PASSWORD';
CREATE USER 'minisoc_soc'@'%' IDENTIFIED BY '$MINISOC_SOC_PASSWORD';
SQL
for table in users products categories reviews orders order_items; do
  docker_process_sql <<SQL
GRANT SELECT,INSERT,UPDATE,DELETE ON minisoc_shop.$table TO 'minisoc_web'@'%';
SQL
done
docker_process_sql <<SQL
GRANT INSERT ON minisoc_shop.http_logs TO 'minisoc_collector'@'%';
GRANT SELECT,UPDATE(processed) ON minisoc_shop.http_logs TO 'minisoc_siem'@'%';
GRANT SELECT,INSERT ON minisoc_shop.alerts TO 'minisoc_siem'@'%';
GRANT SELECT,INSERT ON minisoc_shop.threat_score TO 'minisoc_siem'@'%';
GRANT SELECT,INSERT,UPDATE ON minisoc_shop.siem_health TO 'minisoc_siem'@'%';
GRANT SELECT,UPDATE(status) ON minisoc_shop.alerts TO 'minisoc_soc'@'%';
GRANT SELECT ON minisoc_shop.http_logs TO 'minisoc_soc'@'%';
GRANT SELECT,INSERT ON minisoc_shop.threat_score TO 'minisoc_soc'@'%';
GRANT SELECT ON minisoc_shop.siem_health TO 'minisoc_soc'@'%';
GRANT SELECT,INSERT ON minisoc_shop.alert_audit TO 'minisoc_soc'@'%';
GRANT SELECT,INSERT ON minisoc_shop.soc_alert_reads TO 'minisoc_soc'@'%';
GRANT SELECT,INSERT,UPDATE,DELETE ON minisoc_shop.soc_login_attempts TO 'minisoc_soc'@'%';
SQL
