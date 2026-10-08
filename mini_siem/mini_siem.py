import mysql.connector
import json
import re
import time
import logging
import os
from datetime import datetime

# ─────────────────────────────────────────────────────
# CHEMINS DES FICHIERS
# ─────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MITRE_FILE = os.path.join(BASE_DIR, "mitre_mapping.json")
LOG_FILE   = os.path.join(BASE_DIR, "siem.log")

# ─────────────────────────────────────────────────────
# LOGS DU SCRIPT → fichier siem.log
# ─────────────────────────────────────────────────────
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def log(msg):
    print(msg)
    logging.info(msg)

# ─────────────────────────────────────────────────────
# 1. CONNEXION À MYSQL
# ─────────────────────────────────────────────────────
def connecter():
    return mysql.connector.connect(
        host=os.getenv("MINISOC_DB_HOST", "127.0.0.1"),
        port=int(os.getenv("MINISOC_DB_PORT", "3306")),
        user=os.getenv("MINISOC_DB_USER", "root"),
        password=os.getenv("MINISOC_DB_PASSWORD", ""),
        database=os.getenv("MINISOC_DB_NAME", "minisoc_shop")
    )

# ─────────────────────────────────────────────────────
# 2. CHARGER LE FICHIER D'ILYAS
# ─────────────────────────────────────────────────────
with open(MITRE_FILE, "r", encoding="utf-8") as f:
    mitre_map = json.load(f)

attacks = mitre_map["attacks"]

# Seuils Brute Force depuis le fichier d'Ilyas
BF_SEUIL   = attacks["BruteForce"]["detection_logic"]["thresholds"]["failed_attempts_per_ip_per_window"]
BF_FENETRE = attacks["BruteForce"]["detection_logic"]["thresholds"]["window_seconds"]

# Points par type d'attaque pour le score
POINTS = {
    "SQL Injection": 15,
    "Cross-Site Scripting": 10,
    "Brute Force": 8,
    "Brute Force - Credential Access": 8,
    "BruteForce": 8
}

# ─────────────────────────────────────────────────────
# 3. NORMALISER L'IP
# ─────────────────────────────────────────────────────
def normaliser_ip(ip):
    """Convertit ::1 (IPv6 localhost) en 127.0.0.1"""
    if ip == "::1":
        return "127.0.0.1"
    return ip or "0.0.0.0"

def variantes_ip(ip):
    """Retourne les formes possibles d'une IP pour les tests locaux et reels."""
    ip_norm = normaliser_ip(ip)
    variantes = {ip_norm}
    if ip:
        variantes.add(ip)
    if ip_norm == "127.0.0.1":
        variantes.add("::1")
    return list(variantes)

# ─────────────────────────────────────────────────────
# 4. EXTRAIRE LES PARAMS (format JSON d'Omar Babba)
# ─────────────────────────────────────────────────────
def extraire_params(params_json):
    """Omar stocke les params en JSON — on les convertit en texte analysable"""
    try:
        d = json.loads(params_json or "{}")
        return " ".join(str(v) for v in d.values())
    except:
        return params_json or ""

# ─────────────────────────────────────────────────────
# 5. FONCTIONS DE DÉTECTION
# ─────────────────────────────────────────────────────
def detecter_sqli(texte):
    """Détecte une SQLi en utilisant les regex d'Ilyas"""
    for pattern in attacks["SQLi"]["detection_logic"]["regex_patterns"]:
        try:
            if re.search(pattern, texte, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False

def detecter_xss(texte):
    """Détecte un XSS en utilisant les regex d'Ilyas"""
    for pattern in attacks["XSS"]["detection_logic"]["regex_patterns"]:
        try:
            if re.search(pattern, texte, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False

def detecter_user_agent_suspect(user_agent, attack_key):
    """Détecte les outils connus : sqlmap, Hydra, nikto, curl..."""
    try:
        agents = attacks[attack_key]["ioc"].get("suspicious_headers_or_user_agents", [])
        return any(a.lower() in (user_agent or "").lower() for a in agents)
    except:
        return False

def detecter_brute_force(ip, cursor):
    """Compte les échecs de connexion selon les seuils d'Ilyas"""
    ips = variantes_ip(ip)
    placeholders = ", ".join(["%s"] * len(ips))
    cursor.execute(f"""
        SELECT COUNT(*) as nb FROM http_logs
        WHERE ip_source IN ({placeholders})
        AND url LIKE '%login.php%'
        AND UPPER(method) = 'POST'
        AND response_code IN (401, 403)
        AND timestamp >= NOW() - INTERVAL %s SECOND
    """, tuple(ips) + (BF_FENETRE,))
    result = cursor.fetchone()
    nb = int(result["nb"] or 0)
    return nb >= BF_SEUIL, nb

# ─────────────────────────────────────────────────────
# 6. CRÉER UNE ALERTE ENRICHIE
# ─────────────────────────────────────────────────────
def creer_alerte(log_entry, attack_key, payload, cursor, conn):
    """Crée une alerte enrichie avec les données MITRE d'Ilyas"""
    info = attacks[attack_key]
    ip   = normaliser_ip(log_entry.get("ip_source", ""))

    # Anti-doublon — vérifie log_id + attack_type + source_ip
    cursor.execute("""
        SELECT id FROM alerts
        WHERE log_id = %s
        AND attack_type = %s
        AND source_ip = %s
    """, (log_entry["id"], info["attack_name"], ip))

    if cursor.fetchone():
        log(f"[SKIP] Alerte déjà enregistrée — log_id={log_entry['id']} — {info['attack_name']}")
        return

    reponse = info["recommended_response"]["immediate_actions"][0]

    cursor.execute("""
        INSERT IGNORE INTO alerts (
            timestamp, log_id, attack_type, severity,
            description, payload, source_ip, url,
            mitre_id, mitre_tactic, mitre_technique,
            recommended_response, status
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        datetime.now(),
        log_entry["id"],
        info["attack_name"],
        info["severity"],
        f"{info['attack_name']} détectée sur {log_entry['url']}",
        payload[:500],
        ip,
        log_entry["url"],
        info["mitre_id"],
        info["tactic"],
        info["technique"],
        reponse,
        "nouveau"
    ))
    conn.commit()
    log(f"[ALERTE] {info['attack_name']} — {info['severity']} — IP: {ip} — {log_entry['url']}")

# ─────────────────────────────────────────────────────
# 7. MARQUER LE LOG COMME TRAITÉ
# ─────────────────────────────────────────────────────
def marquer_traite(log_id, cursor, conn):
    cursor.execute(
        "UPDATE http_logs SET processed = 1 WHERE id = %s",
        (log_id,)
    )
    conn.commit()

# ─────────────────────────────────────────────────────
# 8. CALCULER LE SCORE DE MENACE
# ─────────────────────────────────────────────────────
def calculer_score(cursor, conn):
    """Calcule le score de menace des 10 dernières minutes"""
    cursor.execute("""
        SELECT attack_type, source_ip, COUNT(*) as nb
        FROM alerts
        WHERE timestamp >= NOW() - INTERVAL 10 MINUTE
        AND (status IS NULL OR status NOT IN ('resolu', 'faux_positif'))
        GROUP BY attack_type, source_ip
    """)
    alertes = cursor.fetchall()

    score     = 0
    ip_counts = {}
    details   = []

    # Le multiplicateur dépend du total par IP, indépendamment de l'ordre SQL.
    for a in alertes:
        ip_counts[a['source_ip']] = ip_counts.get(a['source_ip'], 0) + a['nb']

    for a in alertes:
        pts_base = POINTS.get(a["attack_type"], 5)
        ip       = a["source_ip"]

        # Multiplicateur x2 si même IP attaque 3 fois ou plus
        multiplicateur = 2 if ip_counts[ip] >= 3 else 1

        pts    = pts_base * a["nb"] * multiplicateur
        score += pts
        details.append(f"{a['attack_type']} x{a['nb']} depuis {ip} = {pts}pts")

    # Niveau de menace
    if score <= 20:
        niveau = "LOW"
    elif score <= 50:
        niveau = "MEDIUM"
    elif score <= 80:
        niveau = "HIGH"
    else:
        niveau = "CRITICAL"

    # Total brut des alertes uniques, y compris celles sorties de la fenêtre.
    # Additionner chaque photographie de dix minutes compterait plusieurs fois
    # la même alerte ; aucun nouveau point n'est ajouté lors d'un simple recalcul.
    cursor.execute("SELECT attack_type, COUNT(*) as nb FROM alerts GROUP BY attack_type")
    score_total = sum(POINTS.get(a['attack_type'], 5) * a['nb'] for a in cursor.fetchall())

    detail = " | ".join(details) if details else "Aucune alerte active"

    cursor.execute("""
        INSERT INTO threat_score (timestamp, score_global, niveau, detail, score_total)
        VALUES (%s, %s, %s, %s, %s)
    """, (datetime.now(), score, niveau, detail, score_total))
    conn.commit()

    log(f"[SCORE] {niveau} — {score} pts (10min) — total cumulatif: {score_total} pts")

# ─────────────────────────────────────────────────────
# 9. ANALYSE PRINCIPALE
# ─────────────────────────────────────────────────────
def analyser_logs(cursor, conn):
    """Lit les nouveaux logs et détecte les attaques"""
    cursor.execute("SELECT * FROM http_logs WHERE processed = 0")
    logs = cursor.fetchall()

    if not logs:
        return

    for log_entry in logs:
        params     = extraire_params(log_entry.get("params", ""))
        url        = log_entry.get("url") or ""
        texte      = params + " " + url
        user_agent = log_entry.get("user_agent", "")
        ip         = normaliser_ip(log_entry.get("ip_source", ""))
        detecte    = False
        is_login_attempt = "login.php" in url.lower() and (log_entry.get("method", "") or "").upper() == "POST"
        brute_detecte, brute_count = detecter_brute_force(ip, cursor)

        # ── Détection SQLi ──
        if detecter_sqli(texte) or detecter_user_agent_suspect(user_agent, "SQLi"):
            creer_alerte(log_entry, "SQLi", texte, cursor, conn)
            detecte = True

        # ── Détection XSS ──
        elif detecter_xss(texte) or detecter_user_agent_suspect(user_agent, "XSS"):
            creer_alerte(log_entry, "XSS", texte, cursor, conn)
            detecte = True

        # ── Détection Brute Force ──
        elif (is_login_attempt and brute_detecte) or detecter_user_agent_suspect(user_agent, "BruteForce"):
            tentative_count = max(brute_count, 1)
            creer_alerte(log_entry, "BruteForce", f"{tentative_count}+ tentatives login depuis {ip}", cursor, conn)
            detecte = True

        # ── Log informatif si aucune attaque ──
        if not detecte:
            log(f"[INFO] log_id={log_entry['id']} — navigation normale — {url}")

        # Marquer le log comme traité dans tous les cas
        marquer_traite(log_entry["id"], cursor, conn)

    log(f"[ANALYSE] {len(logs)} log(s) traité(s)")

    # Recalculer le score après chaque cycle
    calculer_score(cursor, conn)

# ─────────────────────────────────────────────────────
# 10. BOUCLE INFINIE — CŒUR DU SYSTÈME
# ─────────────────────────────────────────────────────
def main():
    log("=" * 55)
    log("  Mini-SIEM démarré — analyse toutes les 10 secondes")
    log("=" * 55)
    
    while True:
        try:
            # Nouvelle connexion à chaque cycle pour plus de stabilité
            conn   = connecter()
            cursor = conn.cursor(dictionary=True)
    
            analyser_logs(cursor, conn)
    
            cursor.close()
            conn.close()
    
        except mysql.connector.Error as e:
            log(f"[ERREUR MySQL] {e} — nouvelle tentative dans 10s")
    
        except Exception as e:
            log(f"[ERREUR] {e}")
    
        # Attendre 10 secondes avant le prochain cycle
        time.sleep(10)

if __name__ == "__main__":
    main()
