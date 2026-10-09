"""Moteur du laboratoire collectif EMSI; extensions personnelles documentées.
Une règle signale une tentative, jamais une compromission confirmée.
L'export JSON est au moins une fois: event_id permet d'identifier les rejeux.
"""
import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import time
from datetime import datetime, timezone, timedelta
import mysql.connector
BASE_DIR = Path(__file__).resolve().parent
MITRE_FILE = BASE_DIR / 'mitre_mapping.json'
LOG_FILE = Path(os.getenv('MINISOC_INTERNAL_LOG', str(BASE_DIR / 'siem.log')))
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
RULE_VERSION = '2026-10-09.1'
logging.basicConfig(level=logging.INFO, handlers=[RotatingFileHandler(
    LOG_FILE,maxBytes=1048576,backupCount=3,encoding='utf-8')],
    format='%(asctime)s [%(levelname)s] %(message)s')
mitre_map = json.loads(MITRE_FILE.read_text(encoding='utf-8'))
attacks = mitre_map['attacks']
PATTERNS = {key:[re.compile(p,re.IGNORECASE) for p in
    attacks[key]['detection_logic']['regex_patterns']] for key in ('SQLi','XSS')}
BF_SEUIL = attacks['BruteForce']['detection_logic']['thresholds']['failed_attempts_per_ip_per_window']
BF_FENETRE = attacks['BruteForce']['detection_logic']['thresholds']['window_seconds']
POINTS = {'SQL Injection':15,'Cross-Site Scripting':10,'Brute Force':8,
          'Brute Force - Credential Access':8,'BruteForce':8}
SENSITIVE_KEYS = {'password','passwd','pass','pwd','token','access_token',
    'refresh_token','secret','api_key','apikey','authorization','cookie',
    'session','sessionid','csrf','csrf_token'}
def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)
def log(msg):
    print(msg,flush=True);logging.info(msg)
def connecter():
    conn=mysql.connector.connect(host=os.getenv('MINISOC_DB_HOST','127.0.0.1'),
        port=int(os.getenv('MINISOC_DB_PORT','3306')),
        user=os.getenv('MINISOC_SIEM_DB_USER',os.getenv('MINISOC_DB_USER','root')),
        password=os.getenv('MINISOC_SIEM_DB_PASSWORD',os.getenv('MINISOC_DB_PASSWORD','')),
        database=os.getenv('MINISOC_DB_NAME','minisoc_shop'),connection_timeout=10)
    conn.time_zone='+00:00'
    return conn
def normaliser_ip(ip):
    return '127.0.0.1' if ip=='::1' else (ip or '0.0.0.0')
def variantes_ip(ip):
    values={normaliser_ip(ip),ip or '0.0.0.0'}
    if normaliser_ip(ip)=='127.0.0.1':values.add('::1')
    return sorted(values)
def assainir_params(value,depth=0):
    if depth>4:return '[depth-limit]'
    if isinstance(value,dict):
        return {str(k)[:80]:('[REDACTED]' if re.sub(r'^(get|post)_','',str(k).lower())
                in SENSITIVE_KEYS else assainir_params(v,depth+1))
                for k,v in list(value.items())[:100]}
    if isinstance(value,list):return [assainir_params(v,depth+1) for v in value[:30]]
    return str(value)[:2048]
def extraire_params(params_json):
    try:value=json.loads(params_json or '{}')
    except (ValueError,TypeError):return params_json if isinstance(params_json,str) else ''
    clean=assainir_params(value)
    def flatten(item):
        if isinstance(item,dict):return ' '.join(flatten(v) for v in item.values())
        if isinstance(item,list):return ' '.join(flatten(v) for v in item)
        return str(item)
    return flatten(clean)
def detecter_sqli(texte):
    return any(p.search(texte) for p in PATTERNS['SQLi'])
def detecter_xss(texte):
    return any(p.search(texte) for p in PATTERNS['XSS'])
def detecter_user_agent_suspect(user_agent,attack_key):
    """Indice contextuel; ne déclenche pas d'alerte à lui seul."""
    agents=attacks[attack_key]['ioc'].get('suspicious_headers_or_user_agents',[])
    return any(a.lower() in (user_agent or '').lower() for a in agents)
def detecter_brute_force(ip,cursor,event_time=None,event_id=None):
    anchor=event_time or utcnow();ips=variantes_ip(ip)
    placeholders=', '.join(['%s']*len(ips))
    causal = ' AND (timestamp < %s OR id <= %s)' if event_id is not None else ''
    cursor.execute(f"""SELECT COUNT(*) AS nb FROM http_logs
        WHERE ip_source IN ({placeholders}) AND url='/login.php'
        AND UPPER(method)='POST' AND response_code IN (401, 403)
        AND timestamp >= %s AND timestamp <= %s{causal}""",
        tuple(ips)+(anchor-timedelta(seconds=BF_FENETRE),anchor)+
        ((anchor,event_id) if event_id is not None else ()))
    result=cursor.fetchone();count=int((result or {}).get('nb',0) or 0)
    return count>=BF_SEUIL,count
def detecter_evenement(entry,cursor):
    text=extraire_params(entry.get('params',''))+' '+(entry.get('url') or '')
    matches=[]
    for key in ('SQLi','XSS'):
        for number,pattern in enumerate(PATTERNS[key],1):
            if pattern.search(text):
                matches.append((key,f'{key}-{number:02d}',
                    f'Motif {key} dans les paramètres assainis ou le chemin HTTP','medium'))
                break
    if (entry.get('url')=='/login.php' and (entry.get('method') or '').upper()=='POST'
            and int(entry.get('response_code') or 0) in (401,403)):
        found,count=detecter_brute_force(entry.get('ip_source'),cursor,entry.get('timestamp'),entry.get('id'))
        if found:matches.append(('BruteForce','BF-01',
            f'{count} échecs de connexion dans {BF_FENETRE}s, même source','high'))
    return matches
def creer_alerte(entry,attack_key,payload,cursor,conn,rule_id=None,reason=None,confidence='medium'):
    info=attacks[attack_key]
    cursor.execute('SELECT id FROM alerts WHERE log_id=%s AND attack_type=%s AND source_ip=%s',
        (entry['id'],info['attack_name'],normaliser_ip(entry.get('ip_source'))))
    if cursor.fetchone():return
    cursor.execute("""INSERT INTO alerts
        (timestamp,event_timestamp,log_id,attack_type,severity,description,payload,
         source_ip,url,mitre_id,mitre_tactic,mitre_technique,recommended_response,
         status,rule_id,rule_version,confidence)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,(
        utcnow(),entry.get('timestamp') or utcnow(),entry['id'],info['attack_name'],
        info['severity'],reason or f'Tentative {attack_key} à examiner',payload[:500],
        normaliser_ip(entry.get('ip_source')),(entry.get('url') or '')[:255],
        info['mitre_id'],info['tactic'],info['technique'],
        info['recommended_response']['immediate_actions'][0],'nouveau',
        rule_id or attack_key,RULE_VERSION,confidence))
def marquer_traite(log_id,cursor,conn):
    cursor.execute('UPDATE http_logs SET processed=1 WHERE id=%s',(log_id,))
def exporter_evenement(entry):
    target=os.getenv('MINISOC_EVENT_LOG')
    if not target:return
    try:values=assainir_params(json.loads(entry.get('params') or '{}'))
    except (ValueError,TypeError):values={'legacy_format':'[not-exported]'}
    timestamp=entry.get('timestamp') or utcnow()
    event={'app':'minisoc-web','event_id':entry.get('event_id') or f"legacy-{entry['id']}",
        'event_time':timestamp.isoformat()+'Z','src_ip':normaliser_ip(entry.get('ip_source')),
        'http_method':entry.get('method'),'url':entry.get('url'),
        'response_code':int(entry.get('response_code') or 0),
        'parameters':extraire_params(json.dumps(values))[:8192]}
    path=Path(target);path.parent.mkdir(parents=True,exist_ok=True)
    # Rétention bornée par taille; elle ne garantit aucune durée en jours.
    maxbytes=max(1024,int(os.getenv('MINISOC_EVENT_MAX_BYTES','10485760')))
    if path.exists() and path.stat().st_size>=maxbytes:
        for number in range(2,0,-1):
            previous=Path(str(path)+f'.{number}')
            if previous.exists():previous.replace(Path(str(path)+f'.{number+1}'))
        path.replace(Path(str(path)+'.1'))
    with path.open('a',encoding='utf-8') as stream:
        stream.write(json.dumps(event,ensure_ascii=False)+'\n');stream.flush();os.fsync(stream.fileno())
def calculer_score(cursor,conn):
    cursor.execute("""SELECT attack_type,source_ip,COUNT(*) AS nb FROM alerts
        WHERE timestamp >= UTC_TIMESTAMP() - INTERVAL 10 MINUTE
        AND status NOT IN ('resolu','faux_positif') GROUP BY attack_type,source_ip""")
    rows=cursor.fetchall();totals={}
    for row in rows:totals[row['source_ip']]=totals.get(row['source_ip'],0)+row['nb']
    score=sum(POINTS.get(row['attack_type'],5)*row['nb']*(2 if totals[row['source_ip']]>=3 else 1)
              for row in rows)
    level='LOW' if score<=20 else 'MEDIUM' if score<=50 else 'HIGH' if score<=80 else 'CRITICAL'
    cursor.execute('SELECT attack_type,COUNT(*) AS nb FROM alerts GROUP BY attack_type')
    cumulative=sum(POINTS.get(r['attack_type'],5)*r['nb'] for r in cursor.fetchall())
    cursor.execute('SELECT timestamp,score_global,score_total FROM threat_score ORDER BY id DESC LIMIT 1')
    previous=cursor.fetchone()
    if (previous and isinstance(previous.get('timestamp'),datetime)
            and utcnow()-previous['timestamp']<timedelta(seconds=60)
            and previous.get('score_global')==score and previous.get('score_total')==cumulative):
        return
    cursor.execute("""INSERT INTO threat_score
        (timestamp,score_global,niveau,detail,score_total) VALUES (%s,%s,%s,%s,%s)""",
        (utcnow(),score,level,'Indicateur pédagogique; poids locaux, pas une cotation du risque',cumulative))
    conn.commit()
def analyser_logs(cursor,conn):
    batch=max(1,min(1000,int(os.getenv('MINISOC_BATCH_SIZE','200'))))
    cursor.execute(f'SELECT * FROM http_logs WHERE processed=0 ORDER BY timestamp,id LIMIT {batch}')
    entries=cursor.fetchall()
    for entry in entries:
        try:
            matches=detecter_evenement(entry,cursor);clean=extraire_params(entry.get('params',''))
            for key,rule,reason,confidence in matches:
                creer_alerte(entry,key,clean,cursor,conn,rule,reason,confidence)
            exporter_evenement(entry);marquer_traite(entry['id'],cursor,conn);conn.commit()
        except Exception:
            conn.rollback();raise
    calculer_score(cursor,conn)
    cursor.execute("""INSERT INTO siem_health (id,last_cycle,rule_version)
        VALUES (1,UTC_TIMESTAMP(),%s) ON DUPLICATE KEY UPDATE
        last_cycle=VALUES(last_cycle),rule_version=VALUES(rule_version)""",(RULE_VERSION,))
    conn.commit();log(f'[ANALYSE] {len(entries)} événement(s) traité(s)')
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--once',action='store_true');args=parser.parse_args()
    while True:
        conn=cursor=None
        try:
            conn=connecter();cursor=conn.cursor(dictionary=True)
            cursor.execute("SELECT GET_LOCK('minisoc_engine',0) AS acquired")
            if cursor.fetchone()['acquired'] == 1: analyser_logs(cursor,conn)
        except Exception as error:
            log(f'[ERREUR] {type(error).__name__}; cycle à reprendre, aucun secret journalisé')
            if args.once:raise
        finally:
            if cursor:cursor.close()
            if conn:conn.close()
        if args.once:break
        time.sleep(max(1,int(os.getenv('MINISOC_POLL_SECONDS','10'))))
if __name__=='__main__':main()
