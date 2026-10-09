"""Scénarios réels HTTP/PHP/MariaDB/Python sur une base dédiée de laboratoire.
Exécution dans le service siem; ne réinitialise ni ne supprime les tables.
"""
import json, os, re, sys, time
from pathlib import Path
from urllib.request import Request,build_opener,HTTPCookieProcessor
from urllib.parse import urlencode
from urllib.error import HTTPError
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'mini_siem'))
import mini_siem as siem
opener=build_opener(HTTPCookieProcessor())
BASE=os.getenv('MINISOC_TEST_URL','http://web')
checks=[]
def request(path,data=None,ua='Mozilla/5.0'):
    req=Request(BASE+path,data=urlencode(data).encode() if data is not None else None,
                headers={'User-Agent':ua})
    try:
        with opener.open(req,timeout=15) as result:return result.status,result.read().decode('utf-8')
    except HTTPError as result:return result.code,result.read().decode('utf-8')
def verify(name,condition):
    checks.append({'scenario':name,'passed':bool(condition)})
    if not condition:raise AssertionError(name)
def rows(sql,args=()):
    conn=siem.connecter();cursor=conn.cursor(dictionary=True)
    try:cursor.execute(sql,args);return cursor.fetchall()
    finally:cursor.close();conn.close()
def csrf(html):
    found=re.search(r'name="csrf" value="([a-f0-9]+)"',html)
    if not found:raise AssertionError('CSRF absent')
    return found.group(1)
start=rows('SELECT COALESCE(MAX(id),0) AS id FROM http_logs')[0]['id']
marker=f'lab-{time.time_ns()}'
status,_=request('/search.php?'+urlencode({'q':marker}),ua='curl/8.0')
verify('navigation HTTP avec curl',status==200)
request('/search.php?'+urlencode({'q':"' OR 1=1 --"}),ua='curl/8.0')
request('/search.php?'+urlencode({'q':'<script>alert(1)</script>'}),ua='curl/8.0')
secret='NEVER_LOG_'+marker
for _ in range(5):request('/login.php',{'username':'invalid-'+marker,'password':secret})
deadline=time.monotonic()+30
while time.monotonic()<deadline:
    if rows('SELECT COUNT(*) AS nb FROM http_logs WHERE id>%s AND processed=0',(start,))[0]['nb']==0:break
    time.sleep(1)
verify('traitement du lot réel',rows('SELECT COUNT(*) AS nb FROM http_logs WHERE id>%s AND processed=0',(start,))[0]['nb']==0)
events=rows('SELECT * FROM http_logs WHERE id>%s',(start,))
alerts=rows('SELECT * FROM alerts WHERE log_id>%s',(start,))
normal_ids={r['id'] for r in events if marker in r['params'] and r['url']=='/search.php'}
verify('aucune alerte pour navigation curl normale',not any(a['log_id'] in normal_ids for a in alerts))
verify('SQLi et XSS correctement distingués',{'SQL Injection','Cross-Site Scripting'} <= {a['attack_type'] for a in alerts})
verify('brute force sur échecs réels',any('Brute' in a['attack_type'] for a in alerts))
verify('mots de passe absents des données conservées',secret not in json.dumps(events,default=str)+json.dumps(alerts,default=str))
verify('identifiants et raisons de règles',all(a['rule_id'] and a['rule_version'] and a['confidence'] for a in alerts))
jsonfile=Path(os.environ['MINISOC_EVENT_LOG'])
verify('export JSON sans le secret',jsonfile.exists() and secret not in jsonfile.read_text())
selected=next(a for a in alerts if a['attack_type']=='Cross-Site Scripting')
verify('console protégée sans session',request('/soc/api.php')[0]==403)
code,html=request('/soc/login.php')
password=Path('/runtime/soc-login.private').read_text().strip()
code,html=request('/soc/login.php',{'username':'admin','password':password,'csrf':csrf(html),'next':'index.php'})
verify('connexion analyste',code==200 and 'data-live-dashboard' in html)
token=csrf(html)
verify('CSRF absent refusé',request('/soc/api.php',{'action':'update_status','id':selected['id'],'status':'resolu'})[0]==403)
verify('clôture sans justification refusée',request('/soc/api.php',{'action':'update_status','id':selected['id'],'status':'resolu','csrf':token})[0]==400)
code,_=request('/soc/api.php',{'action':'update_status','id':selected['id'],'status':'faux_positif',
    'note':'Exercice contrôlé: charge XSS soumise dans le laboratoire; exécution non démontrée.','csrf':token})
verify('qualification via API',code==200)
code,detail=request('/soc/detail.php?id='+str(selected['id']))
verify('justification et historique visibles',code==200 and 'Exercice contrôlé' in detail and 'Historique des décisions' in detail)
verify('identifiant inexistant refusé',request('/soc/api.php',{'action':'update_status','id':2147483600,'status':'resolu','csrf':token})[0]==400)
conn=siem.connecter();cursor=conn.cursor()
try:
    try:cursor.execute("UPDATE users SET username=username WHERE id=1");denied=False
    except Exception:denied=True
    verify('moteur sans droit de modifier les comptes boutique',denied)
finally:conn.rollback();cursor.close();conn.close()
verify('répertoires privés non servis',request('/database/schema.sql')[0]==403 and request('/.env')[0]==403)
out=Path('/runtime/integration-results.json');out.write_text(json.dumps({'checks':checks,'count':len(checks)},ensure_ascii=False,indent=2))
print(json.dumps({'checks':checks,'count':len(checks)},ensure_ascii=False,indent=2))
