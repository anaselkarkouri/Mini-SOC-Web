"""À lancer sur le gestionnaire Wazuh du laboratoire, après installation des règles.
Les requêtes restent sur http://127.0.0.1:8086; aucune cible externe.
"""
from pathlib import Path
from urllib.request import urlopen,Request
from urllib.parse import urlencode
from urllib.error import HTTPError
import json,time
ROOT=Path(__file__).resolve().parents[1]
token='wazuh-lab-'+str(time.time_ns())
def send(path,values=None):
 req=Request('http://127.0.0.1:8086'+path,data=urlencode(values).encode() if values else None,
             headers={'User-Agent':'curl/8.0'})
 try:
  with urlopen(req,timeout=10) as result:result.read();return result.status
 except HTTPError as result:return result.code
assert send('/search.php?'+urlencode({'q':token}))==200
send('/search.php?'+urlencode({'q':"' OR 1=1 -- "+token}))
send('/search.php?'+urlencode({'q':'<script>alert("'+token+'")</script>'}))
for i in range(5):assert send('/login.php',{'username':token,'password':'DO_NOT_RETAIN-'+token})==401
def records(path):
 if not path.exists():return []
 result=[]
 for line in path.read_text(errors='replace').splitlines():
  try:result.append(json.loads(line))
  except ValueError:pass
 return result
deadline=time.monotonic()+70
while time.monotonic()<deadline:
 events=[e for e in records(ROOT/'runtime/events.ndjson') if token in e.get('parameters','')]
 ids={e['event_id'] for e in events}
 matched=[a for a in records(Path('/var/ossec/logs/alerts/alerts.json')) if a.get('data',{}).get('event_id') in ids]
 rules={str(a['rule']['id']) for a in matched}
 if {'110101','110102','110104'}<=rules:break
 time.sleep(2)
assert len(events)==8,{'events':len(events)}
normal=next(e for e in events if e['parameters']==token)
assert not any(a.get('data',{}).get('event_id')==normal['event_id'] for a in matched)
assert {'110101','110102','110104'}<=rules,{'rules':sorted(rules)}
assert 'DO_NOT_RETAIN' not in json.dumps(events)
result={'date':'2026-10-09','wazuh_version':'4.14.8','source':'HTTP réel -> MariaDB -> moteur -> NDJSON -> Wazuh manager',
 'events':len(events),'custom_rules_seen':sorted(rules),'normal_request_has_custom_alert':False,
 'secrets_fixture_absent':True,'correlation_by_event_id':[{'event_id':a['data']['event_id'],'rule_id':a['rule']['id']} for a in matched],
 'scope':'Gestionnaire local seul; aucun indexeur ou dashboard Wazuh.'}
(ROOT/'runtime/wazuh-results.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
print(json.dumps(result,ensure_ascii=False,indent=2))
