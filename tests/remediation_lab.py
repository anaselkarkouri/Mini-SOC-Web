"""Preuves HTTP avant/après, sur la boutique locale uniquement.
Ne conclut pas à une sécurité globale; aucune exécution JavaScript n'est inférée.
"""
import json, os, re, time
from pathlib import Path
from urllib.request import urlopen, Request, build_opener, HTTPCookieProcessor
from urllib.parse import urlencode
from urllib.error import HTTPError
BASE=os.getenv('MINISOC_TEST_URL','http://web')
mode=os.getenv('EXPECTED_HARDENED','0')=='1'
opener=build_opener(HTTPCookieProcessor())
checks=[]
def get(path,data=None):
    req=Request(BASE+path,data=urlencode(data).encode() if data else None)
    try:
        with opener.open(req,timeout=15) as r:return r.status,r.read().decode(),dict(r.headers)
    except HTTPError as r:return r.code,r.read().decode(),dict(r.headers)
def verify(name,condition):
    checks.append({'scenario':name,'passed':bool(condition)})
    if not condition:raise AssertionError(name)
code,normal,_=get('/search.php?'+urlencode({'q':'AtlasPhone'}))
verify('recherche légitime fonctionnelle',code==200 and 'product-card' in normal)
payload='<script>alert("lab")</script>'
code,body,_=get('/search.php?'+urlencode({'q':payload}))
verify('XSS réfléchie: réponse conforme au mode',('&lt;script&gt;' in body and payload not in body) if mode else payload in body)
code,body,_=get('/search.php?'+urlencode({'q':"' OR 1=1 -- "}))
verify('SQLi recherche: injection neutralisée en mode corrigé',('product-card' not in body) if mode else 'product-card' in body)
code,body,_=get('/login.php',{'username':"admin' -- ",'password':'fixture'})
verify('SQLi connexion: contournement refusé en mode corrigé',(code==401) if mode else (code==200 and 'account' in body.lower()))
author='ret-test-'+str(time.time_ns())
code,body,_=get('/review.php',{'product_id':'1','author_name':author,'rating':'3','comment':payload})
verify('XSS stockée: affichage encodé en mode corrigé',(author in body and payload not in body and '&lt;script&gt;' in body) if mode else (author in body and payload in body))
out=Path('/runtime/remediation-'+('after' if mode else 'before')+'.json')
out.write_text(json.dumps({'scope':'search.php, login.php, review.php/product.php','hardened':mode,'checks':checks,
 'limit':'Réponses HTTP uniquement; pas de mesure exhaustive de sécurité ni de preuve d’exécution JavaScript.'},ensure_ascii=False,indent=2))
print(out.read_text())
