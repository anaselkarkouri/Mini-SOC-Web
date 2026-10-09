import importlib.util, json, os, shutil, subprocess, sys, tempfile, unittest
from datetime import datetime,timedelta
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'mini_siem'))
import mini_siem as siem
class Cursor:
    def __init__(self,count=0): self.count=count;self.query='';self.args=()
    def execute(self,query,args=None): self.query=query;self.args=args
    def fetchone(self): return {'nb':self.count}
class RegressionTests(unittest.TestCase):
    def entry(self,**changes):
        row={'id':7,'timestamp':datetime(2026,10,9,12,0,0),'params':'{"GET_q":"casque audio"}',
             'url':'/search.php','method':'GET','response_code':200,'ip_source':'127.0.0.1'}
        row.update(changes);return row
    def test_tools_are_not_attacks(self):
        for ua in ['curl/8','python-requests/2','Hydra','sqlmap/1.0','Mozilla/5.0']:
            with self.subTest(ua=ua):self.assertEqual(siem.detecter_evenement(self.entry(user_agent=ua),Cursor()),[])
    def test_xss_via_curl_keeps_correct_type(self):
        matches=siem.detecter_evenement(self.entry(user_agent='curl/8',params='{"GET_q":"<script>alert(1)</script>"}'),Cursor())
        self.assertEqual([m[0] for m in matches],['XSS'])
    def test_independent_matches(self):
        matches=siem.detecter_evenement(self.entry(params=json.dumps({'GET_q':"' OR 1=1 -- <script>alert(1)</script>"})),Cursor())
        self.assertEqual({m[0] for m in matches},{'SQLi','XSS'})
    def test_secret_redaction_nested(self):
        raw=json.dumps({'POST_password':'SECRET_FIXTURE','POST_info':{'api_key':'SECRET_KEY','items':['ok']}})
        cleaned=siem.extraire_params(raw)
        self.assertNotIn('SECRET',cleaned);self.assertIn('ok',cleaned)
    def test_non_object_json(self):
        self.assertEqual(siem.extraire_params('["a",["b"]]'),'a b')
        self.assertEqual(siem.extraire_params('123'),'123')
    def test_event_time_and_same_second_causality(self):
        cursor=Cursor(5);anchor=self.entry()['timestamp']
        self.assertTrue(siem.detecter_brute_force('127.0.0.1',cursor,anchor,7)[0])
        self.assertNotIn('NOW()',cursor.query);self.assertIn('id <= %s',cursor.query)
        self.assertEqual(cursor.args[-4:],(anchor-timedelta(seconds=60),anchor,anchor,7))
    def test_bruteforce_needs_failed_post_login(self):
        for fields in [{'url':'/search.php'},{'method':'GET'},{'response_code':302}]:
            row=self.entry(url='/login.php',method='POST',response_code=401,**{})
            row.update(fields);self.assertEqual(siem.detecter_evenement(row,Cursor(100)),[])
    def test_export_redacts_and_preserves_event_id(self):
        with tempfile.TemporaryDirectory() as temp,patch.dict(os.environ,{'MINISOC_EVENT_LOG':str(Path(temp)/'events.ndjson')}):
            row=self.entry(event_id='a'*32,params=json.dumps({'POST_password':'DO_NOT_EXPORT','GET_q':'hello'}))
            siem.exporter_evenement(row);content=(Path(temp)/'events.ndjson').read_text(encoding='utf-8')
            self.assertNotIn('DO_NOT_EXPORT',content);self.assertEqual(json.loads(content)['event_id'],'a'*32)
    def test_json_log_rotation_is_bounded_and_keeps_valid_lines(self):
        with tempfile.TemporaryDirectory() as temp,patch.dict(os.environ,{'MINISOC_EVENT_LOG':str(Path(temp)/'events.ndjson'),'MINISOC_EVENT_MAX_BYTES':'1024'}):
            for i in range(30):siem.exporter_evenement(self.entry(event_id=f'{i:032x}',params=json.dumps({'GET_q':'x'*600})))
            files=list(Path(temp).glob('events.ndjson*'))
            self.assertEqual(len(files),4)
            for file in files:
                for line in file.read_text().splitlines():self.assertEqual(json.loads(line)['app'],'minisoc-web')
    @unittest.skipUnless(shutil.which('php'),'PHP non disponible')
    def test_php_score_matches_python_formula(self):
        source=(ROOT/'soc/bootstrap.php').read_text(encoding='utf-8-sig')
        funcs=source[source.index('function soc_score_level('):source.index('function soc_recalculate_threat_score(')]
        script="function soc_db_select($sql){return $GLOBALS['rows'];}"+funcs
        script+="$GLOBALS['rows']=[['attack_type'=>'SQL Injection','source_ip'=>'127.0.0.1','nb'=>2],['attack_type'=>'Cross-Site Scripting','source_ip'=>'127.0.0.1','nb'=>1]];echo soc_current_threat_score()['score'].',';$GLOBALS['rows']=array_reverse($GLOBALS['rows']);echo soc_current_threat_score()['score'];"
        result=subprocess.run(['php','-r',script],capture_output=True,text=True,check=True)
        self.assertEqual(result.stdout,'80,80')
    @unittest.skipUnless(shutil.which('php'),'PHP non disponible')
    def test_php_masking_arrays(self):
        code="require "+json.dumps(str(ROOT/'includes/log_fields.php'))+";echo minisoc_log_params([],['password'=>'NEVER_LOG','nested'=>['token'=>'NEVER_LOG'],'q'=>['one','two']]);"
        output=subprocess.check_output(['php','-r',code],text=True)
        self.assertNotIn('NEVER_LOG',output);self.assertIn('one',output)
    @unittest.skipUnless(shutil.which('php'),'PHP non disponible')
    def test_login_counter_ignores_user_agent(self):
        source=(ROOT/'soc/bootstrap.php').read_text(encoding='utf-8-sig')
        funcs=source[source.index('function soc_login_key('):source.index('function soc_login_lock_remaining(')]
        code="const SOC_LOGIN_USERNAME='admin';function soc_client_ip(){return '127.0.0.1';}"+funcs
        code+="$_SERVER['HTTP_USER_AGENT']='one';$a=soc_login_key();$_SERVER['HTTP_USER_AGENT']='two';echo $a===soc_login_key()?'same':'different';"
        self.assertEqual(subprocess.check_output(['php','-r',code],text=True),'same')
if __name__=='__main__':unittest.main()
