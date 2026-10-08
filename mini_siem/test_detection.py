import unittest
from unittest.mock import patch
import mini_siem as siem

class Connection:
    def commit(self):pass

class Cursor:
    def __init__(self, rows=None, count=0):self.rows=rows or [];self.count=count;self.queries=[];self.insert=None
    def execute(self,query,args=None):
        self.queries.append((query,args))
        if 'INSERT INTO threat_score' in query:self.insert=args
    def fetchone(self):return {'nb':self.count}
    def fetchall(self):return self.rows

class DetectionTests(unittest.TestCase):
    def test_sqli_true_and_ordinary_search_false(self):
        self.assertTrue(siem.detecter_sqli("' OR 1=1 --"))
        self.assertFalse(siem.detecter_sqli('casque audio'))
    def test_xss_true_and_ordinary_text_false(self):
        self.assertTrue(siem.detecter_xss('<script>alert(1)</script>'))
        self.assertFalse(siem.detecter_xss('une commande fictive'))
    def test_ip_variants(self):
        self.assertEqual(siem.normaliser_ip('::1'),'127.0.0.1')
        self.assertEqual(set(siem.variantes_ip('::1')),{'::1','127.0.0.1'})
    def test_json_and_non_json_payload(self):
        self.assertIn('OR 1=1',siem.extraire_params('{"GET_q":"OR 1=1"}'))
        self.assertEqual(siem.extraire_params('not-json'),'not-json')
    def test_failed_login_threshold_and_parameterization(self):
        cursor=Cursor(count=siem.BF_SEUIL-1)
        self.assertFalse(siem.detecter_brute_force('127.0.0.1',cursor)[0])
        cursor.count=siem.BF_SEUIL
        self.assertTrue(siem.detecter_brute_force('127.0.0.1',cursor)[0])
        query,args=cursor.queries[-1]
        self.assertIn('response_code IN (401, 403)',query)
        self.assertNotIn('127.0.0.1',query)
        self.assertIn('127.0.0.1',args)
    @patch.object(siem,'log')
    def test_scores_order_independent_and_recalculation_does_not_accumulate(self, log):
        rows=[{'attack_type':'SQL Injection','source_ip':'127.0.0.1','nb':2},
              {'attack_type':'Cross-Site Scripting','source_ip':'127.0.0.1','nb':1}]
        a=Cursor(rows);b=Cursor(list(reversed(rows)))
        siem.calculer_score(a,Connection());siem.calculer_score(b,Connection())
        self.assertEqual(a.insert[1],80);self.assertEqual(a.insert[1],b.insert[1])
        self.assertEqual(a.insert[-1],40)
        siem.calculer_score(a,Connection());self.assertEqual(a.insert[-1],40)

if __name__=='__main__':unittest.main()
