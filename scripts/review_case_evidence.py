"""Relire les preuves conservées des deux cas SOC, hors ligne.

Ce contrôle n'exécute aucune requête HTTP et ne lance aucun service.
"""
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'docs/evidence'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    data = json.loads((EVIDENCE / 'investigation-reference-20261009.json').read_text(encoding='utf-8'))
    initial = json.loads((EVIDENCE / 'wazuh-results.json').read_text(encoding='utf-8'))
    events = data['events']
    event_ids = {e['event_id'] for e in events}
    require(len(events) == len(event_ids) == initial['events'] == 8, 'Huit événements uniques requis.')
    require(all(e['app'] == 'minisoc-web' and data['marker'] in e['parameters'] for e in events),
            'Origine ou marqueur incohérent.')
    require(all(data['export_occurrences_by_event_id'][e] == 1 for e in event_ids),
            'Un identifiant est dupliqué dans la source examinée.')
    require([e['source_record']['line'] for e in events] == list(range(47, 55)),
            'Ordre de l\'extrait de référence inattendu.')
    alerts = data['wazuh_alerts']
    require(len(alerts) == 3, 'Trois alertes de référence requises.')
    expected = {(a['event_id'], str(a['rule_id'])) for a in initial['correlation_by_event_id']}
    observed = {(a['event_id'], str(a['rule']['id'])) for a in alerts}
    require(observed == expected, 'Le rapprochement initial Wazuh est modifié.')

    failures = [e for e in events if e['http_method'] == 'POST' and e['url'] == '/login.php']
    require(len(failures) == 5 and all(e['response_code'] == 401 for e in failures),
            'Cinq POST en échec attendus.')
    require(len({e['src_ip'] for e in failures}) == len({e['event_time'] for e in failures}) == 1,
            'Les cinq échecs doivent partager source et seconde.')
    require(all('[REDACTED]' in e['parameters'] for e in failures), 'Masquage absent.')
    correlated = next(a for a in alerts if str(a['rule']['id']) == '110104')
    context_ids = {e['event_id'] for e in correlated['previous_output_events']}
    require(context_ids | {correlated['event_id']} == {e['event_id'] for e in failures},
            'Le contexte Wazuh ne couvre pas les cinq échecs.')

    sqli_alert = next(a for a in alerts if str(a['rule']['id']) == '110101')
    sqli = next(e for e in events if e['event_id'] == sqli_alert['event_id'])
    require(sqli['url'] == '/search.php' and sqli['http_method'] == 'GET'
            and "' OR 1=1 --" in sqli['parameters'] and sqli['response_code'] == 200,
            'Signal SQLi de référence incohérent.')
    normal = [e for e in events if e['parameters'] == data['marker']]
    require(len(normal) == 1 and normal[0]['event_id'] not in {a['event_id'] for a in alerts},
            'La navigation témoin a une alerte personnalisée.')
    for mode, hardened in [('before', False), ('after', True)]:
        retest = json.loads((EVIDENCE / f'remediation-{mode}.json').read_text(encoding='utf-8'))
        require(retest['hardened'] is hardened and len(retest['checks']) == 5
                and all(c['passed'] for c in retest['checks']), 'Résumé HTTP incohérent.')
    before = json.loads((EVIDENCE / 'zap-before-summary.json').read_text(encoding='utf-8'))
    after = json.loads((EVIDENCE / 'zap-after-summary.json').read_text(encoding='utf-8'))
    targeted = {'40012', '40018'}
    require(targeted <= {a['plugin_id'] for a in before['alerts']}, 'Alertes ZAP initiales absentes.')
    require(not targeted & {a['plugin_id'] for a in after['alerts']} and len(after['alerts']) == 7,
            'Résumé ZAP après correction incohérent.')
    print(json.dumps({'status': 'ok', 'events': 8, 'login_failures': 5,
                      'wazuh_alerts': 3, 'cases': ['SOC-01', 'SOC-02'],
                      'scope': 'Cohérence des pièces conservées; aucun scénario rejoué.'},
                     ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
