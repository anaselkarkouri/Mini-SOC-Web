# Intégration Wazuh du laboratoire

Le gestionnaire lit le NDJSON du moteur ; ses règles évaluent indépendamment les événements HTTP, sans importer les alertes calculées par le Mini-SIEM.

1. Sur un gestionnaire dédié, sauvegarder `/var/ossec/etc/ossec.conf`.
2. Copier `minisoc_rules.xml` dans `/var/ossec/etc/rules/`, propriétaire `root:wazuh`, droits `640`.
3. Adapter le chemin de `localfile.xml`, puis ajouter ce bloc dans la configuration existante.
4. Vérifier `wazuh-analysisd -t` avant de redémarrer ce gestionnaire.
5. Sur le gestionnaire qui héberge la boutique locale, lancer `sudo python3 scripts/verify_wazuh_lab.py`.

Validation du 9 octobre : Wazuh **4.14.8**, gestionnaire seul. Le module de vulnérabilités est désactivé dans cette VM de test pour éviter un téléchargement CTI de plusieurs Go, sans rapport avec les scénarios HTTP. Cette modification n'est pas destinée à un autre système.

Le champ JSON `url` est statique dans Wazuh : les règles utilisent `<url>`. `src_ip` est dynamique. Corrélation configurée : cinq échecs, même source, dans 60 secondes. Wazuh observe l'arrivée des lignes ; sa fenêtre n'est pas la fenêtre ancrée sur l'heure source utilisée par le moteur Python. Lire les anciennes lignes au redémarrage peut créer des rejeux et des corrélations sur ce rattrapage ; `event_id` sert à les reconnaître. Aucune garantie de 90 jours ou d'absence de doublon n'est annoncée.

Sources officielles : [JSON](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html), [règles personnalisées](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html), [syntaxe](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html), [localfile](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html).
