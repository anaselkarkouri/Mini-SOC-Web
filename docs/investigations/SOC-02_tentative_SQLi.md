# SOC-02 - Qualification d'une tentative SQLi et examen des corrections

**Périmètre :** recherche de la boutique fictive, laboratoire local dédié.  
**Traces :** 9 octobre 2026 ; horodatages UTC.  
**Compte rendu :** 10 octobre 2026, préparé avec assistance d'outils IA à partir des pièces conservées.  
**État :** analyse documentaire de l'exercice terminée ; aucun incident d'entreprise déclaré.

## 1. Résumé

Une requête GET vers `/search.php` contient le motif SQL `' OR 1=1 --` suivi du marqueur de test. L'événement est rapproché de l'alerte Wazuh `110101` par son identifiant. Le motif de tentative SQLi est confirmé. La réponse HTTP 200 de cette requête ne prouve ni extraction de données ni compromission. Des vérifications HTTP et ZAP distinctes documentent un comportement vulnérable puis corrigé sur un périmètre limité ; elles ne constituent pas la réponse enregistrée de cette requête d'origine.

## 2. Pièces examinées

| Pièce | Utilité | Limite |
| --- | --- | --- |
| [Extrait événements / alertes](../evidence/investigation-reference-20261009.json) | Paramètres, réponse HTTP, heure, source et rapprochement par event_id | Ne contient pas le corps de réponse HTTP de cette requête |
| [Résultat Wazuh initial](../evidence/wazuh-results.json) | Vérification indépendante de la règle observée | Résultat local ; aucun indexeur ou dashboard Wazuh |
| [Script de génération](../../scripts/verify_wazuh_lab.py) | Origine et intention du scénario autorisé | Le script lit puis écarte le corps de réponse |
| [Retests HTTP avant](../evidence/remediation-before.json) / [après](../evidence/remediation-after.json) | Comportements attendus observés selon le mode | Synthèses de tests distincts ; pas de réponse HTTP brute publiée |
| [Script de retest](../../tests/remediation_lab.py) | Permet de comprendre chaque condition vérifiée | Les libellés des conditions restent identiques dans les deux modes |
| [Synthèses ZAP avant](../evidence/zap-before-summary.json) / [après](../evidence/zap-after-summary.json) | Comparaison des alertes du scan ciblé | Les rapports bruts restent privés ; synthèses et empreintes publiques |

## 3. Chronologie du signal

Les trois événements suivants partagent `2026-10-09T18:02:31Z` et la source observée `172.29.23.1`. Les lignes donnent l'ordre dans l'export, sans précision inférieure à la seconde.

| Ligne NDJSON | event_id | Observation | Réponse |
| --- | --- | --- | --- |
| 47 | `a00c50e7ea12edae3d69a02da7b161eb` | Recherche témoin contenant seulement le marqueur | 200 |
| 48 | `4980a0f9e8159b4ea849591df241e21f` | Recherche contenant `' OR 1=1 -- wazuh-lab-1791568951352758124` | 200 |
| 49 | `8595aeeecc3aaabe6c769638119dba52` | Motif XSS envoyé par le même script ; événement distinct | 200 |

À `2026-10-09T18:02:34.438+0000`, Wazuh enregistre l'alerte `1791568954.1257080`, règle `110101`, niveau local 8, avec l'identifiant de la ligne 48. L'extrait contient aussi une alerte `110102` liée à la ligne 49. Le motif SQLi et le motif XSS sont donc distingués dans les preuves de ce scénario. La recherche témoin n'a pas d'alerte personnalisée dans l'extrait examiné, conformément au résultat initial.

Les dates des fichiers de retest ne fournissent pas une chronologie détaillée de chaque requête. Ils attestent les résultats des deux modes du test, sans permettre d'inventer leurs heures exactes ou une séquence temporelle par rapport au signal Wazuh ci-dessus.

## 4. Qualification

**Confirmé :** motif SQLi dans une entrée contrôlée, correspondance avec la règle Wazuh et origine autorisée du test. La règle personnalisée examine le contenu des paramètres. Un user-agent de type `curl` n'est pas, à lui seul, une preuve d'attaque.

**Non établi par l'événement :** exécution effective de la condition SQL, nombre de produits retournés, données extraites, modification de la base, identité d'un attaquant ou persistance. HTTP 200 indique une réponse HTTP réussie ; il ne démontre pas le succès d'une exploitation.

**Qualification retenue :** motif de tentative SQLi confirmé dans un exercice autorisé, avec exploitation non établie par cette seule trace. La priorité métier d'un incident réel demanderait de connaître l'exposition du service et les données concernées ; la sévérité du mapping historique et le niveau Wazuh ne remplacent pas cette analyse.

## 5. Ce que démontrent les corrections et les retests

Le mode `MINISOC_HARDENED=1` emploie des requêtes préparées sur les fonctions corrigées et un encodage HTML pour les contenus concernés. Le [script de retest](../../tests/remediation_lab.py) examine réellement les réponses HTTP dans chaque mode :

- Pour la recherche SQLi, le mode initial attend des cartes produits dans la réponse au payload de test ; le mode corrigé attend leur absence. Une recherche légitime reste fonctionnelle dans les deux modes.
- Pour la connexion SQLi, le mode initial attend un accès au parcours de compte avec le payload dédié ; le mode corrigé attend HTTP 401. C'est un test distinct sur `/login.php`, pas un succès de connexion déduit de la recherche en HTTP 200.
- Pour les tests XSS, les conditions vérifient présence brute ou encodage dans les réponses. Elles ne constituent pas une preuve d'exécution JavaScript dans un navigateur.

Dans `remediation-before.json`, `hardened=false` et `passed=true` signifient que les observations attendues du mode vulnérable sont retrouvées. Ils ne signifient pas que le correctif était déjà actif. Dans `remediation-after.json`, `hardened=true` et `passed=true` attestent les conditions du mode corrigé.

Le scan ZAP conserve les alertes SQLi `40018` et XSS reflété `40012` avant correction ; elles ne sont plus signalées après sur la même recherche ciblée. Sept autres catégories restent présentes. La comparaison appuie le retest de ces corrections, sans conclure que toute la boutique est sécurisée.

Une requête contenant un motif SQLi peut toujours être détectée après correction : **les alertes ZAP du retest et les alertes de surveillance Wazuh/Mini-SIEM ne mesurent pas la même chose.** Corriger la recherche ne rend pas une tentative entrante invisible.

## 6. Actions, recommandations et clôture

Actions réalisées pour ce compte rendu : préservation d'un extrait assaini, rapprochement du signal et de l'alerte, comparaison des synthèses HTTP/ZAP, examen des conditions du script et rédaction d'une conclusion limitée aux preuves. Les corrections et tests opérationnels cités sont ceux du bilan du 9 octobre ; ils n'ont pas été rejoués pour rédiger cette analyse. Aucun blocage ni changement d'état de la console n'a été effectué.

Pour une investigation réelle, demander les journaux applicatifs et de base adaptés, les réponses pertinentes et les activités associées pour déterminer l'exploitation et son impact. Préserver les éléments utiles, qualifier le contexte d'autorisation, puis convenir d'une réponse avec le propriétaire du service. Les requêtes préparées et le moindre privilège sont des contrôles pertinents à examiner ; une règle de détection ne les remplace pas.

L'analyse pédagogique est close lorsque le motif, l'alerte, la distinction entre signal et exploitation, ainsi que les preuves et limites du retest sont documentés. Ces critères sont satisfaits ici. Cela ne clôture aucun constat d'entreprise ni l'ensemble des vulnérabilités du laboratoire.

## 7. Repères et reprise en entretien

Le mapping historique utilise [MITRE ATT&CK T1190](https://attack.mitre.org/techniques/T1190/). Il reste un rapprochement indicatif : la boutique est locale et le motif seul ne prouve pas l'exploitation d'une application exposée publiquement. Les recommandations de [prévention SQLi OWASP](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) étayent l'emploi de requêtes paramétrées et du moindre privilège.

Questions à pouvoir expliquer : pourquoi deux réponses HTTP 200 peuvent correspondre à des entrées différentes ; ce qu'il faudrait pour prouver une extraction ; pourquoi les résultats « avant » peuvent être réussis sur un mode vulnérable ; et pourquoi la correction d'une vulnérabilité ne supprime pas forcément une alerte SOC.
