# Lire le Mini-SOC du point de vue de l'analyste

Ce projet collectif EMSI relie des requêtes HTTP, des événements, des règles Python et un tableau de bord SOC. Il s'agit d'un laboratoire web de démonstration, pas d'un SOC de production. La qualification tracée, l'intégration Wazuh et les retests ciblés sont documentés dans le [bilan de validation](VALIDATION_20261009.md), qui distingue les résultats des tests de la démonstration historique.

## Le parcours d'un signal

1. Une requête atteint la boutique PHP avec des données fictives.
2. Le collecteur conserve les informations HTTP utiles dans la base locale.
3. Le [moteur Python](../mini_siem/mini_siem.py) examine les nouveaux événements : motifs SQLi/XSS et seuil de connexions échouées.
4. Une alerte conserve sa source, sa charge utile, sa sévérité et le contexte de la règle.
5. La console permet de consulter les détails et de suivre le traitement.

## Questions de qualification

| Signal du laboratoire | Questions à examiner | Ce qu'il ne prouve pas seul |
| --- | --- | --- |
| Motif SQLi | URL et paramètre concernés ? Requête autorisée ? Réponse et événements associés ? | Extraction de données ou compromission effective de la base |
| Motif XSS | Contenu envoyé ? Stocké ou reflété ? Exécution observée dans le navigateur ? | Exécution JavaScript, vol de session ou correspondance ATT&CK définitive |
| Seuil de connexions échouées | Compte et source concernés ? Échecs puis succès ? Activité d'exercice ou usage légitime ? | Compte compromis ou attribution à un attaquant |

Une règle déclenche une investigation. Son nom et sa sévérité sont des choix du laboratoire. Le code de réponse HTTP, l'adresse source ou le user-agent ne suffisent pas, isolément, à confirmer une attaque réussie.

## Mapping et réponse

Le [mapping MITRE ATT&CK](../mini_siem/mitre_mapping.json) sert à enrichir les alertes et à expliquer les scénarios. Il reste à interpréter selon les comportements réellement observés. Un motif XSS dans une requête ne démontre pas l'exécution de JavaScript. Les recommandations affichées sont des pistes de traitement ; le moteur ne réalise pas automatiquement un blocage de production ou une réponse à incident complète.

Avant une action, conserver les éléments utiles, qualifier le signal et préciser l'autorité requise. Dans le laboratoire, les exercices utilisent une instance locale et des comptes fictifs.

## Vérifications existantes

Les [six tests historiques](../mini_siem/test_detection.py) et [douze tests de régression](../tests/test_regressions.py) vérifient les règles et les cas négatifs, la cotation commune PHP/Python, le masquage et la rotation. Ces tests unitaires utilisent des doubles de base de données : ils ne prouvent pas l'intégration à eux seuls.

Les [17 vérifications d'intégration](../tests/integration_lab.py) distinctes utilisent PHP, MariaDB et le moteur en fonctionnement sous Docker. Elles couvrent notamment les réponses HTTP, les données conservées, la session analyste, la protection CSRF et l'historique de qualification. Des requêtes réelles ont aussi été rapprochées des alertes du gestionnaire Wazuh. Les preuves et les limites figurent dans le bilan ; cela ne mesure pas toute la console, un taux de faux positifs ou une performance de production.

Les [captures de juin 2026](media/README.md) et le [rapport collectif](Rapport_Mini_SOC_Web.pdf) documentent la démonstration historique. Cette lecture ne constitue pas une nouvelle mesure de taux de détection, de faux positifs ou de performance.

## Limites utiles à expliquer

- Les règles par motifs peuvent produire des faux positifs et laisser passer des variantes.
- Le score est un indicateur local calculé avec les poids du projet ; il n'est pas une mesure universelle du risque cyber.
- Le projet ne démontre pas une supervision permanente, un déploiement à grande échelle ou une couverture exhaustive d'ATT&CK.
- Les fonctionnalités volontairement vulnérables appartiennent au terrain d'exercice local.
- La réalisation et les résultats sont collectifs ; le rapport précise la répartition du travail.

## Trame pour un compte rendu d'alerte

Pour reprendre un exercice, renseigner : date et périmètre, source de l'événement, règle déclenchée, observations confirmées, hypothèses, éléments manquants, qualification proposée, recommandation et critère de clôture. Garder séparées la détection d'un motif, la preuve d'exploitation et l'action réellement réalisée.
