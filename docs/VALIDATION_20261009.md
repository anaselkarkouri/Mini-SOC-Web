# Validation des extensions Mini-SOC - 9 octobre 2026

## Périmètre et conclusion

La base est le projet collectif EMSI 2025-2026, commit `57c885a`. Les extensions d'octobre ont été préparées avec assistance d'outils IA, puis exécutées dans un laboratoire Ubuntu dédié avec des données fictives. Elles améliorent la reproductibilité, la détection, la qualification et les preuves de correction. Le dépôt reste un terrain d'exercice volontairement vulnérable. Il ne démontre ni un SOC de production ni une maîtrise personnelle de tous les outils.

Le parcours réellement exercé est : requête HTTP -> PHP -> MariaDB -> moteur Python -> console SOC / NDJSON -> gestionnaire Wazuh. Le scan ZAP vise uniquement la recherche de la boutique locale. Les résultats ci-dessous sont des observations de laboratoire, et non des résultats sur l'infrastructure d'une entreprise.

## Résultats constatés

| Vérification | Résultat | Portée de la preuve |
| --- | --- | --- |
| Tests unitaires et régressions | 18 réussis (6 historiques + 12 nouveaux) | Motifs indépendants, cas négatifs, masquage, fenêtre causale, score PHP/Python, rotation |
| Syntaxe PHP | 29 fichiers validés | Absence d'erreur de syntaxe ; aucune garantie de logique métier |
| Intégration Docker réelle | 17 vérifications réussies | Collecte, traitement, alertes, export, session, CSRF, justification, historique et droits du moteur |
| Réponses HTTP avant/après corrections | 5 vérifications par mode réussies | Recherche légitime, SQLi de recherche/connexion, encodage XSS reflété/stocké |
| Wazuh manager 4.14.8 | 8 événements HTTP ; règles 110101/110102/110104 observées | SQLi, XSS et corrélation d'échecs rapprochés par event_id ; navigation témoin sans alerte personnalisée |
| OWASP ZAP 2.17.0 | SQLi 40018 et XSS reflété 40012 présents avant, absents après | Même URL et plan ciblé ; sept autres catégories d'alertes restent présentes après |
| Migration MariaDB | Deux exécutions réussies | Un ancien journal et une ancienne alerte conservés, identifiants ajoutés et métadonnées LEGACY |

Les [17 résultats d'intégration](evidence/integration-results.json), [retests avant](evidence/remediation-before.json)/[après](evidence/remediation-after.json), [résultats Wazuh](evidence/wazuh-results.json), [migration](evidence/migration-results.json) et synthèses [ZAP avant](evidence/zap-before-summary.json)/[après](evidence/zap-after-summary.json) sont publiés. Les rapports ZAP bruts sont conservés hors du dépôt : ils peuvent contenir cookies, réponses et paramètres. Les synthèses donnent leur empreinte SHA-256 sans les publier.

Les tests unitaires sont relançables avec les commandes du README. La CI exécute les tests Python, la syntaxe PHP, l'intégration Docker et les retests HTTP. Wazuh et ZAP sont validés localement séparément ; ils ne font pas partie de cette CI.

## Corrections ayant fait l'objet d'un contrôle

- Une navigation avec `curl` ne suffit plus à déclencher une alerte. Les motifs SQLi et XSS sont évalués indépendamment : XSS envoyé avec un user-agent d'outil reste XSS.
- Le seuil Python de brute force compte les véritables POST échoués sur `/login.php`, en remontant 60 secondes depuis l'événement traité. La page renvoie effectivement 401 pour un échec ; le rendu HTML ne précède plus la décision de réponse.
- Les champs usuels de secrets sont masqués avant insertion et export. Les tests contrôlent l'absence du secret témoin dans la base et le fichier JSON.
- Le moteur travaille avec son propre compte de base de données. Le test confirme son incapacité à modifier les comptes clients de la boutique.
- Les qualifications exigent session et CSRF. Une clôture sans note suffisante ou un identifiant inexistant est refusé ; les modifications valides conservent une trace consultable.
- Les corrections optionnelles `MINISOC_HARDENED=1` utilisent des requêtes préparées et de l'encodage HTML sur recherche, connexion et avis. Les retests comparent des réponses réelles ; ils ne démontrent pas l'exécution de JavaScript dans un navigateur.

## Limites à expliquer en entretien

1. Les détections reposent sur des motifs et des seuils, pas sur un modèle exhaustif. Aucun taux de couverture, performance, SLA ou taux de faux positifs n'a été mesuré.
2. Wazuh est un gestionnaire local seul, sans indexeur ni dashboard. Sa corrélation suit l'arrivée des événements ; la fenêtre Python suit leurs horodatages sources. Un rejeu ou un retard d'ingestion peut donc donner un résultat différent.
3. L'export est « au moins une fois » : une interruption entre export et commit peut créer un rejeu portant le même event_id. La rotation limite la taille, pas une conservation de 90 jours. Aucune purge SQL automatique n'est ajoutée.
4. Le masquage ne reconnaît pas tout secret sous un nom arbitraire. Un motif placé uniquement dans un champ masqué ne peut plus être détecté. Les anciens journaux ne sont pas nettoyés par la migration.
5. L'historique est protégé par les droits applicatifs, mais l'administrateur MariaDB peut le modifier. Il n'est pas immuable.
6. Le mapping MITRE ATT&CK est indicatif : un motif XSS ne prouve pas l'exécution de JavaScript, et une tentative n'est pas une compromission démontrée.
7. Le mode corrigé reste pédagogique : mots de passe clients fictifs en clair et autres vulnérabilités résiduelles. Les sept catégories ZAP restantes incluent CSP, clickjacking, informations serveur, en-têtes et observations de session/attribut HTML. L'absence des deux alertes ciblées ne signifie pas que l'application est sécurisée globalement.
8. Les captures du README et le rapport collectif sont historiques (juin 2026). Les preuves JSON datent des extensions d'octobre ; aucune capture historique n'est présentée comme une preuve du nouvel essai.

## Sources de conception

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) : données sensibles et événements utiles.
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) : réponses et gestion de session.
- [Docker : publication de ports](https://docs.docker.com/engine/network/port-publishing/) : liaison locale explicite.
- [ZAP Automation Framework](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-ascan/) : règles actives et limites du plan.
- [Wazuh : syntaxe des règles](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html) : champs, corrélation et fenêtre de temps.

L'équipe initiale et l'encadrement sont conservés dans le README et le rapport. Pour réutiliser ce projet sur un CV, annoncer un projet collectif de laboratoire avec extensions documentées, sans résultat de production ni attribution exclusive du travail collectif.
