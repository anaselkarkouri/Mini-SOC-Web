# SOC-01 - Qualification d'échecs de connexion répétés

- **Périmètre :** boutique fictive du Mini-SOC, laboratoire local dédié.
- **Traces :** 9 octobre 2026 ; horodatages UTC.
- **Compte rendu :** 10 octobre 2026, préparé avec assistance d'outils IA à partir des pièces conservées.
- **État :** analyse documentaire de l'exercice terminée ; aucun incident d'entreprise déclaré.

## 1. Résumé

Cinq requêtes POST vers `/login.php`, depuis une même adresse du réseau Docker, ont reçu HTTP 401. Les cinq événements portent le même marqueur de test. L'alerte Wazuh `110104` conserve un événement déclencheur et les quatre autres dans son contexte de corrélation. Le signal attendu du scénario est donc confirmé. Ces éléments ne démontrent ni un mot de passe deviné, ni un compte compromis, ni une attaque réelle. L'origine est un script autorisé du laboratoire.

## 2. Sources et question de qualification

- [Extrait des événements et alertes](../evidence/investigation-reference-20261009.json) : huit événements uniques du scénario, dont cinq échecs de connexion ; aucun doublon de ces identifiants dans l'export examiné.
- [Résultat Wazuh initial](../evidence/wazuh-results.json) : rapprochement de l'alerte `110104` par `event_id`.
- [Script de génération](../../scripts/verify_wazuh_lab.py) : cinq tentatives sur un identifiant fictif, avec un mot de passe témoin identique. Il s'agit d'un test de corrélation, pas d'une recherche effective de mots de passe.
- [Moteur Python](../../mini_siem/mini_siem.py) et [règles Wazuh](../../integrations/wazuh/minisoc_rules.xml) : mécanismes à distinguer.

Question : le seuil attendu est-il atteint, quelles traces relient le signal à l'alerte, et existe-t-il un indice de connexion réussie dans ce périmètre ?

## 3. Chronologie et événements

Les horodatages sources sont limités à la seconde : les cinq POST ont la valeur `2026-10-09T18:02:31Z`. Les numéros de ligne donnent leur ordre dans l'export NDJSON conservé ; ils ne fournissent pas une précision temporelle supplémentaire.

| Ligne NDJSON | event_id | Méthode / route | Réponse |
| --- | --- | --- | --- |
| 50 | `2a72386aa819d629e023673080adb2ce` | POST `/login.php` | 401 |
| 51 | `b95aea1e705973a3d2a1c00005bac9de` | POST `/login.php` | 401 |
| 52 | `4f20fea6e83ab991de122fdd9d32065f` | POST `/login.php` | 401 |
| 53 | `35bf2d77911e68fefdceea8ce30b249b` | POST `/login.php` | 401 |
| 54 | `0682e1386dba41638dad3198bf2dc6ef` | POST `/login.php` | 401 |

Tous indiquent `src_ip = 172.29.23.1`. Les paramètres exportés contiennent le marqueur fictif `wazuh-lab-1791568951352758124` et `[REDACTED]` à la place du mot de passe.

À `2026-10-09T18:02:34.439+0000`, Wazuh enregistre l'alerte `1791568954.1255447`, règle `110104`, niveau local 8. Son `event_id` est celui de la ligne 53. Son `previous_output`, repris sous forme d'événements assainis dans la preuve, contient les quatre autres identifiants, y compris celui de la ligne 54. **Il serait donc incorrect d'affirmer que Wazuh a déclenché sur le cinquième événement selon l'ordre du fichier.** Le contexte atteste les cinq échecs ; l'ordre de traitement du gestionnaire ne se déduit pas du seul ordre de cet export.

## 4. Raisonnement

**Confirmé dans les pièces :** cinq POST en échec, même adresse source observée, même marqueur, même seconde source et présence de l'alerte de corrélation avec les cinq identifiants. La requête de recherche témoin en HTTP 200 est distincte et n'est pas un succès d'authentification.

**Non démontré :** diversité des mots de passe, compte réel visé, connexion réussie, vol de session, origine humaine ou couverture de toutes les authentifications. Le mot de passe est masqué et le script répète un identifiant fictif ; aucune sous-technique de devinette ou de password spraying n'est validée par ce test.

L'adresse est celle observée dans le réseau du laboratoire. Elle ne doit pas être présentée comme une adresse publique d'attaquant ni recherchée comme un indicateur de réputation Internet. Une adresse partagée derrière un proxy/NAT peut aussi agréger plusieurs utilisateurs : une corrélation par IP demande du contexte.

Le moteur Python compte au moins cinq POST échoués de la même source dans une fenêtre de 60 secondes ancrée sur l'événement. Wazuh utilise une règle de corrélation configurée avec `frequency="5"` et `timeframe="60"`, selon l'arrivée des événements. Le résultat conservé établit une alerte sur ce scénario ; il ne prouve pas une équivalence générale des deux fenêtres ni le comportement pour tous les cas limites. Le niveau 8 est un paramètre du laboratoire, pas une priorité métier universelle.

## 5. Qualification et actions

**Qualification retenue :** signal de test autorisé, correctement corrélé sur les traces disponibles ; pas de compromission démontrée. Le qualifier simplement de « faux positif » masquerait le fait que la règle reconnaît les échecs attendus. L'absence de malveillance réelle vient du contexte d'exercice.

Actions réalisées pour ce compte rendu : extraction assainie des pièces, rapprochement des cinq événements avec l'alerte et son contexte, examen du script et des règles, conservation des empreintes des fichiers sources. Aucun blocage, changement de mot de passe ou changement de statut de la console n'a été effectué.

Dans une situation réelle à qualifier, les étapes proposées seraient : vérifier le propriétaire du compte et les tests autorisés ; rechercher les succès et sessions associés sur une fenêtre adaptée ; examiner les autres sources et comptes ; puis faire décider d'une mesure proportionnée. MFA et limitation de tentatives seraient des contrôles à examiner, pas des fonctions démontrées sur cette connexion de boutique. Un blocage automatique d'adresse ou de compte peut pénaliser des utilisateurs légitimes.

## 6. Clôture et lien avec le risque

L'analyse de l'exercice est close lorsque les cinq identifiants, l'alerte et la qualification sont traçables, et que les limites sont explicites. Ce compte rendu remplit ces critères. Il ne clôture aucun risque de la PME fictive des projets GRC et ne modifie aucun statut de production.

Pour un incident réel, l'absence de succès dans ces cinq lignes ne suffirait pas à clore le dossier : il faudrait étendre les vérifications, examiner les sessions et obtenir les validations adaptées.

Le lien GRC est le risque d'accès non autorisé, les contrôles d'authentification et la qualité des preuves de surveillance. La preuve démontre un mécanisme de détection sur un échantillon, pas l'efficacité globale d'un IAM ou d'un SOC.

## 7. Repères et reprise en entretien

[MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/) sert de repère pour les attaques par force brute. Ici, il reste indicatif : le test n'établit pas une activité malveillante ou une sous-technique précise. La [syntaxe Wazuh](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html) explique les champs de corrélation ; le seuil retenu est un choix du laboratoire.

Questions à pouvoir expliquer : pourquoi 401 est utile sans prouver une attaque ; pourquoi cinq échecs ne démontrent pas une compromission ; pourquoi l'IP locale n'identifie pas un attaquant ; et pourquoi le contexte Wazuh complète l'événement déclencheur.
