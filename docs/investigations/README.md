# Deux comptes rendus d'investigation SOC

Ces deux analyses complètent le Mini-SOC collectif. Elles utilisent les traces réelles d'un même scénario contrôlé, exécuté dans le laboratoire le 9 octobre 2026 : une navigation témoin, une requête SQLi, une requête XSS et cinq échecs de connexion. Les comptes rendus ont été préparés le 10 octobre avec assistance d'outils IA, pour être relus, expliqués et repris personnellement.

| Cas | Question étudiée | Conclusion bornée |
| --- | --- | --- |
| [SOC-01 - Échecs de connexion](SOC-01_echecs_connexion.md) | Que démontre une corrélation de cinq échecs ? | Signal de test confirmé ; aucun succès de connexion dans les cinq événements examinés |
| [SOC-02 - Tentative SQLi](SOC-02_tentative_SQLi.md) | Comment distinguer motif, tentative et exploitation ? | Motif SQLi confirmé et rapproché de l'alerte Wazuh ; exploitation non établie par cet événement seul |

Chaque compte rendu contient le périmètre, la chronologie, les justificatifs, la qualification, les actions réellement réalisées, les recommandations et les critères de clôture. La comparaison des corrections HTTP/ZAP du cas SQLi constitue une preuve complémentaire distincte, et non le contenu de la réponse HTTP de la requête d'origine.

## Examiner les preuves

- [Extrait assaini : huit événements, trois alertes Wazuh et contexte de corrélation](../evidence/investigation-reference-20261009.json).
- [Résultat Wazuh publié lors du test initial](../evidence/wazuh-results.json).
- [Script qui a généré les requêtes de référence](../../scripts/verify_wazuh_lab.py).
- [Vérification de cohérence des pièces](../../scripts/review_case_evidence.py).

Depuis la racine du dépôt, sans Docker, base de données ni accès réseau :

```bash
python scripts/review_case_evidence.py
```

Ce contrôle relit les pièces conservées. Il ne rejoue pas les requêtes et ne constitue pas un nouveau test de Wazuh ou de ZAP. Les fichiers d'origine restent privés ; leurs empreintes SHA-256 sont conservées dans l'extrait public. Les mots de passe, cookies et clés ne sont pas publiés.

## Pour reprendre le travail personnellement

1. Retrouver chaque `event_id` cité dans l'extrait JSON et expliquer le rôle de chaque source.
2. Justifier la conclusion avec les traces, puis citer une information encore manquante.
3. Expliquer pourquoi HTTP 200 ne prouve pas une connexion réussie ou une extraction de données.
4. Reprendre les scénarios sur une instance locale dédiée, avec des comptes fictifs, puis conserver ses propres observations selon la [trame analyste](../LECTURE_ANALYSTE.md).

Ces analyses ne représentent pas deux incidents d'entreprise, un service SOC de production ou une compétence déjà maîtrisée. L'état des alertes de la console n'a pas été modifié pour créer ces comptes rendus.
