# Dashboard SOC

## Accès

1. Suivre le lancement Docker du [README principal](../README.md). Pour une base historique, sauvegarder et utiliser la migration additive sur une copie ; `database/schema.sql` réinitialise les tables d'un laboratoire neuf.
2. Se connecter au dashboard SOC avec `admin / votre mot de passe défini localement`.
3. Ouvrir `soc/index.php` depuis le projet local.

## Utilisation

- Les cartes affichent le total des alertes, SQLi, XSS et Brute Force.
- La barre de dates filtre les statistiques, le trend, le tableau et le rapport.
- Les filtres permettent de chercher par type d'attaque, gravité, statut, IP, URL, payload ou MITRE ID.
- Le tableau affiche les alertes récentes créées dans la table `alerts`.
- Le panneau de droite et `detail.php?id=ID` montrent l'IP source, l'URL ciblée, le payload, la règle déclenchée, le MITRE ID, la tactique, la technique et la réponse recommandée.
- Cliquer une alerte récente la sélectionne dans le panneau détail sans modifier son état de lecture.
- Le menu `Alerts` affiche l'historique complet sans détail et marque les alertes comme lues.
- Le statut peut être changé entre `nouveau`, `en_cours`, `resolu` et `faux_positif`. Une clôture demande une justification d'au moins cinq octets ; chaque modification conserve l'auteur, les anciens/nouveaux statuts et la note dans l'historique.
- Les mutations requièrent une session analyste et un jeton CSRF. Un identifiant inexistant ou une note invalide renvoie une erreur.
- `api.php` lit les données et le dernier cycle du moteur. Le moteur externe est lancé par Compose ; son démarrage depuis PHP est désactivé par défaut.
- `settings.php` contient le dark mode et la configuration du rafraîchissement.
- `report.php` permet de prévisualiser et générer un rapport PDF.
- `mitre.php` explique les techniques MITRE utilisées dans ce projet.
- `guide.php` donne la procédure courte de test et démonstration.
