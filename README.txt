AUTODEX V9 — FOURCHETTES DE PRIX ET DIAGNOSTIC DE SAUVEGARDE

Contenu du projet :
- server.js : API et stockage PostgreSQL
- public/index.html : application AutoDex
- package.json : dépendances et commande de démarrage

Changements V9 :
- Les estimations de prix proposent désormais une fourchette indicative basse/haute autour de la valeur de référence. La largeur augmente pour les voitures rares et haut de gamme. Il ne s'agit pas d'une expertise ni d'une garantie de prix de vente.
- La fourchette est conservée dans la fiche de la voiture et affichée dans la collection et les profils.
- Les photos importées sont redimensionnées à 1800 px et compressées en JPEG qualité 80 % pour réduire le volume envoyé à la base de données.
- Les erreurs de sauvegarde donnent des messages plus utiles et le serveur consigne le code et le message de l'erreur dans les logs Render, sans afficher de données secrètes au visiteur.
- Le code garde le catalogue, le cadrage et l'affichage photo plein écran existants.

Installation : remplace les fichiers server.js et public/index.html dans le dépôt, commit puis push. Render doit redéployer.

Important : la correction ne peut pas garantir de résoudre une panne liée aux limites du fournisseur PostgreSQL ou à une configuration de compte. Si la sauvegarde échoue encore, lire le log « Save collection failed » sur Render : le code d'erreur permettra de cibler la cause. Ne supprimez pas la base de données.


V10 — Estimations modèles rares
- Ajout d’une référence spécifique pour la Koenigsegg CC8S afin que le CSV généraliste ne la sous-évalue pas.
- Fourchette large et indicateur de confiance faible car les transactions publiques comparables sont extrêmement rares.
- Google AI Overviews n’est pas utilisé directement : ce n’est pas une API stable d’estimation. Les sources publiques sont indiquées dans la réponse de l’API.

NOUVEAUTÉS — MENU ET PROFIL
- Le bouton Déconnexion est remplacé par un menu en haut à droite : Accueil, Mon profil et Déconnexion.
- La page Mon profil permet de modifier le pseudo, choisir/retirer une photo de profil, et consulter les statistiques de la collection.
- La photo est redimensionnée dans le navigateur avant envoi et enregistrée sur le compte ; elle apparaît dans la liste d'amis et les profils d'amis.
- La base existante est migrée automatiquement avec la colonne profile_photo au démarrage du serveur.
- Le pseudo doit rester unique et respecter les règles habituelles (3 à 24 caractères, lettres/chiffres/_/-).

V12 — Récompenses et skins d'exposition
- Menu : nouvel onglet Récompenses.
- Paliers calculés à partir de la somme des valeurs (champ prix) de la collection : Bronze 100 000 €, Argent 500 000 €, Or 1 000 000 €, Platine 2 500 000 €, Diamant 5 000 000 €, Arc-en-ciel 10 000 000 €, Galaxy 20 000 000 €, Godly 50 000 000 €.
- Les skins débloqués peuvent être équipés ; le choix est enregistré sur le compte dans display_skin.
- Le cadre, l'emblème sous la photo et le fond coloré décorent les fiches de voiture dans la collection et le profil public.
- Migration automatique de la colonne display_skin au démarrage. Les comptes et collections existants sont conservés.
