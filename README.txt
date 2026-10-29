AutoDex — paquet de projet

Contenu :
- server.js : serveur Node.js/Express, route de skin incluant `default: 0`.
- public/index.html : interface avec le skin « Par défaut » gratuit et équipable.
- package.json : dépendances et commande de démarrage pour Render.

Déploiement Render :
1. Décompresse cette archive.
2. Dans ton dépôt GitHub, remplace server.js, package.json et public/index.html par les fichiers correspondants.
3. Conserve les variables d'environnement Render existantes, notamment DATABASE_URL. Ne supprime pas la base de données.
4. Fais un commit et attends le redéploiement.

Le serveur utilise PostgreSQL via DATABASE_URL. Le fichier package-lock.json sera généré par npm install si nécessaire.
