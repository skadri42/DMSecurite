# DM Cybersécurité


# Injection SQL

L’ injection SQL est une des failles de sécurité web les plus courantes : elle permet à un attaquant d’insérer des requêtes malveillantes dans une base de données, menaçant la confidentialité, l’intégrité et la disponibilité des systèmes informatiques.

## Description détaillé 

Une injection SQL survient quand des données fournies par l’utilisateur (formulaire, URL, cookie, etc.) sont incorporées dans une requête SQL sans filtrage ou protection adéquate. Par exemple, si un champ "id" envoyé par l'utilisateur est directement inséré dans une requête, il est possible d’altérer la requête initiale et d’exécuter tout type de commande SQL sur la base de données:

    db.query(`SELECT * FROM users WHERE id = ${req.param('id')}`);

Si l'utilisateur soumet : `-1 UNION SELECT email, password FROM users`, cela expose toutes les données d’utilisateurs au lieu du seul utilisateur demandé.

## Risques sur le système

Les attaques par injection SQL peuvent avoir des impacts très graves:

-   **Accès non autorisé**  à des données sensibles (emails, mots de passe, cartes de crédit)
    
-   **Altération ou suppression**  de données (corruption, perte), parfois définitives
    
-   **Usurpation d’identité**  et vol de comptes utilisateurs ou administrateurs
    
-   **Dégradation du service**  (interruption, publication de faux contenus, défiguration)
    
-   **Mouvement latéral**  permettant de compromettre d’autres systèmes connectés
    
-   **Perte de réputation**, violation de conformité RGPD ou autres

## Sécurisation

Pour se prémunir contre l’injection SQL, voici les mesures principales:

-   **Ne jamais faire confiance aux données utilisateur**  et toujours filtrer/valider les entrées
    
-   **Éviter la concaténation de chaînes**  pour écrire des requêtes SQL
    
-   **Utiliser des requêtes préparées/procédures paramétrées**  dans tous les langages (voir exemples ci-dessous)
    
-   **Limiter les privilèges**  des comptes SQL (principes de moindre privilège)
    
-   **Surveiller et auditer**  régulièrement les accès et les logs

Exemple de sécurisation : 

    db.query("SELECT * FROM users WHERE id = ?", [req.param('id')]);

La valeur id est géré comme une donnée et non comme du SQL.


# XSS


Le Cross-Site Scripting (XSS) est une faille de sécurité qui permet à un attaquant d’injecter du code client malveillant (souvent JavaScript) dans une page web consultée par d’autres utilisateurs, compromettant ainsi la sécurité des internautes.

## Description détaillé

Le XSS survient quand une application web affiche des données non fiables, comme des champs de formulaire ou des URL, sans validation ni échappement approprié. L’attaquant peut alors injecter un script qui sera exécuté par le navigateur de la victime dès que la page vulnérable sera affichée. 
Il existe trois grandes catégories :

-   **XSS stocké**  : le code malveillant est enregistré sur le serveur (dans une base de données ou commentaire), puis diffusé à tous les visiteurs.
    
-   **XSS réfléchi**  : le code est renvoyé dans la réponse HTTP après avoir été fourni par l’utilisateur via une requête (souvent dans les paramètres de l’URL).
    
-   **XSS basé sur le DOM**  : le script est exécuté parce qu’une modification du DOM via JavaScript insère du contenu utilisateur non filtré.

Exemple de mauvais code : 

    <form  method="get"> 
     <input  type="text"  name="name"> 
     <input  type="submit"  value="Envoyer"> 
    </form> 
    Bonjour, <?php echo $_GET['name']; ?>

Un utilisateur peut soumettre `<script>alert('XSS')</script>` et faire exécuter ce JS à chaque visiteur.

## Risques

Le XSS est très dangereux car il cible directement les utilisateurs d’un site web :

-   **Vol de données sensibles**  (cookies, identifiants, jetons de session)
    
-   **Prise de contrôle de compte**  en exploitant des sessions actives
    
-   **Hameçonnage et redirections**  automatiques vers des sites malveillants
    
-   **Installation de malware**  sur le terminal de la victime
    
-   **Défiguration du site**  ou modifications du contenu affiché
    
-   **Propagation de worm**  à travers la plateforme

## Sécurisation


Pour contrer les failles XSS, il est indispensable de :

-   **Échapper et filtrer systématiquement**  toutes les données affichées côté client (HTML, JS, CSS)
    
-   **Utiliser des fonctions natives de sécurisation**  (`htmlspecialchars()`  en PHP, méthodes d’encodage dans les frameworks modernes)
    
-   **Implémenter une politique CSP (Content Security Policy)**  pour restreindre les sources valides de script
    
-   **Limiter les permissions JavaScript**  et désactiver l’exécution de scripts tiers si possible
    
-   **Valider côté serveur et côté client**  toutes les données et les requêtes utilisateur

Exemple de sécurisation : 

    <span>{userInput}</span>
Ces mesures empêchent l’interpréteur HTML/JS du navigateur d’exécuter les scripts injectés, bloquant ainsi toute tentative XSS.


# Brute Force

L’ attaque par brute force est une technique par laquelle un attaquant cherche à deviner des mots de passe ou des clés d’accès en testant systématiquement toutes les combinaisons possibles, souvent à l’aide d’outils automatisés.

## Description détaillé


Le fonctionnement du brute force repose sur l’automatisation : un programme essaie des milliers, voire des millions de combinaisons (lettres, chiffres, symboles) jusqu’à trouver la bonne valeur permettant d’accéder à un compte ou un service sécurisé. Cette méthode est d’autant plus efficace que les mots de passe sont faibles, courts ou figurent dans des listes connues (liste de mots du dictionnaire). L’attaque peut être purement exhaustive, ou optimisée via des listes de mots de passe courants, voire combinée avec d’autres techniques (hybride, dictionnaire).

Exemple de code de brute force en python : 

    URL =  "https://cible.com/login" 
    user =  "admin" 
    for pwd in  ["123456",  "password",  "admin123"]: 
	    r = requests.post(URL, data={'username': user,  'password': pwd}) 
	    if  "Bienvenue"  in r.text:  # Condition simple 
		    print("Mot de passe trouvé:", pwd)

## Risques

Les impacts principaux du brute force :

-   **Accès non autorisé**  à des comptes sensibles, administrateurs ou bases de données
    
-   **Vol de données personnelles**  et professionnelles (identité, informations bancaires, etc.)
    
-   **Compromission de systèmes stratégiques**  (serveurs, VPN, boîtes mails)
    
-   **Blocage ou ralentissement**  de services à cause du trafic massif causé par l’attaque
    
-   **Rebond sur d’autres attaques**  : le brute force sert souvent à préparer une compromission plus vaste ou à exploiter d’autres failles

> **Note:** The **Publish now** button is disabled if your file has not been published yet.

## Sécurisation 

Pour limiter ce risque, il faut :

-   **Imposer des mots de passe forts**  : longueur et complexité élevée (majuscules, chiffres, symboles, aucune réutilisation)
    
-   **Limiter le nombre de tentatives**  : verrouiller le compte ou activer le CAPTCHA après X échecs consécutifs
    
-   **Mettre en place un délai après chaque tentative**  (temporisation, rate limiting) 

-   **Utiliser l’authentification multi-facteurs (MFA)**

Exemple de code pour ajouter un délai : 

    for pwd in pwd_list:
    login(pwd)
    time.sleep(2)  # Temporisation de 2 secondes


# Sécurisation d'une base MySQL

Dans le tp flopsécurity on applique la stratégie du moindre privilège qui est une règle de base en sécurité informatique : on donne à chaque utilisateur ou programme uniquement les droits nécessaires pour effectuer ses tâches, et rien de plus. Cela veut dire qu’on limite leurs accès aux fonctions ou aux données dont ils ont vraiment besoin, pour réduire les risques en cas d’attaque ou d’erreur. Dans notre cas, l'administrateur dba possède les droits pour la gestion et les sauvegardes alors que l'utilisateur applicatif est seulement limité à sa base de donnée qui lui est propre. Cette pratique vise a réduire l'impact d'une potentiel attaque et d'éviter une expostion du  compte root.

# Connexion SSH
## Liste des solutions pour sécuriser OpenSSH-Server :
-   Changer le port par défaut (ex:  `Port 2222`) pour réduire les scans automatiques.
 -   Restreindre les permissions sur les clés privées (chmod 700 ~/.ssh,).
 - Surveiller régulièrement les logs : `/var/log/auth.log`
 - Désactiver l'accès root direct le compte "root" est souvent visé, on force l'administrateur à se connecter avec utilisateur normal puis à utiliser sudo.

## Fichiers à modifier : 
-   **/etc/ssh/sshd_config**  : Fichier central pour la configuration du serveur OpenSSH.

## Sécurisation

    Protocol 2                    # Utiliser uniquement le protocole SSH v2
    PermitRootLogin no            # Interdire la connexion en root
    AllowUsers user1 user2        # Autoriser uniquement les utilisateurs 
    LogLevel VERBOSE              # Activer les logs détaillés pour surveiller



# Firewall

## Rôle d'un firewall
-   Son objectif principal est de contrôler, filtrer et analyser les flux de données  entre réseaux internes et externes.
    
-   Il protège contre les accès non autorisés, les cyberattaques, les virus, et les malwares, tout en permettant de limiter ou autoriser les connexions selon la politique de sécurité définie.

## Configuration 

La configuration dépend du type de firewall (logiciel ou matériel), mais les étapes majeures comprennent :

-   Définir les règles  : spécifier quelle adresse IP, port ou protocole est autorisé ou bloqué.
    
-   Déterminer les flux qu'on doit autoriser  : choisir quels services (web, mail, VPN) peuvent communiquer entre les réseaux.
    
-   Activer l’inspection du trafic  pour repérer les menaces et blocages automatiques.
   
   Exemple : 
   
## Paramètres
Les paramètres les plus courants à ajuster incluent :

-   Règles sur les adresses IP  (authorized/blocked)
    
-   Règles sur les ports (ex : ouverture du port 80 pour le web)
    
-   Protocoles  (ex : TCP, UDP)
    
-   Services et applications protégées
    
-   Niveaux de journalisation et alertes
    
-   Politiques en fonction de plages horaires ou de profils d’utilisateur
    
-   Inspection profonde des paquets et filtrage web
    
-   Options pour le VPN, la gestion des tunnels, le filtrage antivirus.

## Rôle des autres solutions de sécurisation

## Rôle des mises à jour système

-   Correction des vulnérabilités  : chaque mise à jour réduit l’exposition du système aux attaques, notamment en exterminant les brèches utilisées pour les ransomwares, les virus ou le vol d’informations.
    
-   Renforcement de la protection des données : elles bloquent les accès non autorisés et réduisent les risques de piratage et de fuite de données personnelles.
    
-   Amélioration de la stabilité  : les mises à jour corrigent des bugs, optimisent le système et assurent un environnement plus fiable.

## Configuration Apach2

Pour sécuriser Apache2, il faut principalement modifier le fichier `/etc/apache2/apache2.conf`

Exemple de configuration pour sécurisé apache2 : 

    ServerTokens Prod # Cache les infos version d’Apache 
    ServerSignature Off # Désactive l'affichage de la signature serveur sur les pages d'erreur 
    TraceEnable Off # Désactive la méthode TRACE 
    Options -Indexes # Désactive l'affichage du contenu des dossiers sans index 
    Timeout 60 # Réduit le temps d’attente 
    LimitRequestBody 4096 # Limite la taille des requêtes

## Ré écriture d'url 

-   peut masquer la structure du système et empêcher certaines attaques par “information leakage”.
    
-   si mal configurée, elle peut ouvrir des failles (ex: accès involontaires à des fichiers sensibles ou des chemins non prévus).
    
-    essentiel de filtrer et valider les paramètres passés dans les url re écrite désiré.

La re écriture d’url est donc utile pour l’organisation et la confidentialité des chemins, mais seule une bonne configuration protège contre les risques de sécurité.

## Veille technologique

Les publications de  l'ANSSI  utiles pour sécuriser un site web sont principalement :

-   Le guide « Recommandations pour la mise en œuvre d’un site web : maîtriser les standards de sécurité côté navigateur » conseille sur l’application de standards tels que TLS, Content Security Policy, SubResourceIntegrity, sécurisation des cookies, gestion des journaux et principes d’administration.
    
-   Des documents synthétiques sur les « 10 règles d’or de la sécurité numérique » et les pratiques à adopter pour limiter les risques liés aux CMS, plugins et thèmes, ainsi que la gestion des sauvegardes, de l’accès administrateur et du moindre privilège.
    
-   Les publications officielles ANSSI couvrant l’application des mécanismes côté navigateur (CSP, HSTS, SRI), configuration du TLS, principes d’audit, monitoring, et tests de vulnérabilité.
    

## OWASP Top 10 : 

D’après le OWASP, les risques critiques pour les applications web sont :

-   **Contrôle d'accès insuffisant**  : droits mal vérifiés, manipulations non autorisées.
    
-   **Défaillances cryptographiques**  : gestion faible ou absente du chiffrement, menant à l’exposition de données sensibles.
    
-   **Injection**  : exploitation de champs non sécurisés pour insérer et exécuter du code malveillant (inclut XSS, SQL, etc.).
    
-   **Conception non sécurisée**  : architectures ou modèles non réfléchis pour la sécurité dès la phase de conception.
    
-   **Mauvaise configuration de sécurité**  : services ou applications mal paramétrés, laissant des failles ouvertes.
    
-   **Composants vulnérables et obsolètes**  : dépendances non mises à jour ou non maintenues, source fréquente d’attaques.
    
-   **Défaillance d’identification et d’authentification**  : absence ou faiblesse des contrôles d’identité et des mots de passe, risque d’usurpation.
    
-   **Défaillances d’intégrité logicielle et des données**  : absence de vérification des sources, risque d’altérations du code ou des données.
    
-   **Défaillances de journalisation et monitoring**  : incapacité à repérer les intrusions ou à répondre aux incidents par manque de logs ou d’alertes.
    
-   **Server-Side Request Forgery (SSRF)**  : abus du serveur pour accéder, à l’insu de l’utilisateur, à des ressources internes ou externes.
    

Ces publications et référentiels permettent d’appliquer une méthode structurée et exhaustive pour la sécurisation et le suivi continu de tout site web.
