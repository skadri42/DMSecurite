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
