# Splunk SOC Home Lab

Documentation d'un lab SIEM Splunk monté en local (Windows natif, ressources limitées) dans le cadre de ma préparation à un rôle SOC Analyst / GRC.

## 🎯 Objectif du lab

Mettre en place une chaîne complète de collecte et d'analyse de logs avec Splunk : Universal Forwarder → Indexeur → Recherches SPL → Dashboards de détection, en environnement contraint (RAM limitée, machine unique).

## 🏗️ Architecture

```
[Windows 10 Host]                          [VM Kali Linux]
   ├── Splunk Enterprise                      ├── Splunk Universal Forwarder
   │      (Indexeur + Search Head)            │      └── Collecte : auth.log, syslog
   │      Port de réception : 9997 (TCP)      │
   │                                          └── Hydra (génération de trafic d'attaque)
   └── Splunk Universal Forwarder
          └── Collecte : Windows Event Logs
              (Security, System, Application)

Flux : Kali (Hydra) --[RDP brute force]--> Windows (cible)
       Windows Event Log (4625) --> UF Windows --> Indexeur Splunk
       Kali auth.log/syslog --> UF Kali --> Indexeur Splunk (port 9997)
```

## ⚙️ Configuration

### Forwarder → Indexeur
- Connexion TCP configurée via `outputs.conf`
- Vérification de la connexion active :
```powershell
splunk list forward-server -auth admin:<password>
```

### Sources de données collectées
Voir [`configs/inputs.conf`](configs/inputs.conf) — collecte des journaux d'événements Windows :
- `WinEventLog://Security`
- `WinEventLog://System`
- `WinEventLog://Application`

## 🐛 Problèmes rencontrés et résolutions

| Problème | Cause | Solution |
|---|---|---|
| `index=main` vide malgré connexion forwarder active | Aucune source de données réelle configurée, seulement les logs internes du forwarder envoyés vers `_internal` | Ajout de stanzas `WinEventLog` dans `inputs.conf` + redémarrage du service |
| Doute sur l'IP du receiver (127.0.0.1 vs IP machine) | Forwarder et indexeur sur la même machine → équivalent fonctionnel | Validé via `splunk list forward-server` (statut "Active") |
| Logs Kali absents malgré forward-server "Active" | Utilisateur `splunkfwd` (least-privileged) sans permission de lecture sur `/var/log/auth.log` | Ajout de `splunkfwd` au groupe `adm` (`usermod -aG adm splunkfwd`) + redémarrage |
| Hydra : "account not active for remote desktop" | Mauvais nom de compte (`admin` au lieu du compte réel `lenovo`) + compte non membre du groupe Bureau à distance | Identification du compte réel via `net user`, ajout au groupe local (nom localisé en FR : "Utilisateurs du Bureau à distance") |
| Hydra bloqué malgré bon compte/groupe | NLA (Network Level Authentication) empêchait la négociation d'atteindre l'étape de vérification du mot de passe | Désactivation temporaire du NLA (`UserAuthentication = 0` dans le registre) + redémarrage machine, puis réactivation après le test |
| Timestamps des événements ne correspondaient pas à l'attaque en cours | Anciens événements de tests précédents affichés par défaut | Filtrage avec `earliest=-30m` pour isoler les événements récents |
| Lien de téléchargement Universal Forwarder en 404 | Placeholder `<VERSION>` non remplacé par le numéro de version + hash de build réel | Récupération du lien exact depuis la page officielle Splunk (génère un wget avec hash unique par build) |
| Sysmon installé mais aucun event récent dans `Get-WinEvent` | Service Sysmon64 arrêté (`State=Stopped`) après une instabilité | `Start-Service Sysmon64` |
| Sysmon tourne, génère des events Windows, mais rien dans `index=main` | Forwarder jamais redémarré depuis l'ajout de la stanza `WinEventLog://Microsoft-Windows-Sysmon/Operational` dans `inputs.conf` | Redémarrage complet du service forwarder (`splunk restart`) |
| Recherche `EventCode=1` sur Sysmon ne renvoie rien | Sourcetype Sysmon (`XmlWinEventLog`) n'extrait pas `EventCode`/`CommandLine` automatiquement sans Technology Add-on | Extraction manuelle via `rex` sur le XML brut, ou installation du Splunk Add-on for Sysmon |
| Recherche `Image="*powershell*"` noyée de résultats non pertinents | Process internes Splunk (`splunk-powershell.exe`) très fréquents (~7s) matchent aussi le filtre | Filtrage plus précis sur le contenu de `CommandLine` (ex: `*EncodedCommand*`) plutôt que sur `Image` seul |

## 🔍 Recherches SPL utiles

Voir le dossier [`searches/`](searches/) pour les requêtes documentées, notamment :
- Détection de tentatives de connexion échouées répétées (EventCode 4625)
- Suivi des créations de comptes (EventCode 4720)
- Suivi des créations de process (EventCode 4688)

## 🎯 Démo : Détection d'une attaque brute force RDP

Scénario complet de bout en bout démontrant la chaîne attaque → log → détection.

### Attaque (depuis Kali)
```bash
hydra -l lenovo -P /tmp/test-passwords.txt -t 1 -W 3 rdp://<IP_WINDOWS>
```

### Détection (Splunk Web)
```spl
index=main EventCode=4625
| stats count by Account_Name, src_ip
| where count > 3
```

### Preuve forensique observée
Événement `EventCode=4625` capturé avec :
- **Compte ciblé** : `lenovo`
- **Station de travail source** : `kali`
- **Adresse IP source** : `192.168.1.77`
- **Type d'ouverture de session** : 3 (réseau)
- **Package d'authentification** : NTLM
- **Raison de l'échec** : Nom d'utilisateur inconnu ou mot de passe incorrect (0xC000006D)

### Mapping MITRE ATT&CK
| Technique | ID | Description |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | Tentatives répétées de mots de passe via Hydra |
| Remote Services: RDP | T1021.001 | Vecteur d'accès distant ciblé |

📸 Voir [`screenshots/search-4625-bruteforce.png`](screenshots/search-4625-bruteforce.png)

## 🎯 Démo : Détection d'un scan Nmap

### Attaque (depuis Kali)
```bash
nmap -sS -T4 -p- 192.168.1.77
```
*Prérequis : activer `auditpol /set /subcategory:"Connexion de la plateforme de filtrage" /success:enable /failure:enable` sur Windows*

### Détection (Splunk Web)
```spl
index=main (EventCode=5156 OR EventCode=5157) earliest=-15m
| stats dc(Port_de_destination) as ports_scanned count by Adresse_source
| where ports_scanned > 20
```

### Résultat observé
| Adresse_source | ports_scanned | count |
|---|---|---|
| 192.168.1.77 | 45 573 | 78 367 |

### Mapping MITRE ATT&CK
| Technique | ID | Description |
|---|---|---|
| Network Service Scanning | T1046 | Scan de reconnaissance complet des ports TCP |

📸 Voir [`screenshots/search-nmap-scan.png`](screenshots/search-nmap-scan.png)

## 🎯 Démo : Détection d'une commande PowerShell encodée (Sysmon)

### Installation de Sysmon
```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Sysmon.zip"
Expand-Archive -Path "C:\Sysmon.zip" -DestinationPath "C:\Sysmon"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Sysmon\sysmonconfig-export.xml"
cd C:\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

### Attaque simulée
```powershell
$cmd = 'Write-Host "Test Sysmon detection"; Get-Process | Select-Object -First 3'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -EncodedCommand $encoded
```

### Détection (Splunk Web)
```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=-20m
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]*)"
| search EventID=1 CommandLine="*EncodedCommand*"
| table _time, Image, CommandLine
```

### Résultat observé
Commande capturée : `powershell.exe -EncodedCommand <Base64>` — technique d'évasion classique détectée malgré l'obfuscation.

### Mapping MITRE ATT&CK
| Technique | ID | Description |
|---|---|---|
| Command and Scripting Interpreter: PowerShell | T1059.001 | Exécution de code via PowerShell |
| Obfuscated Files or Information | T1027 | Commande encodée en Base64 pour échapper à la détection naïve |

📸 Voir [`screenshots/search-powershell-encoded.png`](screenshots/search-powershell-encoded.png)

## 📸 Captures d'écran

Voir [`screenshots/`](screenshots/) pour les captures de configuration et de dashboards.

## 🛠️ Stack technique
- Splunk Enterprise (Free tier, <500MB/jour)
- Splunk Universal Forwarder (Windows + Linux)
- Sysmon (v15.21) avec configuration SwiftOnSecurity
- Windows 10/11 natif (cible + indexeur)
- VM Kali Linux (forwarder + outils d'attaque)
- Hydra (simulation brute force RDP), Nmap (scan de reconnaissance)

## 📚 Liens utiles
- [Documentation officielle Splunk](https://docs.splunk.com)
- [MITRE ATT&CK](https://attack.mitre.org)

---
*Projet personnel*
