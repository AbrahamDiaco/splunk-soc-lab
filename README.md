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

## 📸 Captures d'écran

Voir [`screenshots/`](screenshots/) pour les captures de configuration et de dashboards.

## 🛠️ Stack technique
- Splunk Enterprise (Free tier, <500MB/jour)
- Splunk Universal Forwarder (Windows + Linux)
- Windows 10/11 natif (cible + indexeur)
- VM Kali Linux (forwarder + outils d'attaque)
- Hydra (simulation brute force RDP)

## 📚 Liens utiles
- [Documentation officielle Splunk](https://docs.splunk.com)
- [MITRE ATT&CK](https://attack.mitre.org)

---
*Projet personnel dans le cadre de ma préparation aux certifications SOC Analyst (TryHackMe SOC Level 1, Splunk Core Power User, CySA+).*
