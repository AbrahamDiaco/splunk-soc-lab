# Splunk SOC Home Lab

Documentation d'un lab SIEM Splunk monté en local (Windows natif, ressources limitées) dans le cadre de ma préparation à un rôle SOC Analyst / GRC.

## 🎯 Objectif du lab

Mettre en place une chaîne complète de collecte et d'analyse de logs avec Splunk : Universal Forwarder → Indexeur → Recherches SPL → Dashboards de détection, en environnement contraint (RAM limitée, machine unique).

## 🏗️ Architecture

```
[Windows Host]
   ├── Splunk Universal Forwarder
   │      └── Collecte : Windows Event Logs (Security, System, Application)
   │
   └── Splunk Enterprise (Indexeur + Search Head)
          └── Port de réception : 9997 (TCP)
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

## 🔍 Recherches SPL utiles

Voir le dossier [`searches/`](searches/) pour les requêtes documentées, notamment :
- Détection de tentatives de connexion échouées répétées (EventCode 4625)
- Suivi des créations de comptes (EventCode 4720)
- Suivi des créations de process (EventCode 4688)

## 📸 Captures d'écran

Voir [`screenshots/`](screenshots/) pour les captures de configuration et de dashboards.

## 🛠️ Stack technique
- Splunk Enterprise (Free tier, <500MB/jour)
- Splunk Universal Forwarder
- Windows 10/11 natif

## 📚 Liens utiles
- [Documentation officielle Splunk](https://docs.splunk.com)
- [MITRE ATT&CK](https://attack.mitre.org)

---
*Projet personnel dans le cadre de ma préparation aux certifications SOC Analyst (TryHackMe SOC Level 1, Splunk Core Power User, CySA+).*
