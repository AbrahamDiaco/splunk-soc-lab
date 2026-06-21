# Recherches SPL — Détection

## 1. Tentatives de connexion échouées répétées (Brute Force)

```spl
index=main EventCode=4625
| stats count by Account_Name, src_ip
| where count > 5
| sort -count
```
**Objectif** : Identifier les comptes/IP avec plusieurs échecs d'authentification, signe potentiel de brute force.
**Référence MITRE ATT&CK** : T1110 (Brute Force)

---

## 2. Création de nouveaux comptes utilisateurs

```spl
index=main EventCode=4720
| table _time, Account_Name, Caller_User_Name
```
**Objectif** : Surveiller la création de comptes, potentiellement liée à de la persistance après compromission.
**Référence MITRE ATT&CK** : T1136 (Create Account)

---

## 3. Création de processus suspects

```spl
index=main EventCode=4688
| table _time, New_Process_Name, Creator_Process_Name, Account_Name
| sort -_time
```
**Objectif** : Suivre les processus lancés sur le système pour repérer des exécutions anormales (ex : PowerShell encodé, outils LOLBins).
**Référence MITRE ATT&CK** : T1059 (Command and Scripting Interpreter)
