# RansomWatch

**Lab blue team : détection comportementale du rançongiciel pédagogique ProManager.**

> J'ai écrit l'attaque, puis la détection.

En TP de cybersécurité, j'ai développé [ProManager](https://github.com/MamadouPapa/ProManager-Ransomware),
un rançongiciel pédagogique en C (Linux, OpenSSL AES-256-CBC, libzip, exfiltration de
la clé sur TCP/4242). RansomWatch est son pendant défensif : je repars du code réel
de l'attaque pour construire, tester et documenter les détections qui l'auraient
arrêtée, au niveau hôte comme au niveau réseau.

## Ce que contient le projet

| Dossier | Contenu |
|---|---|
| `detector/` | `ransomwatch.py` : détecteur comportemental en Python 3, **bibliothèque standard uniquement** (aucune dépendance pip). Sondage de l'arborescence, 5 règles, alertes JSON Lines, mode `--respond` sans danger par défaut. `simulate.py` : simulation inoffensive. |
| `tests/` | 49 tests `unittest` (entropie, fenêtre glissante, notes de rançon, règles, bout en bout, réponse, validation des fichiers de règles). |
| `rules/sigma/` | Règles Sigma : création de note de rançon (`file_event` et `auditd`), connexion TCP/4242 depuis un processus hors liste blanche, archive puis écritures massives (règles de corrélation Sigma). |
| `auditd/` | `ransomwatch.rules` : surveillance du dossier protégé, suppressions, `connect()`, exécutions. |
| `network/` | `ransomwatch.rules` : règles Suricata (syntaxe compatible Snort) pour l'exfiltration de la clé (32 + 16 octets). |
| `docs/` | [`ATTACK-MAPPING.md`](docs/ATTACK-MAPPING.md) (comportements vers ATT&CK vers détections), [`LAB.md`](docs/LAB.md) (scénario complet en VM isolée et leçons pour la défense). |

## Architecture

```
            ProManager (attaque)                          RansomWatch (défense)
 ------------------------------------------    -----------------------------------------------
 sondage de TP/Projet (opendir + sleep)    ->  auditd rw_protected_write (lecture en option)
 libzip -> TP/Projet_temp.zip              ->  RW-004  archive puis suppressions   | Sigma 1+4
 AES-256-CBC -> fichier.enc, remove()      ->  RW-001  rafale d'écritures          | Sigma 2+3
                                               RW-002  entropie > 7,5 bits/octet   | auditd rw_delete
                                               RW-005  X supprimé, X.enc créé      |
 RANÇON.txt                                ->  RW-003  nom de note de rançon       | Sigma note (x2)
 clé+IV -> 127.0.0.1:4242 (TCP brut)       ->  Suricata 10424201..05 | Sigma TCP/4242 | auditd net_connect
```

Fonctionnement du détecteur :

```
 take_snapshot()  --diff-->  FileChange(created|modified|deleted)  -->  DetectionEngine
  (os.walk + stat)                                                        |-- RansomNoteRule      RW-003
                                                                          |-- ArchiveThenDelete   RW-004
                                                                          |-- ExtensionSwapRule   RW-005
                                                                          |-- BurstRule           RW-001
                                                                          |-- EntropyRule         RW-002
                                                                          v
                                                    alertes JSON -> stdout, --output, --respond
```

| Règle | Gravité | Technique ATT&CK | Déclencheur (valeurs par défaut) |
|---|---|---|---|
| RW-001 | high | T1486 | >= 20 créations/modifications en 10 s |
| RW-002 | high | T1486 | fichier >= 1 Kio écrit avec entropie >= 7,5 bits/octet et +1,0 par rapport à sa baseline |
| RW-003 | critical | T1486 | nom de type `RANÇON.txt`, `*RANSOM*`, `*DECRYPT*`, `HOW_TO_RECOVER`, `!README!`, `_readme.txt`... |
| RW-004 | high | T1560.002 | archive créée puis >= 5 suppressions sous son dossier en 30 s |
| RW-005 | critical | T1486 | >= 3 fichiers `X` supprimés pendant que `X.<ext>` est créé, en 30 s |

## Démarrage rapide

Prérequis : Python 3.8 ou plus récent. Rien à installer.

```bash
# 1. Simulation inoffensive : octets aléatoires dans un dossier temporaire,
#    aucun vrai malware, aucune connexion réseau.
./demo.sh                      # ou : python3 detector/simulate.py

# 2. Tests
python3 -m unittest discover -s tests -v

# 3. Surveiller un dossier
python3 detector/ransomwatch.py /chemin/a/surveiller --output alertes.jsonl

# Seuils ajustables, par exemple :
python3 detector/ransomwatch.py /srv/partage --burst-threshold 50 --burst-window 30 \
        --entropy-threshold 7.6 --interval 2

# Réponse : écrit un fichier d'incident et affiche les PID suspects (Linux, via /proc).
# Aucun signal n'est envoyé par défaut.
python3 detector/ransomwatch.py /srv/partage --respond --incident-file /var/tmp/incident.jsonl
```

`--suspend` (SIGSTOP) et `--kill` (SIGKILL) existent mais sont **désactivés par défaut,
réservés au lab** et exigent `--respond`. L'attribution d'un PID via `/proc/<pid>/fd`
est approximative : en production, la décision de confinement revient à l'EDR ou à
l'analyste. `--suspend` est préférable : le processus garde la clé AES en mémoire.

Pour rejouer la vraie attaque, suivez [`docs/LAB.md`](docs/LAB.md) (VM isolée,
snapshot, réseau host-only).

## Exemple de sortie

Sortie réelle de `./demo.sh` (25 fichiers simulés). Le préfixe du dossier temporaire
macOS a été raccourci en `/tmp/ransomwatch-sim-XXXX` pour la lisibilité :

```
=== RansomWatch simulation summary ===
  RW-001: 1 alert(s)
  RW-002: 25 alert(s)
  RW-003: 1 alert(s)
  RW-004: 1 alert(s)
  RW-005: 1 alert(s)
  total: 29
```

```json
{"timestamp": "2026-11-16T10:00:51.825+00:00", "rule_id": "RW-002", "rule_name": "High-entropy content written", "severity": "high", "mitre": {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact"}, "details": {"path": "/tmp/ransomwatch-sim-XXXX/TP/Projet/fichier_00.txt.enc", "change": "created", "entropy_bits_per_byte": 7.952, "baseline_bits_per_byte": 4.136, "threshold": 7.5}}
{"timestamp": "2026-11-16T10:00:51.839+00:00", "rule_id": "RW-005", "rule_name": "Originals replaced by renamed copies", "severity": "critical", "mitre": {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact"}, "details": {"swaps_in_window": 3, "window_seconds": 30.0, "new_extensions": [".enc"], "last_original": "/tmp/ransomwatch-sim-XXXX/TP/Projet/fichier_02.c"}}
{"timestamp": "2026-11-16T10:00:51.839+00:00", "rule_id": "RW-004", "rule_name": "Archive created then originals deleted", "severity": "high", "mitre": {"technique_id": "T1560.002", "technique_name": "Archive Collected Data: Archive via Library"}, "details": {"archive": "/tmp/ransomwatch-sim-XXXX/TP/Projet_temp.zip", "deletions_after_archive": 5, "window_seconds": 30.0, "last_deleted": "/tmp/ransomwatch-sim-XXXX/TP/Projet/fichier_04.cpp"}}
{"timestamp": "2026-11-16T10:00:52.045+00:00", "rule_id": "RW-003", "rule_name": "Ransom note filename", "severity": "critical", "mitre": {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact"}, "details": {"path": "/tmp/ransomwatch-sim-XXXX/TP/Projet/RANÇON.txt", "pattern": "rancon"}}
{"timestamp": "2026-11-16T10:00:52.045+00:00", "rule_id": "RW-001", "rule_name": "File write burst", "severity": "high", "mitre": {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact"}, "details": {"events_in_window": 20, "window_seconds": 10.0, "threshold": 20, "sample_paths": ["/tmp/ransomwatch-sim-XXXX/TP/Projet/fichier_14.c.enc", "/tmp/ransomwatch-sim-XXXX/TP/Projet/fichier_15.h.enc", "/tmp/ransomwatch-sim-XXXX/TP/Projet_temp.zip", "/tmp/ransomwatch-sim-XXXX/TP/Projet/RANÇON.txt", "/tmp/ransomwatch-sim-XXXX/TP/Projet/fichier_16.cpp.enc"]}}
```

Résultat des tests :

```
Ran 49 tests in 0.561s

OK (skipped=1)
```

Le test ignoré est l'analyse YAML complète, qui ne s'exécute que si PyYAML est
installé (optionnel). Avec PyYAML, les 49 tests passent sans exception ; sans PyYAML,
des contrôles structurels en bibliothèque standard vérifient quand même chaque règle
Sigma (champs obligatoires, UUID, date, tags `attack.tXXXX`).

## Choix techniques

- **Sondage plutôt qu'inotify** : la même primitive que l'attaque (`opendir` + `sleep`),
  portable Linux et macOS, sans dépendance. Contrepartie : un fichier créé puis
  supprimé entre deux passages n'est pas vu, et les lectures sont invisibles.
- **Entropie par rapport à une baseline** : la baseline est calculée au démarrage pour
  chaque fichier ; un `X.enc` est comparé à l'entropie de `X`. Les formats déjà
  compressés (`.zip`, `.jpg`, `.pdf`...) sont exclus pour limiter les faux positifs.
- **Aucun nombre magique** : tous les seuils sont dans `detector/constants.py` et
  modifiables en ligne de commande.
- **Tests sans le vrai malware** : le bout en bout écrit des fichiers `os.urandom()`
  dans un dossier temporaire ; ProManager n'est jamais compilé ni exécuté par les tests.

## Limites

- RW-002 ignore les fichiers de moins de 1 Kio (entropie peu significative sur un
  petit échantillon) ; RW-001 et RW-005 couvrent ce cas.
- L'attribution des PID en mode `--respond` est opportuniste (`/proc`, Linux uniquement).
- Les règles Suricata et auditd suivent la syntaxe documentée mais n'ont pas été
  chargées dans un moteur réel lors de la rédaction : validez avec `suricata -T` et
  `auditctl -R` dans la VM du lab.
- Les règles Sigma de corrélation (`correlation:`) demandent un backend compatible
  Sigma 2.x. Les dates suivent le format `2026/11/16` ; la spécification actuelle
  recommande `2026-11-16`.

## Liens

- Attaque : [MamadouPapa/ProManager-Ransomware](https://github.com/MamadouPapa/ProManager-Ransomware)
- MITRE ATT&CK : [T1486](https://attack.mitre.org/techniques/T1486/),
  [T1560.002](https://attack.mitre.org/techniques/T1560/002/),
  [T1041](https://attack.mitre.org/techniques/T1041/),
  [T1095](https://attack.mitre.org/techniques/T1095/),
  [T1083](https://attack.mitre.org/techniques/T1083/)

## Licence

MIT, voir [LICENSE](LICENSE). Projet éducatif : n'exécutez ProManager que dans un
environnement isolé dont vous êtes propriétaire.

Auteur : Papa Mamadou Gueye
