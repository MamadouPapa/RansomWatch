# Cartographie MITRE ATT&CK : ProManager vers RansomWatch

Ce tableau part du **code réel** de ProManager (`TP/ransomware.c`, `TP/serveur_pardon.c`)
et associe chaque comportement à une technique ATT&CK (Enterprise, Linux), puis à la
détection RansomWatch qui le couvre.

Légende des colonnes de couverture :
- **Détecteur** : règles `RW-00x` de `detector/ransomwatch.py`
- **Sigma** : fichiers de `rules/sigma/`
- **auditd** : clés (`-k`) de `auditd/ransomwatch.rules`
- **Réseau** : SID Suricata de `network/ransomwatch.rules`

## Tableau principal

| # | Comportement observé dans le code | Technique ATT&CK | Détecteur | Sigma | auditd | Réseau |
|---|---|---|---|---|---|---|
| 1 | Lancement manuel de `./TP/ransomware` par l'utilisateur | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) User Execution: Malicious File | (aucune) | (aucune) | `rw_exec` | (aucune) |
| 2 | `opendir("TP/Projet")` + `sleep(5)` en boucle, puis `readdir()` et filtrage par extension (`.txt .md .c .h .cpp .hpp`) | [T1083](https://attack.mitre.org/techniques/T1083/) File and Directory Discovery | (aucune, voir lacunes) | (aucune) | `rw_protected_write` uniquement si on ajoute `r` (lecture) à la règle `-w` | (aucune) |
| 3 | `compress_directory()` : libzip crée `TP/Projet_temp.zip` à partir des fichiers de `TP/Projet` | [T1560.002](https://attack.mitre.org/techniques/T1560/002/) Archive Collected Data: Archive via Library | **RW-004** (archive, puis suppressions dans le même arbre) | `file_event_lnx_archive_then_mass_writes.yml` (règle de base 1 et corrélation 4) | `rw_tp_write` | (aucune) |
| 4 | `encrypt_file()` : AES-256-CBC (OpenSSL), écrit `<fichier>.enc` | [T1486](https://attack.mitre.org/techniques/T1486/) Data Encrypted for Impact | **RW-001** (rafale), **RW-002** (entropie > 7,5 bits/octet par rapport à la baseline) | `file_event_lnx_archive_then_mass_writes.yml` (règles 2 et 3) | `rw_protected_write` | (aucune) |
| 5 | `remove(path)` juste après l'écriture du `.enc` (l'original est remplacé) | [T1486](https://attack.mitre.org/techniques/T1486/) Data Encrypted for Impact | **RW-005** (`X` supprimé et `X.enc` créé), **RW-004** | corrélation 4 | `rw_delete` (unlink/unlinkat) | (aucune) |
| 6 | `create_ransom_note()` : dépôt de `TP/Projet/RANÇON.txt` | [T1486](https://attack.mitre.org/techniques/T1486/) (la note fait partie de l'impact d'un rançongiciel) | **RW-003** | `file_event_lnx_ransom_note_creation.yml`, `auditd_lnx_ransom_note_creation.yml` | `rw_protected_write` (PATH `nametype=CREATE`) | (aucune) |
| 7 | `send_key_to_server()` : `connect(127.0.0.1:4242)` puis `write(key, 32)` et `write(iv, 16)` | [T1041](https://attack.mitre.org/techniques/T1041/) Exfiltration Over C2 Channel | (hors périmètre fichiers) | `network_connection_lnx_tcp_4242_non_allowlisted.yml` | `net_connect` (puis filtrage `lport=4242` avec `ausearch -i`) | `10424202` (48 octets), `10424203`/`10424204` (32 puis 16 octets) |
| 8 | Protocole « maison » sur TCP brut, sans couche applicative (pas de HTTP/DNS) | [T1095](https://attack.mitre.org/techniques/T1095/) Non-Application Layer Protocol | (aucune) | `network_connection_lnx_tcp_4242_non_allowlisted.yml` | `net_connect` | `10424201` (session TCP/4242) |
| 9 | `serveur_pardon` restitue la clé au client après les « excuses » | [T1095](https://attack.mitre.org/techniques/T1095/) (même canal) | (aucune) | (aucune) | (aucune) | `10424205` (bannière « Vos excuses sont accept... ») |

### Pourquoi T1095 et non T1071

T1071 (Application Layer Protocol) concerne un C2 caché dans un protocole applicatif
standard (HTTP, DNS, SMTP...). ProManager ouvre une socket `SOCK_STREAM` et écrit
directement 48 octets binaires : il n'y a aucun protocole applicatif. La bonne
technique est donc **T1095 Non-Application Layer Protocol**.

### Techniques volontairement non retenues

| Candidat | Pourquoi il est écarté |
|---|---|
| T1485 Data Destruction | Les originaux sont supprimés, mais les données restent récupérables avec la clé : c'est du chiffrement pour impact (T1486), pas de la destruction. |
| T1497.003 Time Based Evasion | Le délai de 30 s / 3600 s (calculé depuis le `st_ctime` de `TP/Projet`) peut contourner une sandbox à durée limitée, mais dans le code c'est un déclencheur pédagogique, pas une évasion explicite. Je le signale sans le cartographier. |
| T1071 Application Layer Protocol | Voir ci-dessus : TCP brut, donc T1095. |
| T1490 Inhibit System Recovery | ProManager ne touche ni aux sauvegardes ni aux snapshots. |

## Indicateurs propres à ProManager (IOC hôte et réseau)

| Type | Valeur | Source dans le code |
|---|---|---|
| Fichier | `TP/Projet/RANÇON.txt` | `#define RANSOM_FILE` |
| Fichier | `TP/Projet_temp.zip` | `compress_directory()` |
| Fichier | `TP/ransomware.log`, `TP/server.log` | `#define LOG_FILE` |
| Extension | `.enc` ajoutée au nom d'origine | `encrypt_file()` |
| Réseau | TCP `127.0.0.1:4242`, 32 octets (clé) + 16 octets (IV), en clair | `send_key_to_server()` |
| Chaîne | `Vos fichiers ont été chiffrés par ProManager.` | `create_ransom_note()` |

## Observations d'analyste (utiles à la défense)

- **La clé transite en clair** sur TCP/4242. Une capture (`tcpdump -i lo port 4242`)
  pendant l'attaque suffit à récupérer clé et IV, donc à déchiffrer sans « payer ».
  C'est la meilleure démonstration de l'intérêt de la capture réseau en réponse à incident.
- **La clé reste en mémoire** du processus jusqu'à sa fin : suspendre le processus
  (`--suspend`, SIGSTOP) plutôt que le tuer préserve cette preuve pour un dump mémoire.
- **Le filtrage par extension utilise `strstr()`** : `notes.txt.enc` contient `.txt`.
  Selon l'ordre de `readdir()`, un fichier déjà chiffré peut être rechiffré
  (`.enc.enc`). Pour le défenseur, cela produit encore plus d'écritures (RW-001, RW-005).
- **Destination codée en dur sur la boucle locale** : une sonde IDS sur le réseau ne
  voit rien. Il faut écouter sur l'interface `lo` de la VM (voir `LAB.md`).

## Lacunes connues

- **T1083** : un détecteur par sondage (`stat`) ne voit pas les lectures. Il faudrait
  auditd en `-p r` (volumineux), fanotify ou un EDR.
- **RW-002** ignore les fichiers de moins de 1 Kio (`--entropy-min-size`) : sur un
  très petit échantillon l'entropie ne peut pas approcher 8 bits/octet. Les petits
  fichiers chiffrés restent couverts par RW-005 et RW-001.
- **Attribution du PID** (`--respond`) : au mieux, via `/proc/<pid>/fd` et `cwd`,
  donc sujette aux courses (le fichier peut déjà être fermé).
