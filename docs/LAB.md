# Lab : rejouer l'attaque ProManager et la détecter

> **Avertissement.** ProManager chiffre réellement des fichiers. On ne l'exécute
> **que** dans une VM jetable, isolée, avec un snapshot pris avant l'attaque.
> Jamais sur un poste personnel, jamais sur un réseau partagé.
>
> Pour voir les alertes **sans** exécuter de malware, utilisez `./demo.sh`
> (simulation avec des octets aléatoires dans un dossier temporaire).

## 0. Architecture du lab

```
+------------------------- VM Linux isolée (réseau host-only) --------------------------+
|                                                                                        |
|  Terminal 1 : ransomwatch.py  --- surveille --->  /opt/lab/ProManager/TP/              |
|  Terminal 2 : serveur_pardon (écoute TCP 4242)          |-- Projet/   (cibles)          |
|  Terminal 3 : ransomware -d 30  ----- chiffre --------->|-- Projet_temp.zip            |
|                   |                                                                    |
|                   +--- clé+IV sur 127.0.0.1:4242 ---> serveur_pardon                   |
|                                 ^                                                      |
|  auditd (règles RansomWatch)    |   Suricata / tcpdump sur l'interface "lo"            |
+----------------------------------------------------------------------------------------+
```

## 1. Préparer la VM

1. Créer une VM Ubuntu Server 24.04 (VirtualBox, VMware ou KVM), 2 vCPU, 2 Go de RAM.
2. Pendant l'installation, garder un accès réseau (NAT) pour récupérer les paquets :
   ```bash
   sudo apt update
   sudo apt install -y build-essential pkg-config libssl-dev libzip-dev libgtk-3-dev \
                       auditd python3 tcpdump suricata
   ```
3. Copier les deux dépôts dans la VM :
   ```bash
   sudo mkdir -p /opt/lab && sudo chown "$USER" /opt/lab
   git clone https://github.com/MamadouPapa/ProManager-Ransomware /opt/lab/ProManager
   git clone <url-de-RansomWatch> /opt/lab/RansomWatch
   ```
4. Compiler ProManager en suivant le README de son dépôt (`make`).
5. **Isoler la VM** : passer la carte réseau en *host-only* (ou la déconnecter).
   ProManager ne parle qu'à `127.0.0.1`, il n'a pas besoin de réseau externe.
6. **Prendre un snapshot** nommé `pre-attack`. C'est votre PRA du lab.

## 2. Activer la télémétrie

### auditd

```bash
cd /opt/lab/RansomWatch
# Adapter le chemin si le dépôt n'est pas dans /opt/lab/ProManager
sudo cp auditd/ransomwatch.rules /etc/audit/rules.d/50-ransomwatch.rules
sudo augenrules --load
sudo auditctl -l | grep -E 'rw_|net_connect'
```

### Capture réseau (Suricata et/ou tcpdump) sur la boucle locale

ProManager envoie sa clé à `127.0.0.1:4242` : seule l'interface `lo` voit ce trafic.

```bash
# Terminal 4 : IDS (-k none : pas de vérification des checksums sur lo)
sudo suricata -i lo -k none -S /opt/lab/RansomWatch/network/ransomwatch.rules -l /tmp/suri
# Terminal 5 : preuve brute (la clé passe en clair)
sudo tcpdump -i lo -w /tmp/promanager-4242.pcap 'tcp port 4242'
```

## 3. Préparer la cible et démarrer le détecteur

ProManager utilise des chemins relatifs (`TP/Projet`) : on travaille depuis la racine
de son dépôt.

```bash
cd /opt/lab/ProManager
mkdir -p TP/Projet
# Fichiers de test >= 1 Kio pour que la règle d'entropie RW-002 s'applique
for i in $(seq 1 8); do
  for ext in txt md c; do
    yes "Donnees de test du lab RansomWatch, fichier $i" | head -c 4096 > "TP/Projet/doc_$i.$ext"
  done
done
```

Terminal 1, détecteur (le dossier surveillé est `TP/` pour voir aussi le `.zip`) :

```bash
python3 /opt/lab/RansomWatch/detector/ransomwatch.py TP \
    --interval 0.5 \
    --burst-threshold 10 --burst-window 10 \
    --archive-delete-threshold 3 --swap-threshold 3 \
    --output /var/tmp/rw-alerts.jsonl \
    --respond --incident-file /var/tmp/rw-incident.jsonl
```

Les fichiers de sortie sont **hors** de l'arbre surveillé. Les seuils sont abaissés
parce que le dossier du lab ne contient que quelques dizaines de fichiers ; sur un vrai
partage, gardez les valeurs par défaut et ajustez-les après une semaine de baseline.

## 4. Lancer l'attaque

```bash
# Terminal 2
cd /opt/lab/ProManager && ./TP/serveur_pardon
# Terminal 3 : 30 s après la création de TP/Projet, le chiffrement démarre
cd /opt/lab/ProManager && ./TP/ransomware -d 30
```

## 5. Observer

| Source | Commande | Ce qu'on doit voir |
|---|---|---|
| Détecteur | Terminal 1, ou `jq . /var/tmp/rw-alerts.jsonl` | RW-004, RW-002 (un par fichier >= 1 Kio), RW-005, RW-001, RW-003 |
| Réponse | `jq . /var/tmp/rw-incident.jsonl` | l'alerte, les PID suspects trouvés via `/proc` (au mieux) |
| auditd, fichiers | `sudo ausearch -k rw_protected_write -i \| grep -i 'RAN.*ON'` | création de `RANÇON.txt` par `comm="ransomware"` |
| auditd, suppressions | `sudo ausearch -k rw_delete -i --summary` | rafale d'`unlinkat` par le même PID |
| auditd, réseau | `sudo ausearch -k net_connect -i \| grep -B4 'lport=4242'` | `saddr={ saddr_fam=inet laddr=127.0.0.1 lport=4242 }` |
| Suricata | `cat /tmp/suri/fast.log` | SID 10424201, puis 10424202 ou 10424204 |
| pcap | `tcpdump -r /tmp/promanager-4242.pcap -X` | les 32 octets de clé puis les 16 octets d'IV, en clair |

Variante (lab uniquement) : relancer le scénario avec `--respond --suspend` pour
envoyer SIGSTOP au processus suspect. Le processus reste en mémoire avec sa clé
(utile pour un dump avec `gcore <pid>`). `--kill` (SIGKILL) existe aussi mais détruit
cette preuve. **Aucune de ces options n'est active par défaut.**

## 6. Restaurer

1. Arrêter le détecteur (Ctrl+C), Suricata et tcpdump ; copier les preuves hors de la
   VM si besoin (`rw-alerts.jsonl`, `rw-incident.jsonl`, pcap, `ausearch --raw`).
2. Optionnel : tester la récupération prévue par le TP (`./TP/client_decrypt`).
3. **Revenir au snapshot `pre-attack`.** C'est la seule restauration fiable : on ne
   « nettoie » pas une machine compromise, on la restaure.

---

## Leçons pour la défense

1. **Sauvegardes hors ligne et PRA testé.** La règle 3-2-1-1-0 : 3 copies, 2 supports,
   1 hors site, 1 hors ligne ou immuable, 0 erreur à la restauration. Le snapshot du
   lab joue ce rôle ; en production, un PRA qui n'a jamais été testé n'existe pas.
   Ici, ProManager n'efface aucune sauvegarde : une copie hors ligne suffit.
2. **EDR et détection comportementale.** ProManager n'a aucune signature connue :
   ce sont ses comportements (archive, rafale d'écritures, entropie, note,
   connexion sortante) qui le trahissent. Un EDR fait la même chose avec une
   visibilité noyau (eBPF, fanotify), une attribution fiable des PID et la
   possibilité d'isoler l'hôte.
3. **Moindre privilège.** Le binaire chiffre tout ce que l'utilisateur peut écrire,
   rien de plus. Comptes séparés, partages en lecture seule par défaut, pas de
   compte administrateur au quotidien, `noexec` sur `/tmp` et les répertoires
   personnels quand c'est possible.
4. **Filtrage des flux sortants (egress).** Une liste blanche de flux sortants
   (pare-feu hôte et périmétrique) aurait bloqué l'envoi de la clé vers un port
   inhabituel comme 4242. Sans clé chez l'attaquant, pas de chantage possible.
   Corollaire : journaliser les connexions sortantes refusées, c'est une alerte gratuite.
5. **Capture réseau et réponse à incident.** La clé de ProManager passe en clair :
   un pcap pris pendant l'attaque permet de déchiffrer. Suspendre plutôt que tuer
   (SIGSTOP) garde la clé en mémoire. Réfléchir à la préservation des preuves
   *avant* de contenir.
6. **Detection as code.** Règles Sigma, auditd et Suricata versionnées, testées
   (`tests/test_rule_files.py`) et reliées à ATT&CK : on sait ce qu'on couvre et,
   surtout, ce qu'on ne couvre pas (voir les lacunes dans `ATTACK-MAPPING.md`).
