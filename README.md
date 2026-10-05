# sbmgr

[![CI](https://github.com/fjacquet/secure-import/actions/workflows/ci.yml/badge.svg)](https://github.com/fjacquet/secure-import/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go&logoColor=white)
![Licence](https://img.shields.io/badge/licence-MIT-green)
![Statut](https://img.shields.io/badge/statut-alpha-orange)
![Dépendances](https://img.shields.io/badge/dépendances-stdlib%20seule-brightgreen)
![Binaire](https://img.shields.io/badge/binaire-unique%2C%20sans%20runtime-blue)
![OS](https://img.shields.io/badge/OS-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![Redfish](https://img.shields.io/badge/Redfish-DMTF%20DSP0266%201.14-informational)

Gestion de Secure Boot et de la base de certificats UEFI `db` sur une flotte de
serveurs, par Redfish. Un seul binaire par OS, rien à installer.

> **Statut : alpha.** Le code est écrit et testé contre un faux BMC ; seul le
> comportement iDRAC9 repose sur un script éprouvé en production. Aucune plateforme n'a
> été validée sur matériel avec cet outil : commencez par `-a status` puis `-a db_list`.

## Plateformes visées

| Plateforme | Actions v1 | Validation |
|---|---|---|
| Dell iDRAC9 | `status`, `enable`, `disable`, `set_policy_custom`, `set_policy_standard`, `db_list`, `db_import`, `db_export`, `db_delete`, `reset_keys` | Comportement du script en production ; tests simulés |
| Dell iDRAC10 | mêmes actions qu'iDRAC9 (confirmées par l'OpenAPI 1.30) | Non validé sur matériel ; import par le POST standard |
| HPE iLO (ProLiant) | `status`, `enable`, `disable`, `db_list`, `db_import`, `db_delete`, `reset_keys` | Non validé sur matériel |
| Lenovo XCC | `status`, `enable`, `disable`, `db_list`, `db_import`, `db_delete`, `reset_keys` | Non validé sur matériel ; l'import exige la politique « Custom Policy » |
| Supermicro | `status`, `enable`, `disable`, `db_list`, `db_import`, `db_delete`, `reset_keys` | Non validé sur matériel |

La plateforme est détectée automatiquement depuis Redfish (`--platform` pour la forcer).
Les changements Secure Boot et BIOS restent en attente jusqu'au reboot ; l'outil ne
redémarre jamais un serveur.

## Utilisation

```sh
sbmgr -i examples/nodes.example.csv -o status.csv -a status
sbmgr -i nodes.csv -o import.csv -a db_import --cert-file ./certs/vendor_db.der
sbmgr -i nodes.csv -o plan.csv -a db_import --cert-file ./certs/vendor_db.der --dry-run   # rien n'est écrit
sbmgr -i nodes.csv -o reset.csv -a reset_keys --reset-type ResetDB --confirm              # destructif
```

Options principales (`sbmgr -h` donne la liste complète) :

| Option | Rôle |
|---|---|
| `-a`, `--action` | `status`, `enable`, `disable`, `set_policy_custom`, `set_policy_standard`, `db_list`, `db_import`, `db_export`, `db_delete`, `reset_keys` |
| `--dry-run` | lit et valide tout, n'écrit rien : le résultat dit ce qui changerait |
| `--cert-file`, `--cert-uri` | fichier de certificat (PEM ou DER, 64 Kio max) ; URI d'un certificat pour `db_export` et `db_delete` |
| `--reset-type`, `--confirm` | type de `reset_keys` ; confirmation obligatoire de cette action destructive |
| `--retries N` | nouvelles tentatives sur erreur transitoire (défaut 2) ; jamais d'écriture rejouée |
| `--concurrency`, `--timeout`, `--task-timeout`, `--no-wait` | hôtes en parallèle (20) ; délai par requête (30 s) ; durée de suivi d'une tâche (120 s) ; ne pas suivre les tâches |
| `--platform`, `--method` | forcer la plateforme ; méthode d'import Dell `oem` ou `standard` |
| `--verify-tls`, `--ca-file` | vérifier les certificats des BMC |
| `--version` | version du binaire |

Code de sortie : `0` tout a réussi ; `1` au moins un hôte a échoué ou une ligne du CSV a été
ignorée ; `2` erreur d'usage ou d'entrée (fichier illisible, aucun hôte).

Un `db_import` déjà présent n'écrit rien (« already present », comparaison par SHA-256).
`enable` et `disable` restent en attente jusqu'au prochain démarrage.

Fichier d'entrée : voir [`examples/nodes.example.csv`](examples/nodes.example.csv)
(IP seule, plage sur n'importe quel octet, CIDR). Les mots de passe y sont en clair :
ne le versionnez pas.

## Sécurité

La vérification TLS est **désactivée par défaut** (les BMC ont presque toujours un
certificat auto-signé) ; l'outil le signale à chaque exécution. Sur un réseau de
gestion non maîtrisé, une personne en position d'interception pourrait se faire passer
pour un BMC et capter les identifiants. Utilisez `--ca-file ca.pem` (ou `--verify-tls`
avec des certificats valides) et des comptes dédiés à Secure Boot.

## Compilation

```sh
make build        # binaire local dans bin/sbmgr
make build-all    # linux amd64/arm64, windows amd64, macOS arm64/amd64 (sans CGO, sans runtime)
make test         # tests contre un faux BMC
```

## Licence

[MIT](LICENSE).

## Documentation

- [Spec de design](docs/superpowers/specs/2026-10-05-secure-boot-manager-go-design.md)
  : architecture, comportement par plateforme, points non validés.
- Décisions d'architecture (ADR) :
  - [0001 — Go plutôt que Rust](docs/adr/0001-go-plutot-que-rust.md)
  - [0002 — Découverte par liens Redfish](docs/adr/0002-decouverte-par-liens-redfish.md)
  - [0003 — Un driver par plateforme](docs/adr/0003-un-driver-par-plateforme.md)
  - [0004 — Succès lu dans `ExtendedInfo`](docs/adr/0004-succes-lu-dans-extendedinfo.md)
  - [0005 — Dell : OEM sur iDRAC9, standard sur iDRAC10](docs/adr/0005-dell-methode-import.md)
  - [0006 — `reset_keys` : action destructive, explicite et confirmée](docs/adr/0006-reset-keys.md)
