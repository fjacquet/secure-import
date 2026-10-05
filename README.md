# sbmgr

![Go](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go&logoColor=white)
![Statut](https://img.shields.io/badge/statut-design-orange)
![Dépendances](https://img.shields.io/badge/dépendances-stdlib%20seule-brightgreen)
![Binaire](https://img.shields.io/badge/binaire-unique%2C%20sans%20runtime-blue)
![OS](https://img.shields.io/badge/OS-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![Redfish](https://img.shields.io/badge/Redfish-DMTF%20DSP0266%201.14-informational)

Gestion de Secure Boot et de la base de certificats UEFI `db` sur une flotte de
serveurs, par Redfish. Port en Go du script Python `secure_boot_manager.py` (Dell),
étendu à d'autres constructeurs. Un seul binaire par OS, rien à installer.

> **Statut : design uniquement.** La spec est écrite, le code ne l'est pas encore.
> Rien n'a été validé sur matériel réel.

## Plateformes visées

| Plateforme | Actions v1 | Validation |
|---|---|---|
| Dell iDRAC9 | `status`, `enable`, `disable`, `set_policy_custom`, `set_policy_standard`, `db_list`, `db_import`, `db_export`, `db_delete` | Comportement du script en production ; tests simulés |
| Dell iDRAC10 | `status`, `db_list` | Non validé sur matériel |
| HPE iLO (ProLiant) | `status`, `enable`, `disable`, `db_list`, `db_import`, `db_delete` | Non validé sur matériel |
| Lenovo XCC | `status`, `enable`, `disable` | Non validé sur matériel |
| Supermicro | `status`, `enable`, `disable`, `db_list`, `db_import`, `db_delete` | Non validé sur matériel |

La plateforme est détectée automatiquement depuis Redfish (`--platform` pour la forcer).
Les changements Secure Boot et BIOS restent en attente jusqu'au reboot ; l'outil ne
redémarre jamais un serveur.

## Utilisation prévue

```sh
sbmgr -i examples/nodes.example.csv -o status.csv -a status
sbmgr -i nodes.csv -o import.csv -a db_import --cert-file ./certs/vendor_db.der
```

Fichier d'entrée : voir [`examples/nodes.example.csv`](examples/nodes.example.csv)
(IP seule, plage sur n'importe quel octet, CIDR). Les mots de passe y sont en clair :
ne le versionnez pas.

## Documentation

- [Spec de design](docs/superpowers/specs/2026-10-05-secure-boot-manager-go-design.md)
  : architecture, comportement par plateforme, points non validés.
- Décisions d'architecture (ADR) :
  - [0001 — Go plutôt que Rust](docs/adr/0001-go-plutot-que-rust.md)
  - [0002 — Découverte par liens Redfish](docs/adr/0002-decouverte-par-liens-redfish.md)
  - [0003 — Un driver par plateforme](docs/adr/0003-un-driver-par-plateforme.md)
  - [0004 — Succès lu dans `ExtendedInfo`](docs/adr/0004-succes-lu-dans-extendedinfo.md)
