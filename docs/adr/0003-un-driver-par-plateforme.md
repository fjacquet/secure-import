# 0003 — Un driver par plateforme derrière une interface `Platform`

- Statut : accepté
- Date : 2026-10-05

## Contexte

Le périmètre couvre Dell iDRAC9 et iDRAC10, HPE iLO, Lenovo XCC et Supermicro. Tous
suivent Redfish, mais divergent là où ça compte :

- Dell : import de certificat OEM en multipart, politique `Custom`/`Standard` via un
  attribut BIOS, et `ResetKeys` réduit sur iDRAC10.
- HPE et Supermicro : import par `POST` JSON `{CertificateString, CertificateType}` sur
  `SecureBootDatabases/{db}/Certificates`.
- Lenovo : pas de `SecureBootDatabases` documenté, seulement `SecureBoot`.

## Décision

Une interface `Platform` (`Status`, `SetSecureBoot`, `SetPolicy`, `DBList`, `DBImport`,
`DBExport`, `DBDelete`) et un package par famille (`dell`, `hpe`, `lenovo`, `supermicro`).
Le client Redfish, le CSV, le pool de workers et le rapport restent communs. La plateforme
est détectée depuis `Vendor` et `FirmwareVersion` ; `--platform` la force. Une action
non gérée renvoie `ErrUnsupported`, qui devient une ligne de résultat, jamais un crash.

## Raisons

- L'OEM Dell est confiné à un package : iDRAC10 ou un autre constructeur s'ajoute sans
  toucher au reste.
- Chaque driver porte sa propre règle de succès et son statut « validé / non validé ».

## Conséquences

- Plus de packages qu'un script unique, mais chacun est testable avec son faux BMC.
- Deux drivers (HPE, Supermicro) partagent le même schéma de POST ; une factorisation
  se fera si la duplication se confirme, pas avant.
- Ajouter un constructeur exige sa documentation officielle (cf. spec §3).
