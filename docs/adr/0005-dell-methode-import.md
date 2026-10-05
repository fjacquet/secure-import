# 0005 — Dell : import OEM sur iDRAC9, standard sur iDRAC10

- Statut : accepté
- Date : 2026-10-05

## Contexte

Le script de production importe un certificat en `multipart/form-data` (champ `file`) sur
le magasin OEM `SecureBoot/Oem/Dell/Certificates/DB/`. L'OpenAPI Dell décrit pourtant ce
POST en JSON avec `CryptographicHash` obligatoire, et l'OpenAPI iDRAC9 7.00 comme iDRAC10
exposent aussi `SecureBootDatabases/{id}/Certificates` (POST, DELETE).

Les projets existants (recherche GitHub) pointent vers le chemin standard :

- le module Ansible officiel `dellemc.openmanage.idrac_secure_boot` envoie
  `{"CertificateString": "<PEM>", "CertificateType": "PEM"}` sur la collection `Certificates`
  de la base, URI découverte par liens, et prend en charge iDRAC10 (17G) ;
- `bmclib` importe un certificat de la même façon sur tous les constructeurs.

Le script de production, lui, est éprouvé sur la flotte de l'utilisateur en multipart OEM.

## Décision

- iDRAC9 : multipart OEM par défaut (comportement prouvé en production).
- iDRAC10 : POST/DELETE standard par défaut (méthode du module Ansible Dell, seule
  documentée pour cette génération).
- `--method oem|standard` permet de forcer l'autre voie sur Dell.

## Conséquences

- Aucun changement de comportement pour la flotte iDRAC9 actuelle.
- L'écriture iDRAC10 repose sur la documentation Dell, pas sur un test matériel : elle est
  marquée non validée (spec §11).
- À tester sur un iDRAC9 de test : si `--method standard` fonctionne, le standard pourra
  devenir le défaut et le chemin OEM un repli.
- Le script Dell envoie aussi `CryptographicHash` (utile aux hashs `dbx`) ; hors périmètre
  tant que seule la base `db` est visée.
