# 0009 — Autres bases Secure Boot (PK, KEK, dbx) et reset par base

- Statut : accepté
- Date : 2026-10-05

## Contexte

Jusqu'ici l'outil ne gère que la base `db`. Les OpenAPI Dell (iDRAC10 1.30 vérifiée) exposent
pour chaque base de `SecureBootDatabases` une collection `Certificates` (GET, POST, DELETE
d'un membre) et une collection `Signatures` (GET, POST, DELETE d'un membre), ainsi qu'une
action `SecureBootDatabase.ResetKeys` limitée à `ResetAllKeysToDefault` et `DeleteAllKeys`.
Aucune source consultée (sushy, gofish, guides Lenovo et Supermicro, OpenAPI Dell) ne
montre une écriture sûre sur PK ou KEK, ni le corps du POST sur `Signatures` pour dbx :
le schéma Dell n'y décrit aucune propriété utile.

## Décision

- Option `--database db|KEK|PK|dbx` (défaut : `db`, comportement inchangé).
- Un pilote est lié à une base par hôte (`WithDatabase`) ; l'interface `Platform` ne change
  que par `AddSignature`. Le magasin OEM multipart de Dell n'existe que pour `db` : toute
  autre base passe par les collections standard, quelle que soit `--method`.
- `dbx` porte des signatures, pas des certificats : `db_list --database dbx` compte les
  membres de `Signatures` ; `db_import --database dbx --signature <sha256 hex>
  [--signature-owner GUID]` ajoute une signature SHA-256. Le corps du POST reprend les noms
  DMTF de la ressource `Signature` (`SignatureString`, `SignatureType`
  `EFI_CERT_SHA256_GUID`, `SignatureTypeRegistry` `UEFI`, `UefiSignatureOwner`). **Ce format
  n'est confirmé par aucun BMC.**
- Garde-fous, appliqués avant toute écriture (y compris `db_delete` d'un membre dont l'URI
  contient `/PK/`, `/KEK/` ou `/dbx/`, et `reset_keys --database`) :
  - PK, KEK et dbx exigent `--confirm` ;
  - PK et KEK exigent en plus un `SecureBootMode` égal à `SetupMode` ou `AuditMode` :
    on ne remplace pas la clé de plateforme d'un serveur déployé par accident.
  - `--dry-run` applique les mêmes refus.
- `reset_keys --database X` appelle l'action `SecureBootDatabase.ResetKeys` de la base,
  validée contre ses `AllowableValues` ; seuls `ResetAllKeysToDefault` et `DeleteAllKeys`
  existent à ce niveau.
- `-a probe` rapporte, par base, la collection exposée, le nombre de membres, les valeurs
  de `ResetKeys` permises et les bases `*Default` présentes.

## Hors périmètre

`dbr` et `dbt`, les bases `*Default` (en lecture seule par définition), l'import de
certificats dans dbx, l'écriture de PK ou KEK par un autre moyen que les collections
standard.

## Conséquences

- Tout ce qui concerne PK, KEK et dbx est **non validé sur matériel** ; `-a probe` dit ce
  que chaque BMC expose avant la moindre écriture.
- Le format du POST `Signatures` est une hypothèse documentée. Un BMC qui le refuse
  renvoie une erreur rapportée telle quelle ; rien n'est présenté comme un succès sans
  message de succès (ADR 0004).
- Un `SecureBootMode` illisible est traité comme « pas en Setup/Audit » : refus.
