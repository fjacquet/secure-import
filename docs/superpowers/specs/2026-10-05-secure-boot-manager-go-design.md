# sbmgr — Gestion Secure Boot par Redfish (design)

Date : 2026-10-05 · Statut : à relire · Langage : Go 1.27, stdlib seule

## 1. Intention

Port en Go du script Python `secure_boot_manager.py` (Dell iDRAC9), pour injecter
les certificats constructeur dans la base UEFI `db` d'une flotte de serveurs afin
d'autoriser Secure Boot. Un seul binaire par OS, sans runtime ni interpréteur à
installer (cross-compilation Windows / Linux / macOS).

Succès :
- Les 9 actions du script tournent à l'identique sur iDRAC9 (mêmes colonnes CSV).
- Les 6 bugs listés dans `secure_boot_manager_changes.md` sont couverts par des tests.
- Le design suit la spec DMTF DSP0266 1.14 : aucune URI supposée, tout part de `/redfish/v1/`.
- iLO (ProLiant) et iDRAC10 sont pris en charge selon le périmètre du §3, chaque
  driver étant explicitement marqué validé ou non validé.

Dit par l'utilisateur : Go plutôt que Rust ; améliorations autorisées ; iDRAC9 est
la cible principale ; iLO et iDRAC10 inclus selon §3. Hypothèse : le déploiement
se fait depuis un poste Windows (Git Bash) ou Linux, avec accès réseau direct aux BMC.

Décisions structurantes : `docs/adr/0001` (Go), `0002` (découverte par liens),
`0003` (un driver par plateforme), `0004` (succès lu dans `ExtendedInfo`).

## 2. Sources utilisées

- Scripts et changelog fournis (comportement de référence iDRAC9).
- OpenAPI Dell iDRAC9 7.00.00.00 (`docs/openapi-7.xx.yaml`) et iDRAC10 I10-1.10.00.00
  (`docs/11017-1.30.xx.json`).
- Doc HPE iLO Redfish (SecureBootDatabases) via Context7.
- DMTF DSP0266 1.14 (sessions, tâches, ETag, découverte par liens).

## 3. Périmètre

| Driver | Actions v1 | Statut |
|---|---|---|
| `idrac9` | `status`, `enable`, `disable`, `set_policy_custom`, `set_policy_standard`, `db_list`, `db_import`, `db_export`, `db_delete` | Comportement issu du script en production ; tests simulés |
| `idrac10` | `status`, `db_list` | Lecture seule, d'après l'OpenAPI ; **non validé sur matériel** |
| `ilo` | `status`, `db_list`, `db_import`, `db_delete`, `enable`, `disable` | Redfish standard d'après la doc HPE ; **non validé sur matériel** |
| `lenovo` | `status`, `enable`, `disable` | D'après le XCC REST API Guide ; **non validé sur matériel**. Aucune action `db_*` : le guide ne documente pas `SecureBootDatabases` |
| `supermicro` | `status`, `enable`, `disable`, `db_list`, `db_import`, `db_delete` | D'après le guide Redfish Supermicro ; **non validé sur matériel**. Import documenté pour `dbt` seulement ; `db` supposé identique |

Le YAML Supermicro fourni (`super-micro-computer-chassis-api-openapi.yml`) ne couvre que
`/Chassis`, `Power` et `Thermal` : il n'est pas utilisé. Le driver `supermicro` repose
sur le guide officiel Redfish 1.22.2-00.04 (User Guide 4.0, PDF de 320 pages).

Une action non prise en charge par un driver produit une ligne de résultat
`Success=No` avec l'erreur `action not supported on <platform>`, jamais un crash.
Hors périmètre v1 : reboot automatique, écriture iDRAC10, écriture standard sur
Dell (voir §11), `PK`/`KEK`/`dbx` en écriture.

## 4. Architecture

```
cmd/sbmgr/            flags, câblage, code de sortie
internal/inventory/   lecture CSV (BOM), expansion des IP
internal/redfish/     client : session, découverte, tâches, ExtendedInfo, ETag
internal/platform/    interface Platform + détection
internal/dell/        drivers idrac9 et idrac10 (OEM Dell isolé ici)
internal/hpe/         driver ilo (standard)
internal/lenovo/      driver lenovo (SecureBoot seul, pas de bases de certificats)
internal/supermicro/  driver supermicro (standard + particularités Supermicro)
internal/report/      CSV (colonnes du Python) et JSON
internal/runner/      pool de workers
```

Interface (une par BMC, créée après détection) :

```go
type Platform interface {
    Name() string
    Status(ctx context.Context) (Status, error)
    SetSecureBoot(ctx context.Context, enable bool) (Change, error)
    SetPolicy(ctx context.Context, policy string) (Change, error)
    DBList(ctx context.Context) ([]Cert, error)
    DBImport(ctx context.Context, file string) (Change, error)
    DBExport(ctx context.Context, uri, file string) error
    DBDelete(ctx context.Context, uri string) (Change, error)
}
```

Un driver renvoie `ErrUnsupported` pour ce qu'il ne gère pas. `Status`, `Change`
et `Cert` portent les champs nécessaires aux colonnes CSV existantes.

## 5. Client Redfish (`internal/redfish`)

- **Découverte** : `GET /redfish/v1/` → `Links.Sessions`, `Systems`, `Managers`. Le
  membre de `Systems` est suivi par `@odata.id` (pas de `System.Embedded.1` en dur).
  `SecureBoot`, `Bios` et le lien `@Redfish.Settings` sont lus depuis les ressources
  parentes. La résolution des URI est mise en cache par hôte.
- **Authentification** : `POST` sur `Links.Sessions`, jeton `X-Auth-Token`,
  `DELETE` de la session à la fin (`defer`). Repli sur HTTP Basic si la création
  de session échoue (401/403/404/405). Le mot de passe n'apparaît jamais dans les logs.
- **Réponses acceptées** : 200, 201, 202, 204 (comme `try_request`) ; autres statuts
  → erreur `HTTP <code>: <corps>`. L'interprétation du succès est laissée au driver
  (chez Lenovo, un 200 peut porter un échec dans `ExtendedInfo`).
- **Sessions** : toujours libérées (`DELETE`). Supermicro documente 16 sessions
  simultanées maximum par BMC ; une session fuyante finit par bloquer l'accès.
- **ExtendedInfo** : les 3 regex insensibles à la casse, indépendantes de la version
  (`^Base\.\d+\.\d+\.Success$`, `^i?DRAC\.\d+\.\d+\.SYS4\d+$`,
  `^Bios\.\d+\.\d+\.BiosPropertyModified$`) ; détection de « restart / reboot »
  dans `Resolution`/`Message`.
- **ETag** : `If-Match` sur les `PATCH` quand l'ETag est connu ; `428` → relecture
  de la ressource et nouvel essai (une fois).
- **Tâches** : sur 202, suivre le `Location` tel quel (URI opaque) ; respecter
  `Retry-After` ; état `New`/`Scheduled` avec statut OK = succès « en attente de
  reboot » ; `Completed` = succès ; `Exception`/`Killed` = échec. Délai maximal
  `--task-timeout` (défaut 120 s). `--no-wait` désactive le suivi.
- **TLS** : vérification désactivée par défaut (BMC auto-signés) ; `--verify-tls`
  et `--ca-file` pour l'activer.

## 6. Détection de plateforme

La plateforme est déduite des données Redfish ; l'utilisateur ne la saisit pas.
La colonne `Platform` du résultat est calculée, jamais lue dans le CSV d'entrée.

1. `GET /redfish/v1/` → `Vendor`. `Dell` → famille iDRAC ; `HPE` → `ilo` ;
   `Lenovo` → `lenovo` (valeur confirmée par l'exemple du XCC REST API Guide) ;
   `Supermicro` → `supermicro` (**valeur non confirmée** : le guide ne montre pas
   la racine de service ; l'override `--platform` est prévu pour ce cas).
2. Pour Dell, `GET Managers/<id>` (membre `ManagerType: BMC`) → `FirmwareVersion` :
   version majeure 1 → `idrac10` ; majeure 3 à 7 → `idrac9`. `Model` (`16G…`, `17G…`)
   est lu et rapporté, mais n'est pas le critère.
3. `--platform auto|idrac9|idrac10|ilo|lenovo|supermicro` force le choix (défaut `auto`).

Constat : `Vendor` (`Dell`) et `Product` (`Integrated Dell Remote Access Controller`)
sont identiques entre iDRAC9 et iDRAC10 dans les exemples des deux OpenAPI ; seuls
`FirmwareVersion` (`7.20.30.50` contre `1.30.60.50`) et `Model` (`16G` contre `17G
Monolithic`) les distinguent. Ces valeurs viennent des exemples des specs, pas d'un
BMC réel. Si `Vendor` est inconnu ou si la version est illisible, l'hôte est rapporté
en erreur `cannot detect platform (use --platform)`.

## 7. Comportement par driver

### idrac9 (référence : script Python)
- `status` : `GET SecureBoot` (`SecureBootEnable`, `SecureBootCurrentBoot`,
  `SecureBootMode`, `Oem.Dell.Certificates`) + `SecureBootPolicy` lu dans
  `Bios?$select=Attributes/SecureBootPolicy`.
- `enable`/`disable` : `PATCH SecureBoot {"SecureBootEnable": bool}` ; pas de
  relecture après le PATCH ; nouvel état = `Enabled|Disabled (Pending - Reboot Required)`
  si le message mentionne restart/reboot.
- `set_policy_*` : `PATCH` sur la ressource Settings du BIOS avec
  `{"Attributes":{"SecureBootPolicy":P},"@Redfish.SettingsApplyTime":{"ApplyTime":"OnReset"}}` ;
  garde : si Secure Boot est activé et le mode ≠ `DeployedMode` → refus ; si la
  politique cible est déjà en place → succès sans PATCH. La garde « Custom exige
  Secure Boot activé » du changelog est **absente** du code actuel ; on suit le code.
  Succès exige `Location` et un identifiant de job.
- `db_list` : GET du magasin OEM `DB` (lien `Oem.Dell.Certificates`), champs
  `Certificates` ou `Hash`.
- `db_import` : `POST multipart/form-data` (champ `file`) sur le magasin OEM `DB`.
  La spec OpenAPI décrit un corps JSON, mais le script fonctionne en multipart
  (changelog n° 4) : on garde le multipart. Succès = regex ExtendedInfo ou HTTP 2xx.
- `db_export` : `GET` de l'URI du certificat avec `Accept: application/octet-stream`,
  écriture en streaming vers le fichier (bug n° 1).
- `db_delete` : `DELETE` de l'URI du certificat.
- `--cert-uri` passe par `sanitizeRedfishPath` (bug n° 5, conservé pour Git Bash).

### idrac10 (lecture seule)
- `status` : mêmes ressources que idrac9 (`SecureBoot`, `Bios`), l'OpenAPI
  les expose avec `{ComputerSystemId}` ; l'identifiant vient de la découverte.
- `db_list` : collection standard `SecureBootDatabases/db/Certificates`, plus le
  magasin OEM Dell s'il existe.
- Constat OpenAPI : `SecureBoot.ResetKeys` n'accepte plus que `ResetAllKeysToDefault`,
  `DeleteAllKeys`, `DeletePK`. Aucune écriture n'est implémentée.

### ilo (Redfish standard, d'après doc HPE)
- `db_list` : `GET SecureBootDatabases/db/Certificates`.
- `db_import` : `POST` JSON `{"CertificateString":"<PEM>","CertificateType":"PEM"}`.
  Si le fichier est en DER, conversion en PEM côté client.
- `db_delete` : `DELETE` de `.../Certificates/{Id}`.
- `enable`/`disable` : `PATCH SecureBoot` ; **à valider** si un reboot est requis.
- Limites connues à signaler dans le résultat : PK = 1 certificat, autres bases =
  16 certificats, 3 KiB par certificat (contrôle de taille avant envoi).
- `set_policy_*` : non supporté (pas de politique Custom/Standard chez HPE).

### lenovo (XCC, d'après le XCC REST API Guide)
- Chemins : `/redfish/v1/Systems/1/SecureBoot` (en pratique suivis par découverte).
- `status` : `GET SecureBoot` (`SecureBootEnable`, `SecureBootCurrentBoot`,
  `SecureBootMode` ∈ `UserMode|SetupMode|AuditMode|DeployedMode`). Pas de
  `SecureBootPolicy` : la colonne `Current Policy` vaut `N/A`.
- `enable`/`disable` : `PATCH SecureBoot {"SecureBootEnable": bool}`. **Le succès ne
  se lit pas dans le code HTTP** : le guide documente HTTP 200 dans les deux cas.
  `@Message.ExtendedInfo` contenant `RebootRequired` = succès « en attente de reboot » ;
  `PhysicalPresenceError` = échec (« Remote Physical Presence » non obtenu) ; sans
  message reconnu = échec « réponse inconnue ». Cette règle est propre au driver Lenovo.
- `ResetKeys` (`ResetAllKeysToDefault`, `DeleteAllKeys`, `DeletePK`) existe mais n'est
  pas exposé comme action en v1 (pas dans le script de référence).
- `db_*`, `set_policy_*` : non supportés (`SecureBootDatabases` absent du guide).

### supermicro (d'après le Redfish User Guide 1.22.2-00.04)
- `status` : `GET /redfish/v1/Systems/1/SecureBoot` (`SecureBootEnable`,
  `SecureBootCurrentBoot`, `SecureBootMode`). Pas de `SecureBootPolicy` : `N/A`.
- `enable`/`disable` : `PATCH SecureBoot {"SecureBootEnable": bool}`, réponse 200. Le
  changement est en attente jusqu'au reboot ; il se lit dans `Bios/SD` (« BIOS
  Configuration Pending Settings »). Résultat : `Enabled|Disabled (Pending - Reboot Required)`.
- `db_list` : `GET SecureBootDatabases/db/Certificates` (`db`, `dbt`, `dbr`, `KEK`, `PK`
  portent des certificats ; `dbx` porte des signatures, pas des certificats).
- `db_import` : `POST SecureBootDatabases/db/Certificates` JSON
  `{"CertificateString":"<PEM>","CertificateType":"PEM"}` ; succès = HTTP 201. Le guide
  n'illustre l'import que pour `dbt` ; `db` est supposé identique. Le fichier DER est
  converti en PEM côté client.
- `db_delete` : `DELETE` de l'URI du certificat (le guide annonce GET/DELETE).
- Les URI SecureBoot et BIOS exigent la licence `SFT-DCMS-SINGLE` ; prérequis
  matériel : X13/H13 ou plus récent pour `SecureBootDatabases`. Un `403`/`404` sans
  licence est rapporté tel quel avec le rappel « licence DCMS requise ? ».
- `set_policy_*` : non supporté.
- `ResetKeys` (`ResetAllKeysToDefault`, `DeleteAllKeys`, `DeletePK`) existe, non exposé en v1.

## 8. CLI

```
sbmgr -i nodes.csv -o out.csv -a <action> [options]
  -f csv|json            format de sortie (défaut csv)
  --platform auto|idrac9|idrac10|ilo|lenovo|supermicro
  --cert-uri URI         db_export, db_delete
  --cert-file PATH       db_import, db_export
  --concurrency N        défaut 20
  --timeout 30s          par requête
  --task-timeout 120s    suivi de tâche
  --no-wait              ne pas suivre les tâches
  --verify-tls, --ca-file PATH
  -v                     logs détaillés (jamais de secret)
```

`--hashtype` est supprimé (jamais utilisé dans le script).

**Entrée CSV** : `start_ip,end_ip,username,password` (BOM toléré). `start_ip` et
`end_ip` peuvent différer sur n'importe quel octet ; `start_ip` peut être un CIDR
(`end_ip` vide). Les anciens fichiers restent valides.

**Sortie CSV** : colonnes du Python, dans le même ordre (pour les actions
`db_*` : `IP Address, Action, Success, Message, Error, Certificate Count`), plus une
colonne finale `Platform`. Code de sortie 0 si tout a réussi, 1 si au moins un hôte
a échoué, 2 en cas d'erreur d'usage.

## 9. Erreurs et sécurité

- Une erreur sur un hôte n'arrête jamais les autres ; elle devient une ligne de résultat.
- Les mots de passe et jetons ne sont ni logués ni écrits dans la sortie.
  (Le Python affichait les lignes du CSV d'entrée, mots de passe compris.)
- Le fichier CSV d'entrée contient des mots de passe en clair : avertissement dans
  l'aide si ses permissions sont plus larges que `0600` (Unix).
- `SYS011` (« Pending configuration values are already committed ») est rapporté
  tel quel : deux changements BIOS en attente exigent deux cycles de reboot.

## 10. Tests

- Faux BMC (`httptest`) par driver, avec fixtures reprises du changelog
  (`Base.1.12.Success`, `IDRAC.2.9.SYS430`, `SYS011`, `Location` sous
  `TaskService/Tasks/`, `Location` sous `TaskMonitors/`).
- Un test par bug du changelog : export non vide (n° 1), nouvel état en attente
  de reboot (n° 2), suivi du `Location` fourni (n° 3), regex de succès toutes versions
  (n° 4), URI mutilée par MSYS (n° 5), `set_policy_standard` (n° 6).
- Tests unitaires : expansion d'IP (même octet, multi-octets, CIDR), lecture CSV
  avec BOM, session (succès, repli Basic, logout), `428`/ETag, `Retry-After`.
- Golden files pour le CSV et le JSON.
- Les deux OpenAPI servent de contrôle : un test vérifie que chaque chemin utilisé
  par les drivers `idrac9`/`idrac10` existe dans la spec correspondante (après
  remplacement des variables de chemin).
- Build multi-OS : `make build-all` (linux/amd64, windows/amd64, darwin/arm64).
- **Pas de validation sur matériel dans ce projet.** Premiers essais conseillés sur
  un serveur de test : `status`, puis `db_list`, avant toute écriture.

## 11. Points non validés (à confirmer sur matériel)

1. Détection : `Vendor` et `FirmwareVersion` sont tirés des exemples des OpenAPI Dell ;
   la valeur de `Vendor` chez HPE et les plages de firmware iDRAC9 (3 à 7) restent à
   confirmer sur BMC réels.
2. iDRAC10 : le POST OEM (multipart ou JSON) et l'écriture standard ne sont pas
   couverts ; seule la lecture est implémentée.
3. iLO : format de certificat accepté (PEM seul ou DER), reboot après import.
4. Dell : schéma de corps du `POST` standard `SecureBootDatabases/.../Certificates`
   (non documenté dans l'OpenAPI) ; l'écriture standard est volontairement absente.
5. Lenovo : certificats de la base `db` non injectables par Redfish d'après le guide
   fourni ; si XCC les expose dans une version plus récente, un guide à jour est
   nécessaire. Le comportement de `PhysicalPresenceError` (RPP) en pratique est à
   observer sur matériel.
   Supermicro : valeur de `Vendor`, import vers `db` (exemple du guide limité à `dbt`),
   limites par base, besoin de licence DCMS et génération minimale du BMC.
6. Suppression des garde-fous « Custom exige Secure Boot actif » : comportement du
   firmware à confirmer.
