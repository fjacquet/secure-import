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
- Projets existants lus pour leur comportement (aucun code copié) : `bmc-toolbox/bmclib`
  (Apache-2.0), `stmcginnis/gofish` (BSD-3), module Ansible `dellemc.openmanage.idrac_secure_boot`
  (GPL-3.0) et `dell/iDRAC-Redfish-Scripting`. Aucun ne fait « injection de certificats sur
  une flotte multi-constructeurs » ; ils ont servi à corriger le design (§7, §11).

## 3. Périmètre

| Driver | Actions v1 | Statut |
|---|---|---|
| `idrac9` | `status`, `enable`, `disable`, `set_policy_custom`, `set_policy_standard`, `db_list`, `db_import`, `db_export`, `db_delete`, `reset_keys` | Comportement issu du script en production ; tests simulés |
| `idrac10` | les 10 actions, comme `idrac9` | Vérifié dans l'OpenAPI 1.30 : `SecureBoot` PATCH, `Bios/Settings` (`SecureBootPolicy`), collections `Certificates`, `ResetKeys`. Import/suppression par le POST/DELETE standard (méthode du module Ansible Dell) ; export lu dans `CertificateString` du JSON ; **non validé sur matériel** |
| `ilo` | `status`, `db_list`, `db_import`, `db_delete`, `enable`, `disable` | Redfish standard d'après la doc HPE ; **non validé sur matériel** |
| `lenovo` | `status`, `enable`, `disable`, `db_list`, `db_import`, `db_delete` | `status`/`enable`/`disable` d'après le XCC REST API Guide ; `db_*` par le POST/DELETE standard comme `bmclib`, que le guide ne documente pas ; **non validé sur matériel** |
| `supermicro` | `status`, `enable`, `disable`, `db_list`, `db_import`, `db_delete` | D'après le guide Redfish Supermicro ; **non validé sur matériel**. Import documenté pour `dbt` seulement ; `db` supposé identique |

Le YAML Supermicro fourni (`super-micro-computer-chassis-api-openapi.yml`) ne couvre que
`/Chassis`, `Power` et `Thermal` : il n'est pas utilisé. Le driver `supermicro` repose
sur le guide officiel Redfish 1.22.2-00.04 (User Guide 4.0, PDF de 320 pages).

Une action non prise en charge par un driver produit une ligne de résultat
`Success=No` avec l'erreur `action not supported on <platform>`, jamais un crash.
Hors périmètre v1 : reboot automatique, `PK`/`KEK`/`dbx` en écriture, `ResetKeys`,
écriture standard sur iDRAC9 (iDRAC9 garde le multipart OEM, voir §7).

## 4. Architecture

```
cmd/sbmgr/            flags, câblage, code de sortie
internal/inventory/   lecture CSV (BOM), expansion des IP
internal/redfish/     client : session, découverte, tâches, ExtendedInfo, ETag
internal/platform/    interface Platform, types partagés, noms d'actions
internal/stdsb/       aide SecureBoot standard (DMTF) + driver générique (ilo, supermicro)
internal/dell/        drivers idrac9 et idrac10 (OEM Dell isolé ici)
internal/lenovo/      driver lenovo (règle de succès propre à XCC)
internal/detect/      détection de plateforme et fabrique de drivers
internal/actions/     orchestration des 9 actions vers un résultat
internal/report/      CSV (colonnes du Python) et JSON
internal/runner/      pool de workers, cycle de vie des sessions
internal/testbmc/     faux BMC pour les tests
```

Les drivers `ilo` et `supermicro` sont identiques sauf la limite de taille de certificat :
un seul driver paramétré (`stdsb.Driver`) évite la duplication prévue par l'ADR 0003.

Interface (une par BMC, créée après détection) :

```go
type Platform interface {
    Name() string
    Supports(action string) bool
    Status(ctx context.Context) (Status, error)
    SetSecureBoot(ctx context.Context, enable bool) (Change, error)
    SetPolicy(ctx context.Context, policy string) (Change, error)
    DBList(ctx context.Context) ([]Cert, error)
    DBImport(ctx context.Context, file string) (Change, error)
    DBExport(ctx context.Context, uri, file string) (Change, error)
    DBDelete(ctx context.Context, uri string) (Change, error)
}
```

`Supports` permet à l'orchestrateur de refuser une action sans appel réseau. Un type
`platform.Unsupported`, embarqué par les drivers, renvoie `ErrUnsupported` pour les
méthodes non gérées. `Status` porte aussi `PendingPolicy` (valeur en attente dans
`Bios/Settings`, voir §7).

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
  `^Bios\.\d+\.\d+\.BiosPropertyModified$`) ; **un message de gravité `Critical` n'est jamais
  un succès** (`IDRAC.2.9.SYS403`, « resource not found », correspond au motif `SYS4xx` mais
  est une erreur) ; détection de « restart / reboot » dans `Resolution`/`Message`.
- **ETag** : le `PATCH` part sans `If-Match` ; sur `428 Precondition Required`, relecture
  de la ressource, reprise de son `ETag` et nouvel essai (une fois).
- **Tâches** : sur 202, suivre le `Location` tel quel (URI opaque) ; respecter
  `Retry-After` ; état `New`/`Scheduled` avec statut OK = succès « en attente de
  reboot » ; `Completed` = succès ; `Exception`/`Killed` = échec. Délai maximal
  `--task-timeout` (défaut 120 s). `--no-wait` désactive le suivi.
- **TLS** : vérification désactivée par défaut (BMC auto-signés) ; `--verify-tls`
  et `--ca-file` pour l'activer. Un avertissement sur stderr rappelle à chaque exécution
  que les identifiants peuvent être interceptés sur un réseau non maîtrisé.

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
  garde : si Secure Boot est activé et le mode ≠ `DeployedMode` → refus. La garde
  « Custom exige Secure Boot activé » du changelog est **absente** du code actuel ; on
  suit le code. Succès exige `Location` et un identifiant de job.
  **Idempotence corrigée** : le script saute l'écriture si la politique *appliquée*
  (`Bios`) vaut déjà la cible. Or une autre valeur peut être *en attente* dans
  `Bios/Settings` (constaté en réel par `bmclib`). Le driver lit donc aussi la valeur en
  attente (`PendingPolicy`) : succès sans PATCH seulement si appliquée = cible **et**
  aucune valeur différente en attente ; si une valeur en attente vaut déjà la cible,
  succès « déjà en attente » sans nouveau PATCH ; sinon PATCH.
- `db_list` : GET du magasin OEM `DB` (lien `Oem.Dell.Certificates`), champs
  `Certificates` ou `Hash`.
- `db_import` : `POST multipart/form-data` (champ `file`) sur le magasin OEM `DB`.
  La spec OpenAPI décrit un corps JSON avec `CryptographicHash` obligatoire, et le
  script Dell officiel envoie une partie `text` `{"CryptographicHash": ...}` avec le
  fichier (utile pour les hashs `dbx`). Le script de production n'envoie que `file` et
  fonctionne pour les certificats `db` (changelog n° 4) : on garde ce multipart.
  Succès = regex ExtendedInfo ou HTTP 2xx. `--method standard` bascule sur le POST
  standard (voir idrac10) ; `--method oem` est le défaut sur iDRAC9.
- `db_export` : `GET` de l'URI du certificat avec `Accept: application/octet-stream`,
  écriture en streaming vers le fichier (bug n° 1).
- `db_delete` : `DELETE` de l'URI du certificat.
- `--cert-uri` passe par `sanitizeRedfishPath` (bug n° 5, conservé pour Git Bash).

### idrac10 (standard, d'après l'OpenAPI I10-1.10 et le module Ansible Dell)
- `status` : mêmes ressources que idrac9 (`SecureBoot`, `Bios`), l'OpenAPI
  les expose avec `{ComputerSystemId}` ; l'identifiant vient de la découverte.
- `db_list` : collection standard `SecureBootDatabases/db/Certificates` ; repli sur le
  magasin OEM Dell si la collection standard échoue.
- `db_import` : `POST` JSON `{"CertificateString":"<PEM>","CertificateType":"PEM"}` sur la
  collection `Certificates` de la base `db`, URI découverte par liens (méthode du module
  Ansible `idrac_secure_boot`, aussi utilisée par `bmclib`). Fichier DER converti en PEM.
- `db_delete` : `DELETE` de l'URI du certificat.
- `--method oem` bascule sur le multipart OEM (hérité d'iDRAC9) ; défaut `standard`.
- Constat OpenAPI : `SecureBoot.ResetKeys` n'accepte plus que `ResetAllKeysToDefault`,
  `DeleteAllKeys`, `DeletePK`. Pas d'`enable`/`disable` ni de `set_policy_*` en v1.

### ilo (Redfish standard, d'après doc HPE)
- `db_list` : `GET SecureBootDatabases/db/Certificates`.
- `db_import` : `POST` JSON `{"CertificateString":"<PEM>","CertificateType":"PEM"}`.
  Si le fichier est en DER, conversion en PEM côté client.
- `db_delete` : `DELETE` de `.../Certificates/{Id}`.
- `enable`/`disable` : `PATCH SecureBoot` ; **à valider** si un reboot est requis.
- Limites : 3 KiB par certificat (contrôle de taille avant envoi) ; une base `db` qui
  contient déjà 16 certificats refuse l'import avec un message clair, sans POST.
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
- `db_list`, `db_import`, `db_delete` : POST/DELETE standard sur `SecureBootDatabases/db`
  (comme `bmclib`). Le XCC REST API Guide ne les documente pas : **non validé**.
  Prérequis connu : l'attribut BIOS `SecureBootConfiguration.SecureBootPolicy` doit valoir
  « Custom Policy », sinon XCC renvoie l'erreur Lenovo `FQXSFPU4097G`. Cet attribut n'est
  pas modifiable par l'outil (accessibilité par `/Bios` non confirmée). Une erreur
  `FQXSFPU4097G` est donc rapportée avec l'indication « politique Secure Boot à passer en
  Custom Policy (setup UEFI ou OneCLI) ».
- `set_policy_*` : non supporté.

### supermicro (d'après le Redfish User Guide 1.22.2-00.04)
- `status` : `GET /redfish/v1/Systems/1/SecureBoot` (`SecureBootEnable`,
  `SecureBootCurrentBoot`, `SecureBootMode`). Pas de `SecureBootPolicy` : `N/A`.
- `enable`/`disable` : `PATCH SecureBoot {"SecureBootEnable": bool}`, réponse 200. Le
  changement est en attente jusqu'au reboot. Résultat : `Enabled|Disabled (Pending - Reboot
  Required)`, toujours : `Bios/SD` (« BIOS Configuration Pending Settings ») n'est pas lu,
  car ses attributs pour Secure Boot ne sont pas documentés et une lecture ne pourrait
  produire qu'un faux « pas de reboot nécessaire ».
- `db_list` : `GET SecureBootDatabases/db/Certificates` (`db`, `dbt`, `dbr`, `KEK`, `PK`
  portent des certificats ; `dbx` porte des signatures, pas des certificats).
- `db_import` : `POST SecureBootDatabases/db/Certificates` JSON
  `{"CertificateString":"<PEM>","CertificateType":"PEM"}` ; succès = HTTP 201 (un autre
  2xx reste un succès, avec une note « HTTP n, le guide documente 201 »). Le guide
  n'illustre l'import que pour `dbt` ; `db` est supposé identique. Le fichier DER est
  converti en PEM côté client.
- `db_delete` : `DELETE` de l'URI du certificat (le guide annonce GET/DELETE).
- Les URI SecureBoot et BIOS exigent la licence `SFT-DCMS-SINGLE` ; prérequis
  matériel : X13/H13 ou plus récent pour `SecureBootDatabases`. Un `403`/`404` sur
  `SecureBoot` est rapporté avec le rappel de la licence `SFT-DCMS-SINGLE` et du prérequis
  de génération.
- `set_policy_*` : non supporté.
- `ResetKeys` (`ResetAllKeysToDefault`, `DeleteAllKeys`, `DeletePK`) existe, non exposé en v1.

## 8. CLI

```
sbmgr -i nodes.csv -o out.csv -a <action> [options]
  -f csv|json            format de sortie (défaut csv)
  --platform auto|idrac9|idrac10|ilo|lenovo|supermicro
  --method oem|standard  méthode d'import/suppression Dell (défaut : oem sur iDRAC9, standard sur iDRAC10)
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
(`end_ip` vide). Les anciens fichiers restent valides. Une ligne ne peut pas dépasser
4096 adresses (erreur claire au-delà).

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
2. iDRAC10 : l'import et la suppression par POST/DELETE standard suivent le module Ansible
   Dell et `bmclib` mais ne sont pas validés sur matériel ; le schéma du corps n'est pas
   documenté dans l'OpenAPI Dell. Le repli multipart OEM (`--method oem`) n'est pas
   documenté pour iDRAC10 non plus.
3. iLO : format de certificat accepté (PEM seul ou DER), reboot après import.
4. iDRAC9 : si `--method standard` fonctionne sur le firmware de la flotte (le POST
   standard est dans l'OpenAPI 7.00 mais son corps n'y est pas décrit) : à tester avant
   d'en faire le défaut.
5. Lenovo : l'import `db` par POST standard (`bmclib`) n'est pas dans le guide XCC fourni ;
   la condition « Custom Policy » et le code `FQXSFPU4097G` viennent de `bmclib`. Le
   comportement de `PhysicalPresenceError` (RPP) est à observer sur matériel.
   Supermicro : valeur de `Vendor`, import vers `db` (exemple du guide limité à `dbt`),
   limites par base, besoin de licence DCMS et génération minimale du BMC.
6. Suppression des garde-fous « Custom exige Secure Boot actif » : comportement du
   firmware à confirmer.
7. Statut d'implémentation : le code et ses tests (faux BMC, specs OpenAPI Dell) sont en place ;
   l'ensemble reste non validé sur matériel. Ordre d'essai conseillé : `status`, `db_list`,
   puis une écriture sur un serveur de test.
