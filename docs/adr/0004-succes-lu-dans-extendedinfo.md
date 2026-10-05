# 0004 — Succès lu dans `@Message.ExtendedInfo`, pas dans le code HTTP

- Statut : accepté
- Date : 2026-10-05

## Contexte

Le script Python traite HTTP 200/202/204 comme un succès (`try_request`), puis cherche
des `MessageId` précis. Le changelog montre que les `MessageId` varient avec le firmware
(`Base.1.0.Success` contre `Base.1.12.Success`, `iDRAC.1.6.SYS413` contre
`IDRAC.2.9.SYS430`) et que ça a produit de faux échecs. Le guide Lenovo XCC va plus
loin : `PATCH SecureBoot` et `ResetKeys` renvoient **HTTP 200 dans tous les cas**.
`RebootRequired` signifie succès ; `PhysicalPresenceError` signifie échec.

## Décision

Le client Redfish accepte 200, 201, 202 et 204 comme réponses valides, mais **ne décide
pas** du succès : chaque driver interprète la réponse.

- Dell : regex insensibles à la casse et indépendantes de la version
  (`^Base\.\d+\.\d+\.Success$`, `^i?DRAC\.\d+\.\d+\.SYS4\d+$`,
  `^Bios\.\d+\.\d+\.BiosPropertyModified$`), avec repli sur le statut HTTP. Un message de
  gravité `Critical` n'est jamais un succès : le motif `SYS4xx` reconnaît aussi
  `IDRAC.2.9.SYS403` (« resource not found »), une erreur que le script Python pouvait
  prendre pour un succès.
- Lenovo : `RebootRequired` = succès en attente de reboot ; `PhysicalPresenceError` =
  échec ; message inconnu = échec « réponse inconnue ».
- Supermicro : 201 attendu pour l'import ; changement en attente lu dans `Bios/SD`.
- Une tâche 202 est suivie via son `Location` ; `New`/`Scheduled` valent « en attente de
  reboot », `Exception`/`Killed` valent échec.

## Conséquences

- Pas de faux succès sur Lenovo, pas de faux échec sur les firmwares Dell récents.
- Chaque driver doit être testé avec ses réponses réelles (fixtures du changelog et des guides).
- L'inconnu est un échec explicite : on préfère un faux négatif à un faux succès sur un
  changement de sécurité.
