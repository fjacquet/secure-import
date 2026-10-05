# 0007 — `probe` : valider une plateforme par des lectures, pas par un avertissement

- Statut : accepté
- Date : 2026-10-05

## Contexte

Hors iDRAC9, rien n'a tourné sur un vrai BMC avec cet outil. L'aide et le README le disaient
par une mise en garde (« non validé sur matériel »), qui informe sans rien prouver et ne
permet pas de la lever. Plusieurs points de la spec attendent un fait : valeur de `Vendor`
(HPE, Supermicro), plage de firmware iDRAC9, champs réellement remplis dans `Certificate`,
présence de `ResetKeys` et de ses valeurs, licence Supermicro.

## Décision

- Nouvelle action `-a probe`, **strictement en lecture** : seulement des `GET`.
- Pour chaque hôte, elle rejoue les lectures dont dépendent les drivers (service root,
  détection de plateforme, firmware du manager, système, `SecureBoot`, action `ResetKeys`,
  bases, certificats de `db` et champs présents, `Bios/SecureBootPolicy` sur Dell) et
  exécute les lectures réelles des drivers (`status`, `db_list`).
- Chaque contrôle vaut `OK`, `FAIL` ou `ABSENT` (le BMC ne l'expose pas : information, pas
  erreur) avec sa raison. Un contrôle qui échoue n'arrête pas les suivants. Le code de
  sortie est 1 si un contrôle `FAIL`.
- `--probe-dump FICHIER` conserve les réponses brutes, **expurgées** : les valeurs des clés
  qui identifient une machine ou portent un secret (numéros de série, UUID, adresses, noms
  d'hôte, mots de passe, jetons…) sont remplacées par `<redacted>`. Le fichier est en 0600.
- Une plateforme dont le `probe` a été relu et confirmé perd sa mention « non validé » ;
  la spec §11 est mise à jour avec les faits.

## Conséquences

- Les points « non validés » deviennent des faits vérifiables sur n'importe quelle flotte,
  sans risque d'écriture, et les captures peuvent servir de jeux de test pour `testbmc`.
- `probe` ne prouve pas le comportement des écritures (import, suppression, reset) :
  `--dry-run` puis un essai sur un serveur de test restent nécessaires.
- L'expurgation est par nom de clé : une donnée sensible sous un nom inattendu pourrait y
  échapper. Relire la capture avant de la partager.
