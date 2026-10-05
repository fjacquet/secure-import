# 0006 — `reset_keys` : action destructive, explicite et confirmée

- Statut : accepté
- Date : 2026-10-05

## Contexte

La recherche (sushy, gofish, guide Lenovo XCC, OpenAPI Dell) montre une action standard
`#SecureBoot.ResetKeys` (`POST SecureBoot/Actions/SecureBoot.ResetKeys`, corps
`{"ResetKeysType": ...}`). Les valeurs courantes sont `ResetAllKeysToDefault`,
`DeleteAllKeys` et `DeletePK` ; la liste permise est annoncée par le BMC dans
`ResetKeysType@Redfish.AllowableValues`. `DeleteAllKeys` et `DeletePK` mettent le système
en « Setup Mode » : le Secure Boot cesse de protéger le serveur. C'est pourtant la seule
sortie de secours quand un `db` a été mal rempli. Ironic expose ces opérations avec une
priorité nulle : elles ne s'exécutent que sur demande explicite de l'opérateur.

## Décision

- Nouvelle action `reset_keys`, jamais implicite.
- `--reset-type` obligatoire, limité à `ResetAllKeysToDefault`, `DeleteAllKeys`, `DeletePK`
  (valeurs DMTF, identiques dans l'OpenAPI iDRAC10 1.30) et `ResetPK`, `ResetKEK`, `ResetDB`,
  `ResetDBX` (documentées par l'OpenAPI iDRAC9 7.00 ; `ResetDB` ne touche que `db`), puis
  validé contre `AllowableValues` du BMC quand il en annonce. Une réponse 202 est suivie
  jusqu'à la fin de la tâche ; un échec ou une tâche non vérifiée est une erreur.
- `--confirm` obligatoire : sans lui, l'outil refuse. `--dry-run` montre ce qui serait fait.
- L'action est cherchée dans `Actions` de la ressource `SecureBoot` ; son absence est une
  erreur « non pris en charge », pas une URI devinée.
- Succès lu dans `ExtendedInfo` (ADR 0004), comme pour toute écriture ; l'outil ne
  redémarre pas.

## Conséquences

- Un opérateur peut récupérer un `db` corrompu sans passer par l'interface du BMC.
- Le risque (Setup Mode) est écrit dans l'aide de la commande et dans le README.
- Comportement non validé sur matériel, comme le reste hors iDRAC9.
