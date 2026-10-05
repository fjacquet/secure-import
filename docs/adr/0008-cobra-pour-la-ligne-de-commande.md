# 0008 — cobra pour la ligne de commande (complétion du shell)

- Statut : accepté
- Date : 2026-10-05
- Remplace en partie : l'objectif « bibliothèque standard seule » de l'ADR 0001

## Contexte

La ligne de commande reposait sur le paquet `flag` de la bibliothèque standard. Il n'a ni
complétion du shell, ni option courte et longue en une seule entrée dans l'aide (chaque
alias apparaissait deux fois), ni sous-commandes. La complétion (valeurs de `-a`,
`--platform`, `--reset-type`, fichiers de `--cert-file`…) a un vrai intérêt pour des
opérateurs qui manipulent une flotte avec des noms d'actions longs. Un binaire Go reste
un binaire unique avec des dépendances : le critère « rien à installer » n'est pas touché.

## Décision

- Adopter **cobra** (`spf13/cobra` v1.9.1 ; dépendances : `spf13/pflag`, et
  `inconshreveable/mousetrap` pour Windows).
- Pourquoi cobra plutôt que kong : cobra génère nativement la complétion bash, zsh, fish
  et PowerShell et la complétion dynamique des valeurs d'options ; kong n'offre pas cela
  de façon intégrée.
- Une seule commande racine, qui garde `-a <action>` (aucun changement de contrat pour les
  scripts existants), plus `sbmgr version` et `sbmgr completion <shell>`. Cobra ne crée la
  commande `completion` que si la racine a une sous-commande, d'où `version`.
- `run(args, stdout, stderr) int` et les codes de sortie (0, 1, 2) sont inchangés.
- Changements visibles : une option courte et sa forme longue tiennent sur une ligne
  (`-i, --input`) ; les formes longues à un seul tiret (`-input`) ne sont plus acceptées ;
  `-v` gagne `--verbose` ; l'aide `-h` va sur la sortie standard.

## Conséquences

- Le module a maintenant des dépendances : `go.sum` est versionné, Dependabot surveille les
  modules Go, le README n'annonce plus « stdlib seule ».
- Le binaire grossit d'environ 0,3 Mo (mesuré : 6,96 → 7,25 Mo, macOS arm64).
- Une éventuelle refonte en sous-commandes (`sbmgr probe`, `sbmgr reset-keys`) devient
  possible sans changer de bibliothèque ; elle n'est pas décidée ici.
