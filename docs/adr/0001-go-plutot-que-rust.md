# 0001 — Go plutôt que Rust

- Statut : accepté
- Date : 2026-10-05

## Contexte

Le script Python d'origine impose d'installer un interpréteur et la bibliothèque
`requests` sur chaque poste. Le besoin : un outil à copier et lancer, sans rien
installer, sous Windows (Git Bash), Linux et macOS. L'alternative envisagée était Rust,
sous réserve qu'il évite l'installation d'un runtime.

## Décision

Go 1.27, bibliothèque standard seule (`net/http`, `encoding/csv`, `log/slog`).

## Raisons

- Go et Rust produisent tous deux un binaire autonome : Rust n'apporte rien de plus
  sur le critère « sans installation ».
- Go se cross-compile en une commande (`GOOS`/`GOARCH`), sans chaîne d'outils par cible.
- C'est la pile déjà utilisée pour les exporters de l'équipe.
- Goroutines et client HTTP de la stdlib suffisent pour le pool de workers et les
  sessions Redfish : aucune dépendance externe.

## Conséquences

- Aucune dépendance tierce à suivre ni à auditer (à l'origine ; cobra a été ajouté ensuite, voir ADR 0008).
- Le binaire embarque le runtime Go et pèse quelques Mo.
- Pas de gestion mémoire manuelle ni de garanties de Rust : acceptable pour un client HTTP.
