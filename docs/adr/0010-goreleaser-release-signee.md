# 0010 — GoReleaser, release signée, SBOM et provenance

- Statut : accepté
- Date : 2026-10-05

## Contexte

La release de `v0.1.0-alpha.1` venait d'un script de workflow maison : 5 binaires nus et un
`SHA256SUMS`, sans signature, sans SBOM. L'outil détient des identifiants de BMC et écrit
dans le Secure Boot : qui le télécharge doit pouvoir vérifier d'où il vient.

## Décision

- **GoReleaser** (`.goreleaser.yaml`, version 2) construit les 5 cibles (linux, macOS, Windows
  amd64 ; linux et macOS arm64), sans CGO, `-trimpath`, horodatage du commit (compilation
  reproductible), version injectée par `-X main.version`.
- Archives `tar.gz` (`zip` sous Windows) avec `LICENSE` et `README.md`, `checksums.txt`.
- **Signature cosign « keyless »** du fichier de sommes de contrôle (qui couvre toutes les
  archives), via l'identité OIDC du workflow GitHub : aucune clé à garder.
- **SBOM** de chaque archive (syft) et **attestation de provenance** GitHub
  (`actions/attest`) sur `checksums.txt`.
- La release est publiée en pré-release pour toute version `v0.x` ou à suffixe.
- Le workflow de release rejoue les tests et `govulncheck` avant de construire.

## Conséquences

- Vérification : `sha256sum -c`, `cosign verify-blob`, `gh attestation verify` (voir README).
- Les archives ne sont plus des binaires nus : le nom des fichiers change.
- `make build-all` reste pour le développement local ; `goreleaser release --snapshot` essaie
  la release sans rien publier ni signer.
- La signature et l'attestation ne peuvent être exercées qu'en CI, sur un vrai tag : la
  première release avec cette chaîne en est le premier essai réel.
