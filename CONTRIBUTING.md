# Contribuer

## Construire et tester

```sh
make check        # gofmt
go vet ./...
go test -race ./...
make build-all    # 5 cibles, sans CGO
goreleaser release --snapshot --clean --skip=sign,sbom,publish   # essai local de la release
```

La seule dépendance directe est cobra (ADR 0008) : n'en ajoutez pas sans
raison forte.

## Règles du dépôt

- **Test d'abord.** Chaque comportement est testé contre le faux BMC
  (`internal/testbmc`) avant d'être codé ; regardez le test échouer avant d'écrire le code.
- **Le succès se lit dans `@Message.ExtendedInfo`**, pas dans le code HTTP, et un message
  `Critical` n'est jamais un succès (ADR 0004).
- **Un changement de périmètre** (nouvelle action, nouvelle base Secure Boot, nouveau
  constructeur) commence par un ADR dans `docs/adr/`, puis la spec est mise à jour.
- **Pas de document constructeur versionné** : les OpenAPI et PDF vont dans `docs/` et
  sont ignorés par git ; les tests de conformité sont ignorés quand ils sont absents.
- **Tout ce qui n'a pas tourné sur un vrai BMC est dit « non validé »** dans le README et la
  spec.
- Commits en anglais, au format `type: sujet` (`feat`, `fix`, `docs`, `chore`).
