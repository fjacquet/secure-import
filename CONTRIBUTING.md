# Contributing

## Building and testing

```sh
make check        # gofmt
go vet ./...
go test -race ./...
make build-all    # 5 targets, no CGO
goreleaser release --snapshot --clean --skip=sign,sbom,publish   # local release dry run
go test ./internal/stdsb/ -run=NONE -fuzz=FuzzToPEM -fuzztime=30s   # fuzzing (also weekly in CI)
```

The only direct dependency is cobra (ADR 0008): do not add another without a
strong reason.

## Repository rules

- **Test first.** Every behavior is tested against the fake BMC
  (`internal/testbmc`) before being coded; watch the test fail before writing the code.
- **Success is read from `@Message.ExtendedInfo`**, not from the HTTP code, and a
  `Critical` message is never a success (ADR 0004).
- **A scope change** (new action, new Secure Boot database, new
  vendor) starts with an ADR in `docs/adr/`, then the spec is updated.
- **No vendor documents committed**: OpenAPI files and PDFs go in `docs/` and
  are ignored by git; conformance tests are skipped when they are absent.
- **Anything that has not run on a real BMC is called "not validated"** in the README and the
  spec.
- Commits in English, in the format `type: subject` (`feat`, `fix`, `docs`, `chore`).
