## What and why

## Verified

<!-- What you ran and saw: tests, builds, manual checks. -->

## Not verified

<!-- What could not be tested here, and why. Write "nothing" only if true. -->

## Checklist

- [ ] `make fmt-check vet test` clean (gofmt, vet also with `-tags production`, `go test -race`)
- [ ] Docs / README updated
- [ ] No fixtures or demo code reachable from a production build
