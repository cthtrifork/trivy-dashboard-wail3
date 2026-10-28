# Releasing

## Cut a release

**Actions → Tag and release → Run workflow** (on `main`), or from a terminal:

```sh
gh workflow run tag-release.yml -f bump=minor      # next minor version
gh workflow run tag-release.yml -f tag=v1.0.0      # an exact tag
```

Give **either** an exact tag **or** a bump:

| Input | Effect |
|---|---|
| `tag` (text) | Use exactly this tag: `v1.4.0` or `v1.4.0-rc.1`. When filled in, it wins over `bump`. |
| `bump` (`patch` / `minor` / `major`, default `patch`) | Increase that part of the highest **stable** `vX.Y.Z` tag, resetting the lower parts. |

With no tags yet the base is `v0.0.0`: `minor` gives `v0.1.0`, `major` gives `v1.0.0`, `patch` gives `v0.0.1`.
Pre-releases and tags that are not `vX.Y.Z` are ignored when working out the base, so `v2.0.0-rc.1` does not make
the next `minor` become `v2.1.0`.

The workflow then:

1. refuses to run anywhere but `main`;
2. works out the tag (`scripts/next-version.sh`) and stops if a **release** for it already exists;
3. creates an annotated tag on the head of `main` and pushes it, unless the tag already exists (see *Retrying*);
4. calls `release.yml` for that tag, which re-runs vet, tests and `govulncheck`, builds the binary, and publishes the
   release with its assets (binary and its `.sig`, tarball, signed `.deb` and `.rpm`, public key, CycloneDX SBOM, `SHA256SUMS`) and signed attestations. See [self-update](self-update.md) for why those assets
   have the names they do. The same run also pushes the headless container image to
   `ghcr.io/cthtrifork/trivy-dashboard-wail3` (tags `1.2.3`, `v1.2.3`, and `latest` for a final release) with a signed
   provenance attestation; see [headless](headless.md). The image is only pushed for a tagged release, never from a
   branch or a dry run.

## One-time setup: the package signing key

The `.deb` and `.rpm` are signed with a PGP key kept in two repository secrets (Settings → Secrets and variables →
Actions). A release **fails without the key**; a dry run on a branch builds unsigned packages.

```sh
gpg --quick-gen-key 'Trivy Scanner releases <you@example.com>' rsa4096 sign 2y
gpg --armor --export-secret-keys <fingerprint>        # -> secret RELEASE_GPG_PRIVATE_KEY
# the key's passphrase                                 # -> secret RELEASE_GPG_PASSPHRASE (omit for no passphrase)
```

Use a key made only for this. The workflow exports the matching public key as `trivy-scanner-release-key.asc` on every
release and prints its fingerprint in the log, so publish the fingerprint somewhere users can cross-check it (the README
is a good place). Rotating the key means updating the secrets; users import the new public key.

## The update signing key

The in-app updater installs a binary only if it carries an Ed25519 signature from a key compiled into the app (see
[self-update](self-update.md#security)). This is a different key from the PGP one above: it is checked by the app, not
by `apt` or `dnf`. Until it is set up, release builds report "no update signing key" and never update themselves, and a
real release **fails** (a dry run on a branch skips signing).

```sh
scripts/gen-update-key.sh ~/update-key.pem        # writes the private key there and the public key into the repo
# put the contents of ~/update-key.pem into the repository secret RELEASE_UPDATE_SIGNING_KEY, then:
shred -u ~/update-key.pem
git add internal/selfupdate/update-signing-key.pub && git commit -m "Add the update signing key"
```

Merge the public key **before** cutting the release that is meant to be the first signed one: the app embeds it at
build time. The workflow signs `trivy-scanner_linux_amd64` into `trivy-scanner_linux_amd64.sig`, verifies the signature
with the committed public key and fails if it does not match (a wrong secret, or a key that was not committed), so an
unverifiable release cannot be published. Keep a copy of the private key somewhere safe: a lost key means shipping a new
app with a new public key, and installed apps will not update across that gap by themselves (they must be installed again,
for example from the `.deb`).

To rotate it, ship a release signed with the *old* key that embeds the *new* public key, then switch the secret.

## Packages

`scripts/package-linux.sh` runs `wails3 tool package` (nfpm) with `build/linux/nfpm/nfpm.yaml`. They install the
binary to `/usr/bin/trivy-scanner`, the launcher `build/linux/trivy-scanner.desktop` (category Security, startup
notification, `StartupWMClass=trivy-scanner`, matching `ProgramName` in `main.go`) and the icon in hicolor (256px PNG
and scalable SVG). Dependencies are `libgtk-4-1` and `libwebkitgtk-6.0-4` (`gtk4`, `webkitgtk6.0` for the rpm), and
podman is recommended. The packages are built from the Ubuntu 24.04 binary, so the Fedora package needs a Fedora with
WebKitGTK 6 and a glibc that new. Try it locally with a built binary: `make wails3-install` then
`scripts/package-linux.sh <binary> v1.2.3 dist` (set `PKG_SIGNING_KEY_FILE` and `NFPM_PASSPHRASE` to sign).

## Retrying

If the tag was created but the release failed (a flaky step, a vulnerability that needed fixing first), run
**Tag and release** again with that **exact tag** in `tag`. A tag that exists without a release is reused, not moved, so
the run finishes the release for the commit that was tagged. If you instead need the fix in the release, delete the tag
(`git push origin :refs/tags/v1.2.3`) and run again.

## Why the release is called, not triggered

Pushing a tag normally triggers `release.yml`, and still does when you push one from your own machine. A tag pushed by a
workflow using its own `GITHUB_TOKEN` does **not** trigger other workflows (GitHub prevents workflows from starting each
other that way). So *Tag and release* calls `release.yml` directly after creating the tag. The alternative is a personal
access token or a GitHub App, which would work but adds a long-lived secret.

## Notes

- Only one *Tag and release* run happens at a time, so two runs cannot pick the same next version.
- The release is built from the **tag**, not from whatever `main` has become by then, and `release.yml` still checks the
  tagged commit is on `main`.
- Running `release.yml` by hand on a branch is still a dry run that builds but does not publish. Dispatched on a tag it
  publishes, which is another way to retry.
- **Not run on GitHub yet.** The scripts and the workflow steps' shell are tested here (see `internal/release`), and
  `actionlint` validates the reusable-workflow wiring, but the first real run is the first end-to-end.

## Verifying a release

The release job signs a SLSA build-provenance attestation for the binary, tarball and SBOM, and an SBOM attestation for
the binary, then verifies them itself before creating the release. To check a download by hand:

```sh
gh attestation verify trivy-scanner_linux_amd64 --repo cthtrifork/trivy-dashboard-wail3
gh attestation verify trivy-scanner_linux_amd64 --repo cthtrifork/trivy-dashboard-wail3 \
  --predicate-type https://cyclonedx.org/bom
```

The packages are also signed with the release PGP key. Import `trivy-scanner-release-key.asc` from the release, check
its fingerprint, then:

```sh
# rpm: rpmkeys --import checks the signature from now on, even with plain rpm/dnf
sudo rpmkeys --import trivy-scanner-release-key.asc
rpm --checksig trivy-scanner_<version>_x86_64.rpm

# deb: the signature is an origin signature inside the .deb (_gpgorigin), checked with debsig-verify
# or by hand; apt itself does not check it for a file installed with `apt install ./x.deb`.
ar p trivy-scanner_<version>_amd64.deb debian-binary control.tar.gz data.tar.gz > payload
ar p trivy-scanner_<version>_amd64.deb _gpgorigin > payload.sig
gpg --import trivy-scanner-release-key.asc && gpg --verify payload.sig payload
```

The SBOM (`trivy-scanner_<version>.sbom.cdx.json`) lists the Go modules and npm packages the binary is built from (from `go.mod` and `frontend/package-lock.json`), generated with Trivy (`format: cyclonedx`).
It has no os/arch in its name so the in-app updater never considers it as the binary.
