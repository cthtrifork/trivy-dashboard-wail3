# Self-update

The app can update itself from GitHub Releases. This follows Wails' tutorial
[Self-Updating Wails App](https://v3.wails.io/tutorials/04-self-update-a-wails-app/) and the Updater guide,
adapted to this app. Open **Options → App updates** and press **Check for updates…**.

## What happens

1. **Check for updates…** asks the GitHub API for the latest release of `cthtrifork/trivy-dashboard-wail3`. It only
   looks; the button then becomes **Download vX.Y.Z** if the release is newer.
2. **Download** fetches the binary and checks it against `SHA256SUMS` from the same release. Nothing is installed if
   it does not match. The button becomes **Restart & apply**.
3. **Restart & apply** swaps the running binary for the new one and relaunches. The binary re-executes itself in a
   helper mode for the swap, so no separate helper executable is shipped.

Every step runs only when you click it: there is no background polling (`CheckInterval` is unset), so the app contacts
`api.github.com` only on that click.

## When it is available

The button is disabled, with the reason as its tooltip, when:

- the build is not a release (`dev`, or the `ci-<sha>` binaries CI uploads): the updater compares versions with
  `x/mod/semver`, where an invalid string such as `dev` sorts *below every release*, so such a build would otherwise
  offer to replace itself with the newest release;
- the app runs in headless server mode (the updater restarts the native app);
- the build has no update signing key yet (see Security below).

Clicking it also refuses, before downloading anything, when the directory holding the executable is not writable.
The new binary is staged beside the old one, so a copy installed by a package manager (`/usr/bin`) should be updated
by that package manager instead. Inside an AppImage the updater replaces the `.AppImage` file itself.

## The release contract

The updater picks assets by name, so the names are an interface. `scripts/package-release.sh` produces them and
`release.yml` publishes them:

| Asset | For | Notes |
|---|---|---|
| `trivy-scanner_linux_amd64` | the updater | the raw binary; the only asset it installs |
| `trivy-scanner_<version>_linux_amd64.tar.gz` | people | binary + `README.md` + `LICENSE` |
| `trivy-scanner_linux_amd64.sig` | the updater | Ed25519 signature of the binary's release statement (see Security); named after the binary |
| `SHA256SUMS` | the updater and people | digests of the files above and the packages; the name must stay fixed |

The release also carries the `.deb`, the `.rpm` and the public key that signed them (see
[releasing](releasing.md#packages)). `SHA256SUMS` lists those too, but the updater never installs them: it skips
`.deb` and `.rpm` as it does archives, and a packaged install should be updated through the package instead.

Why two downloads of the same program: the updater installs a single file, or an archive with **exactly one top-level
entry**. The tarball has three, so it would be rejected, and the default asset matcher would pick it whenever GitHub
lists it first. `internal/selfupdate` therefore skips archives when matching.

Release tags must be semantic versions (`v1.2.3`, `v1.2.3-rc.1`); the leading `v` is handled on both sides.
The version is stamped into the binary with `-ldflags "-X github.com/cthtrifork/trivy-dashboard-wail3/internal/app.version=<tag>"` (the tutorial's `currentVersion`).

## Security

- **Fail closed.** The GitHub provider silently omits verification when `SHA256SUMS` is missing or has no line for the
  chosen asset, and the updater would then install unchecked bytes. `internal/selfupdate` wraps the provider and refuses
  such a release. The updater's own tests cannot catch this: it is a property of how the provider is configured.
- **Signed releases.** `SHA256SUMS` comes from the same release as the binary, so on its own it detects a corrupted
  download but not a malicious release: someone who can publish to the repository can publish a matching pair. So the
  release also publishes `trivy-scanner_linux_amd64.sig`, an Ed25519 signature (made with `scripts/sign-update.sh`) over a
  short statement naming the **version**, the **asset name** and its **SHA-256**. The public key is compiled into the app
  (`internal/selfupdate/update-signing-key.pub`); the release feed does not choose it. `internal/selfupdate` fetches the
  signature while checking and refuses the release (`ErrUnsigned`) when it is missing, malformed, made by another key, or
  made for another binary or version, so a validly signed old binary cannot be passed off as a newer release. The updater
  then compares the downloaded bytes with the signed digest. This is the tutorial's Ed25519 approach, done in a thin
  wrapper because the built-in GitHub provider does not fetch signatures, and it adds no dependency.
- **Without a key there is no updater.** A build whose key file is still the placeholder reports
  "this build has no update signing key" and never offers an update, rather than falling back to unsigned releases.
  The one-time setup is in [releasing](releasing.md#the-update-signing-key). Rotating the key means shipping an app
  with the new public key *before* signing with the new private key, because old apps only trust the old one.
  Releases up to the first signed one are not signed, so apps built from them keep their old behaviour and can still
  update *to* the first signed release (they only check `SHA256SUMS`); that one hop is the last unauthenticated one.
  The packages are separately signed with the PGP key; see [releasing](releasing.md#packages).
- **Attestations are for people.** Releases also carry signed attestations (build provenance, plus a CycloneDX SBOM bound
  to the binary); see [releasing](releasing.md#verifying-a-release). The app does not check them: that needs the Sigstore
  libraries (hundreds of modules, see decision 18), which the Ed25519 check avoids.
- **No redirecting the source.** Development builds read `TRIVY_SCANNER_UPDATE_API_URL` (for tests and GitHub
  Enterprise); production builds ignore it and only use `api.github.com`.

## How it differs from the tutorial

| Tutorial | Here | Why |
|---|---|---|
| `wails3 init` scaffold, `currentVersion` constant | existing app, `internal/app.version` via `-ldflags` | already how releases are stamped |
| "Check for Updates…" **menu item** | button in **Options** | the app has no native menu and is Linux-only; a menu would add window chrome I have not evaluated on GTK4. Easy to add if wanted |
| `ChecksumAsset: "SHA256SUMS"` | same, plus fail-closed wrapper and a custom asset matcher | see above |
| optional Ed25519 `PublicKey` | checked in a provider wrapper, with the version and asset name in the signed text | the built-in provider does not fetch signatures, see above |
| optional `CheckInterval` | not used | the app should not phone home unprompted |

## Tests

- `internal/selfupdate` runs the **real** `package-release.sh`, serves its output from a fake GitHub API, and checks the
  updater's provider picks the raw binary, gets the right digest and downloads identical bytes. It also covers version
  comparison, refusing releases without a digest, and the writable-directory check.
- The same tests sign the packaged release with the real `scripts/sign-update.sh` and check the provider accepts it, and
  refuses a release with no signature, a truncated or empty one, one from another key, one for another binary (the
  `SHA256SUMS` and binary swapped together) and one signed for another version.
- `internal/app/update_test.go` checks that non-release builds cannot update, that a build without a signing key has no
  release feed.
- The swap itself was verified by hand in the native window against a local fake GitHub: the installed binary became
  byte-identical to the release asset, the relaunched app reported the new version, a release without checksums was
  refused with nothing downloaded, and an up-to-date check downloaded nothing.
