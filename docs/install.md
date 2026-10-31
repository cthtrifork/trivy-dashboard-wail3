# Install

Linux amd64 only. Every release on the [releases page](https://github.com/cthtrifork/trivy-dashboard-wail3/releases)
has a `.deb`, an `.rpm`, a tarball, the raw binary, `SHA256SUMS` and `trivy-scanner-release-key.asc` (the public key that
signed the packages). Replace `<version>` below with the tag, for example `v1.2.3`.

## Before you start

- **GTK 4 and WebKitGTK 6.** The packages pull these in. The tarball and raw binary need them installed yourself.
  The binary is built on Ubuntu 24.04, so use a distribution at least that recent (glibc, WebKitGTK 6).
- **Podman** runs Trivy for every scan. The packages only recommend it, because it can also be a remote podman.
- Scans need the Trivy image and vulnerability database, so the first scan needs network access.

## Debian, Ubuntu

```sh
sudo apt install ./trivy-scanner_<version>_amd64.deb
```

`apt install ./file` resolves the GTK and WebKitGTK dependencies and installs `podman` as a recommendation. Needs
Debian 13 or Ubuntu 24.04 and newer (older releases have no `libwebkitgtk-6.0-4`).

Remove: `sudo apt remove trivy-scanner`.

## Fedora, RHEL and derivatives

```sh
sudo dnf install ./trivy-scanner_<version>_x86_64.rpm
sudo dnf install podman        # if you do not have it yet
```

The rpm depends on `gtk4` and `webkitgtk6.0`. These need a Fedora recent enough to ship WebKitGTK 6 (this build is not
yet tested on Fedora; please report problems). Remove: `sudo dnf remove trivy-scanner`.

## Verify the download (recommended)

Check the checksum, then the signature. The key is published with every release, and its fingerprint is printed in the
"Signing packages with PGP key" line of that release's workflow log (Actions tab, `Release` workflow). Before trusting
the key, compare the fingerprint with that line and with the one from an earlier release you already trust: it should
not change between releases.

```sh
sha256sum --ignore-missing -c SHA256SUMS
gpg --show-keys trivy-scanner-release-key.asc        # shows the fingerprint

# rpm
sudo rpmkeys --import trivy-scanner-release-key.asc
rpm --checksig trivy-scanner_<version>_x86_64.rpm

# deb: see "Verifying a release" in releasing.md for the gpg commands
```

Build provenance: `gh attestation verify <file> --repo cthtrifork/trivy-dashboard-wail3`. Details:
[releasing.md](releasing.md#verifying-a-release).

## Any other distribution: tarball or raw binary

```sh
tar -xzf trivy-scanner_<version>_linux_amd64.tar.gz
sudo install -m 0755 trivy-scanner /usr/local/bin/trivy-scanner
trivy-scanner
```

Install GTK 4 and WebKitGTK 6 from your distribution first (Arch: `gtk4 webkitgtk-6.0`). The tarball and raw binary
do not install a launcher entry or icon. To add one, copy `build/linux/trivy-scanner.desktop` from the repository to
`~/.local/share/applications/`, with `Exec=` pointing at the binary. A binary in a writable directory can also update
itself, see [self-update.md](self-update.md).

## Set up podman

The app runs the Trivy image through `podman`, rootless is fine:

```sh
podman info                       # works? then you are done
```

Image listing and scans use the `podman` on your PATH; set `PODMAN=/path/to/podman` to use another one. To scan on a
remote machine, point `CONTAINER_HOST` at its podman socket (see [architecture.md](architecture.md)).

## Update

- **Packages:** download the new `.deb`/`.rpm` and install it the same way; the config and VEX data in your home
  directory are kept. Packaged installs live in `/usr/bin`, so the in-app updater refuses them: use the package.
- **Tarball or raw binary in a writable directory:** **Options → App updates → Check for updates…**.

## Uninstall

Remove the package as above, or delete the binary and desktop file for a manual install. Your data stays in
`~/.config/trivy-scanner/` (VEX assessments) and `~/.cache/trivy-scanner/` (Trivy database, KEV cache);
delete them too for a clean removal.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `error while loading shared libraries: libgtk-4.so.1` or `libwebkitgtk-6.0.so.4` | GTK 4 or WebKitGTK 6 is missing (manual install) or the distribution is too old |
| `version 'GLIBC_2.xx' not found` | the distribution is older than Ubuntu 24.04 |
| Window opens, scans fail immediately | `podman info` fails for your user, or `podman` is not on PATH |
| No launcher entry after installing | log out and in, or run `update-desktop-database` and `gtk-update-icon-cache -f /usr/share/icons/hicolor` |
| Icon shows as a generic one, or a second icon appears while running | the window class does not match the launcher; report it with your desktop (GNOME, KDE, X11 or Wayland) |
| No window on a server | use the headless deployment instead: [headless.md](headless.md) |
