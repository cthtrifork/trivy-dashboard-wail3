# Sourced by scripts/package-release.sh and scripts/package-linux.sh (not run on its own).
#
#   script=package-release
#   source "$(dirname "$0")/lib/package-args.sh" "$@"
#
# Reads <binary> <version> <outdir> from the arguments, sets $bin, $version, $out (absolute paths)
# and $app (APP, default trivy-scanner), changes to the repository root and checks the binary.
usage="usage: ${script:?set script before sourcing}.sh <binary> <version> <outdir>"
bin="${1:?$usage}"
version="${2:?$usage}"
out="${3:?$usage}"
app="${APP:-trivy-scanner}"

bin="$(realpath "$bin")"
out="$(realpath -m "$out")"
cd "$(dirname "$0")/.."

[ -x "$bin" ] || { echo "$script: $bin is not an executable file" >&2; exit 1; }
