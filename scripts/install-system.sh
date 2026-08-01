#!/bin/sh
# Install AUR Codex Guard beneath /usr/local without replacing /usr/bin/yay.
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
project_root=$(CDPATH='' cd -- "$script_dir/.." && pwd -P)
destination=${DESTDIR:-}

if [ "$destination" = "/" ]; then
  destination=
fi
case "$destination" in
  "" | /*) ;;
  *)
    echo "error: DESTDIR must be empty or an absolute path" >&2
    exit 2
    ;;
esac
if [ -z "$destination" ] && [ "$(id -u)" -ne 0 ]; then
  echo "error: system installation requires root; run sudo ./scripts/install-system.sh" >&2
  exit 2
fi
if [ -z "$destination" ] && [ ! -x /usr/bin/yay ]; then
  echo "error: expected the real yay executable at /usr/bin/yay" >&2
  exit 2
fi
if [ ! -x /usr/bin/python3 ]; then
  echo "error: expected Python at /usr/bin/python3" >&2
  exit 2
fi

bindir="$destination/usr/local/bin"
libdir="$destination/usr/local/lib/aur-codex-guard"
docdir="$destination/usr/local/share/doc/aur-codex-guard"
marker="# Managed by AUR Codex Guard"

check_managed_target() {
  target=$1
  if [ -e "$target" ] || [ -L "$target" ]; then
    if [ -L "$target" ] || [ ! -f "$target" ] || ! grep -Fqx "$marker" "$target"; then
      echo "error: refusing to overwrite unmanaged path: $target" >&2
      exit 2
    fi
  fi
}

for command in aur-codex-guard aur-codex-guard-hook aur-codex-guard-makepkg yay; do
  check_managed_target "$bindir/$command"
done

install -d -m 755 "$bindir" "$libdir/aur_codex_guard/schemas" "$docdir"
for source in "$project_root"/aur_codex_guard/*.py; do
  install -m 644 "$source" "$libdir/aur_codex_guard/$(basename -- "$source")"
done
install -m 644 \
  "$project_root/aur_codex_guard/schemas/review.schema.json" \
  "$libdir/aur_codex_guard/schemas/review.schema.json"
install -m 644 "$project_root/LICENSE" "$docdir/LICENSE"
install -m 644 "$project_root/README.md" "$docdir/README.md"
install -m 644 "$project_root/docs/threat-model.md" "$docdir/threat-model.md"
install -m 644 "$project_root/packaging/system/aur-codex-guard" "$bindir/aur-codex-guard"
install -m 644 "$project_root/packaging/system/aur-codex-guard-hook" "$bindir/aur-codex-guard-hook"
install -m 644 \
  "$project_root/packaging/system/aur-codex-guard-makepkg" \
  "$bindir/aur-codex-guard-makepkg"
install -m 644 "$project_root/packaging/system/yay" "$bindir/yay"
chmod 755 \
  "$bindir/aur-codex-guard" \
  "$bindir/aur-codex-guard-hook" \
  "$bindir/aur-codex-guard-makepkg" \
  "$bindir/yay"

echo "Installed AUR Codex Guard under $destination/usr/local"
echo "The real yay remains unchanged at /usr/bin/yay"
echo "Open a new shell or run 'rehash', then verify: command -v yay"
echo "Expected result: /usr/local/bin/yay"
echo "Before the first update, run: aur-codex-guard doctor --live"
