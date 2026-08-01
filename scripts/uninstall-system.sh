#!/bin/sh
# Remove only paths managed by the AUR Codex Guard system installer.
set -eu

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
  echo "error: system removal requires root; run sudo ./scripts/uninstall-system.sh" >&2
  exit 2
fi

bindir="$destination/usr/local/bin"
libdir="$destination/usr/local/lib/aur-codex-guard"
docdir="$destination/usr/local/share/doc/aur-codex-guard"
marker="# Managed by AUR Codex Guard"

for command in aur-codex-guard aur-codex-guard-hook aur-codex-guard-makepkg yay; do
  target="$bindir/$command"
  if [ -e "$target" ] || [ -L "$target" ]; then
    if [ -L "$target" ] || [ ! -f "$target" ] || ! grep -Fqx "$marker" "$target"; then
      echo "error: refusing to remove unmanaged path: $target" >&2
      exit 2
    fi
  fi
done

rm -f -- \
  "$bindir/aur-codex-guard" \
  "$bindir/aur-codex-guard-hook" \
  "$bindir/aur-codex-guard-makepkg" \
  "$bindir/yay"
rm -f -- "$libdir"/aur_codex_guard/*.py
rm -f -- "$libdir/aur_codex_guard/schemas/review.schema.json"
rm -f -- "$docdir/LICENSE" "$docdir/README.md" "$docdir/threat-model.md"
rmdir -- "$libdir/aur_codex_guard/schemas" "$libdir/aur_codex_guard" "$libdir" 2>/dev/null || true
rmdir -- "$docdir" 2>/dev/null || true

echo "Removed AUR Codex Guard system files; /usr/bin/yay was never modified"
echo "Open a new shell or run 'rehash' to clear the old command path"
