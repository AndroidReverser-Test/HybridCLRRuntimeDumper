#!/system/bin/sh
set -eu

session=${1:?capture session name required}
case "$session" in
    *[!0-9-]*|'') echo 'Invalid session name' >&2; exit 1 ;;
esac
source=/data/user/0/com.plantsvszombies3.mengxing/files/hybridclr_dll_dump/$session
root=/data/local/tmp/hybridclr-verification
destination=$root/$session
test -f "$source/manifest.json"
test ! -e "$destination"
mkdir -p "$root"
chmod 755 "$root"
cp -R "$source" "$destination"
logcat -d -s HybridCLRDump:I libc:F DEBUG:F AndroidRuntime:E > "$destination/logcat.txt"
sha256sum /data/local/tmp/libhybridclr_dumper.so > "$destination/module.sha256"
chmod -R a+rX "$destination"
echo "$destination"
