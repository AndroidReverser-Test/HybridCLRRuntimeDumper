#!/system/bin/sh
set -eu

files=/data/user/0/com.plantsvszombies3.mengxing/files
source=${1:-/data/local/tmp/hybridclr_dump.conf}
destination="$files/hybridclr_dump.conf"
test -d "$files"
test -f "$source"
if [ -e "$destination" ]; then
    cp -p "$destination" "$destination.backup.$(date +%s)"
fi
cp "$source" "$destination"
chown "$(stat -c '%u:%g' "$files")" "$destination"
chmod 600 "$destination"
restorecon -F "$destination"
ls -lZ "$destination"
