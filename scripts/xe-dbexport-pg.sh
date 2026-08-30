#!/usr/bin/env bash

set -u

EXP_DIR="${XE_EXP_DIR:-/var/lib/xenoeye/exp}"
FAIL_DIR="${XE_FAIL_DIR:-/var/lib/xenoeye/expfailed}"
DATABASE_DSN="${XE_DATABASE_DSN:-postgresql://xenoeye:password@localhost/xenoeyedb}"

shopt -s nullglob
FILES=("$EXP_DIR"/*.sql)
if [ ${#FILES[@]} -eq 0 ]; then
    echo "No files"
    exit 0
fi

TMPFILE=$(mktemp $EXP_DIR/tmp.XXXXXX)

{ echo "BEGIN;" ; cat "${FILES[@]}"; echo "COMMIT;"; } > "$TMPFILE"
psql -v "ON_ERROR_STOP=1" "$DATABASE_DSN" -f "$TMPFILE" > /dev/null 2>/dev/null

if [ $? -eq 0 ]; then
    rm -f "${FILES[@]}"
else
    mkdir -p "$FAIL_DIR"
    mv "${FILES[@]}" "$FAIL_DIR/"
fi
rm -f "$TMPFILE"
