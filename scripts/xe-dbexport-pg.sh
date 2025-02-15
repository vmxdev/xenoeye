#!/usr/bin/env bash

EXP_DIR="/var/lib/xenoeye/exp"
FAIL_DIR="/var/lib/xenoeye/expfailed/"

FILES=`ls $EXP_DIR/*.sql`
if [ -z "$FILES" ]; then
    echo "No files"
    exit
fi

TMPFILE=$(mktemp $EXP_DIR/tmp.XXXXXX)

{ echo "BEGIN;" ; cat $FILES; echo "COMMIT;"; } > "$TMPFILE"
psql -v "ON_ERROR_STOP=1" postgresql://xenoeye:password@localhost/xenoeyedb -f "$TMPFILE" > /dev/null 2>/dev/null

if [ $? -eq 0 ]; then
    rm -f $FILES
else
    mv $FILES $FAIL_DIR
fi
rm -r "$TMPFILE"
