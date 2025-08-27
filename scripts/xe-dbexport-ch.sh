#!/usr/bin/env bash

EXP_DIR="/var/lib/xenoeye/exp"
FAIL_DIR="/var/lib/xenoeye/expfailed/"

TMPLIST=$(mktemp $EXP_DIR/tmp.XXXXXX)
TMPSQL=$(mktemp $EXP_DIR/tmp.XXXXXX)
find "$EXP_DIR" -type f -name "*.sql" -print0 | while IFS= read -r -d '' file; do
  echo "$file" >> "$TMPLIST"
  cat "$file" >> "$TMPSQL"
done

clickhouse-client --multiquery --multiline --database xe < "$TMPSQL"

if [ $? -eq 0 ]; then
    while IFS= read -r file ; do rm -f -- "$file" ; done < "$TMPLIST"
else
    while IFS= read -r file ; do mv "$file" "$FAIL_DIR" ; done < "$TMPLIST"
fi

rm -f "$TMPSQL"
rm -f "$TMPLIST"
