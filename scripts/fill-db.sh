#!/usr/bin/env bash

EXP_DIR="/var/lib/xenoeye/exp"
FAIL_DIR="/var/lib/xenoeye/expfailed/"

for sqlscript in $EXP_DIR/*.sql; do
  psql postgresql://user:password@127.0.0.1:5432/database -f "$sqlscript"
  if [ $? -eq 0 ]; then
      rm -f "$sqlscript"
  else
      mv "$sqlscript" $FAIL_DIR
  fi
done
