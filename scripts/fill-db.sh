#!/usr/bin/env bash

EXP_DIR="/var/lib/xenoeye/exp"
FAIL_DIR="/var/lib/xenoeye/expfailed/"

for sqlscript in $EXP_DIR/*.sql; do
  psql postgresql://xenoeye:password@localhost/xenoeyedb -f "$sqlscript"
  if [ $? -eq 0 ]; then
      rm -f "$sqlscript"
  else
      mv "$sqlscript" $FAIL_DIR
  fi
done
