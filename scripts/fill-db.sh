#!/usr/bin/env bash

for sqlscript in sqldata/*.sql; do
  psql postgresql://user:password@127.0.0.1:5432/database -f "$sqlscript"
  if [ $? -eq 0 ]; then
      rm -f "$sqlscript"
  else
      mv "$sqlscript" sqlfailed/
  fi
done
