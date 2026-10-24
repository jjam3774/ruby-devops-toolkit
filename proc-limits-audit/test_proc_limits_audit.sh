#!/bin/sh
# Builds a fake procfs and verifies the script flags the right process.
set -e
D=$(mktemp -d)
mk() { mkdir -p $D/$1/fd; echo $2 > $D/$1/comm
  printf 'Limit Soft Limit Hard Limit Units\nMax open files            %s          %s          files\n' $3 $4 > $D/$1/limits
  i=0; while [ $i -lt $5 ]; do : > $D/$1/fd/$i; i=$((i+1)); done; }
mk 100 nginx 1024 4096 950
mk 200 postgres 1024 1024 100
mk 300 sleepy unlimited unlimited 3
ruby "$(dirname $0)/proc_limits_audit.rb" --proc $D --threshold 80 && echo "exit 0 (unexpected)" || echo "exit $? (expected 1)"
ruby "$(dirname $0)/proc_limits_audit.rb" --proc $D --json | head -12
rm -rf $D
