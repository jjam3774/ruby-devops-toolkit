#!/bin/sh
set -e
D=$(mktemp -d); mkdir -p $D/sys/kernel/mm/transparent_hugepage $D/proc
echo "[always] madvise never" > $D/sys/kernel/mm/transparent_hugepage/enabled
echo "always defer [madvise] never" > $D/sys/kernel/mm/transparent_hugepage/defrag
printf 'MemTotal:       16384000 kB\nAnonHugePages:   2097152 kB\nHugePages_Total:       64\nHugePages_Free:        64\nHugepagesize:        2048 kB\n' > $D/proc/meminfo
ruby "$(dirname $0)/thp_memory_audit.rb" --root $D && echo "exit 0" || echo "exit $? (expected 1)"
echo "always [madvise] never" > $D/sys/kernel/mm/transparent_hugepage/enabled
printf 'MemTotal:       16384000 kB\nAnonHugePages:         0 kB\nHugePages_Total:        0\n' > $D/proc/meminfo
ruby "$(dirname $0)/thp_memory_audit.rb" --root $D && echo "exit 0 (expected)"
rm -rf $D
