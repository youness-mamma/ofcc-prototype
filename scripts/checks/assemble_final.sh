#!/bin/sh
# Final analysis set = test2 (E1, E2, eloss, E3 systems) + test (E3 org scaling, clock test), as symlinks.
set -e
cd "$(dirname "$0")/../../results/raw"
rm -rf final && mkdir final
find test2 -name '*.json' -exec sh -c 'ln -s "../$1" final/$(basename "$1")' _ {} \;
find test -name 'e3_*_scale*.json' -exec sh -c 'ln -s "../$1" final/$(basename "$1")' _ {} \;
find test -name 'eclock_*.json' -exec sh -c 'ln -s "../$1" final/$(basename "$1")' _ {} \;
# long outages (60/180/360 min), renamed so they do not collide with the test2 E2 files
[ -d e2long ] && find e2long -name 'e2_*.json' -exec sh -c 'b=$(basename "$1"); ln -s "../$1" final/$(echo "$b" | sed "s/_seed/_long_seed/")' _ {} \;
ls final | wc -l
