#!/bin/sh
# Final analysis set = test2 (E1, E2, eloss, E3 systems) + test (E3 org scaling, clock test), as symlinks.
set -e
cd "$(dirname "$0")/../../results/raw"
rm -rf final && mkdir final
find test2 -name '*.json' -exec sh -c 'ln -s "../$1" final/$(basename "$1")' _ {} \;
find test -name 'e3_*_scale*.json' -exec sh -c 'ln -s "../$1" final/$(basename "$1")' _ {} \;
find test -name 'eclock_*.json' -exec sh -c 'ln -s "../$1" final/$(basename "$1")' _ {} \;
ls final | wc -l
