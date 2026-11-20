#!/bin/bash
set -e
cp /repo/third_party/hydra.sage /tmp/hydra.sage
cp /repo/tests/anchor.sage /tmp/anchor.sage
cd /tmp
python3 -c "import Cryptodome" 2>/dev/null || sage -pip install pycryptodomex -q
sage anchor.sage
