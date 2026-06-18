#!/bin/bash

set -euo pipefail

if [ "$(git log --pretty='format:%G?' -1 HEAD)" = "N" ]; then
    echo "ERROR: BDK requires that commits be signed, see CONTRIBUTING.md."
    exit 1
fi

echo "All commits are GPG signed."
