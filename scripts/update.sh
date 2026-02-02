#!/usr/bin/env bash
# update.sh - thin wrapper around manage.sh update
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/manage.sh" update "$@"
